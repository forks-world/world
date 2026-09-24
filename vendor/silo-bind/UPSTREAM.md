# Provenance

Source: https://github.com/silo-rs/silo
Commit: `8364a4298a0b85ffcecc281bfd5c6bb73963be8a`
Component: `crates/silo-bind/src`, MIT license (included).

World vendors the real silo interposition library, rather than reimplementing
its address translation behind an unrelated name. Local changes enforce
unconditional localhost translation (no host fallback or listener probe),
reject other loopback aliases through the intercepted socket calls, reject
unsupported IPv6-only operations, and check injection/child environment.
Final child exec targets must be native binaries; unresolved shebangs and
replacement interpreters that resolve to SIP-protected paths fail with EACCES.
World also rejects setuid/setgid targets and tracks cwd-changing spawn actions
through their public APIs, including handle relocation and both API spellings.
World additionally redirects the shared host temp directories (`/tmp`,
`/var/tmp` and their `/private` forms) below a per-workspace `WORLD_TMP` root
in libSystem path calls, spawn paths and AF_UNIX addresses (`src/tmp.rs`,
`src/platform/paths.rs`), and requires children to keep the same root.
This remains a developer compatibility layer, not a hostile-code security
boundary: raw syscalls and uninjected code can bypass interposition.

Forkfs integration remains RPC-only; the OS socket ABI here is unrelated to
linking a forkfs C ABI.
