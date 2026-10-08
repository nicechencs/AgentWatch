// First-write TLS ClientHello probe (P3-LNX-01).
//
// NOT BUILT. Aya is intentionally not a dependency of aw-collector-linux
// (see src/lib.rs: "Aya is intentionally not a dependency. SPIKE-01 has not
// started"). This file is not named by build.rs, by any Cargo target, or by
// a clang/bpf invocation. It is the program a later task will compile once a
// loader exists. Until then, userspace (src/sni.rs) refuses to attach and
// returns FallbackNeeded.
//
// What this probe would do, and nothing more:
//
//   * Attach to tcp_sendmsg (kprobe, or fentry where the kernel has it).
//   * Run only for a tgid that is in scope_pids or a cgroup in scope_cgroups.
//     A process outside the session is not read.
//   * Run only on the first write of a socket. The socket pointer is the key
//     of sni_seen. A hit means this socket was already copied; return.
//   * Look at the first byte of the first iov. If it is not 0x16 (TLS
//     handshake, RFC 8446 §5.1), return without copying.
//   * Copy at most SNI_PREFIX_CAP (1024) bytes with bpf_probe_read_user, from
//     the start of that iov, into one ringbuf record. No second iov, no later
//     write, no bytes past the cap.
//   * On socket close (tcp_close), delete the sni_seen entry. The map holds
//     the socket pointer and a flag. It does not hold payload.
//
// If bpf_probe_read_user is rejected at this attach point, the program is not
// loaded and userspace takes the AF_PACKET fallback (source
// "linux.afpacket/sni") or writes a gap. That fallback is not implemented here.

#ifndef __VMLINUX_H__
/* vmlinux.h is generated from BTF. It is not vendored: this file is not compiled. */
#endif

/* Maps shared with the loader. Names match src/maps.rs. */
#define SCOPE_PIDS    "scope_pids"     /* hash<u32 tgid, u32 flags>  */
#define SCOPE_CGROUPS "scope_cgroups"  /* hash<u64 cgroup_id, u32>   */
#define EVENTS        "events"         /* ringbuf, 16 MiB             */
#define LOST          "lost"           /* per-CPU counter              */

/* Socket-pointer set. Key: struct sock *. Value: one byte, "already copied".
 * No payload is stored. Deleted from tcp_close. */
#define SNI_SEEN      "sni_seen"

/* Bytes copied from the first write. linux.md §2.3. */
#define SNI_PREFIX_CAP 1024

/* TLS record content type: handshake. */
#define TLS_HANDSHAKE 0x16

/* Ringbuf record. One per socket, ever. `prefix_len` is the number of bytes
 * actually copied, which may be less than SNI_PREFIX_CAP when the first iov
 * was shorter. Userspace treats a short record as Incomplete and records
 * NA(partial_client_hello); it does not read past `prefix_len`. */
struct sni_event {
    __u64 ts_mono_ns; /* bpf_ktime_get_ns */
    __u32 tgid;
    __u32 tid;
    __u64 sock;       /* pointer, also the sni_seen key */
    __u32 prefix_len; /* 0..=SNI_PREFIX_CAP */
    __u8  prefix[SNI_PREFIX_CAP];
};

/*
 * tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
 *
 * Pseudocode, written out so the later port to Aya keeps the same limits.
 * It is not valid C as it stands: the iterator types come from vmlinux.h,
 * which this tree does not ship.
 *
 * SEC("kprobe/tcp_sendmsg")
 * int sni_tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
 * {
 *     __u32 tgid = bpf_get_current_pid_tgid() >> 32;
 *     if (bpf_map_lookup_elem(&scope_pids, &tgid) == NULL)
 *         return 0;                       // not a session process: read nothing
 *
 *     __u8 *seen = bpf_map_lookup_elem(&sni_seen, &sk);
 *     if (seen != NULL)
 *         return 0;                       // this socket's first write was taken
 *
 *     // First byte only. A non-handshake is not copied and not remembered as
 *     // payload; it is remembered so the second write is not inspected either.
 *     struct iovec iov;
 *     if (bpf_probe_read_user(&iov, sizeof(iov), msg->msg_iter.iov) < 0)
 *         return 0;                       // cannot read user memory: userspace falls back
 *     if (iov.iov_len == 0)
 *         return 0;
 *     __u8 first = 0;
 *     if (bpf_probe_read_user(&first, 1, iov.iov_base) < 0)
 *         return 0;
 *     if (first != TLS_HANDSHAKE) {
 *         __u8 one = 1;
 *         bpf_map_update_elem(&sni_seen, &sk, &one, BPF_ANY);
 *         return 0;
 *     }
 *
 *     __u32 n = iov.iov_len;
 *     if (n > SNI_PREFIX_CAP)
 *         n = SNI_PREFIX_CAP;
 *
 *     struct sni_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
 *     if (ev == NULL) {
 *         bump(&lost);                    // a lost record is a gap, not a drop
 *         return 0;
 *     }
 *     ev->ts_mono_ns = bpf_ktime_get_ns();
 *     ev->tgid = tgid;
 *     ev->tid = (__u32)bpf_get_current_pid_tgid();
 *     ev->sock = (__u64)sk;
 *     ev->prefix_len = n;
 *     if (bpf_probe_read_user(ev->prefix, n, iov.iov_base) < 0) {
 *         bpf_ringbuf_discard(ev, 0);
 *         return 0;                       // the read failed; do not submit a zeroed buffer
 *     }
 *     bpf_ringbuf_submit(ev, 0);
 *
 *     __u8 one = 1;
 *     bpf_map_update_elem(&sni_seen, &sk, &one, BPF_ANY);
 *     return 0;
 * }
 *
 * SEC("kprobe/tcp_close")
 * int sni_tcp_close(struct sock *sk)
 * {
 *     bpf_map_delete_elem(&sni_seen, &sk); // the key only; there is no payload to free
 *     return 0;
 * }
 */
