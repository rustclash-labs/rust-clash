#ifndef RUST_CLASH_NE_BRIDGE_H
#define RUST_CLASH_NE_BRIDGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Opaque handle token to an embedded `rust-clash` `ProxyEngine` + virtual `smoltcp` packet session
/// hosted inside a macOS/iOS `NEPacketTunnelProvider` System Extension.
///
/// Thread-safety: All `rc_ne_*` functions resolve `handle` through a thread-safe Rust `Arc` registry,
/// eliminating Use-After-Free (UAF) and double-free races across concurrent NE packet/IPC queues.
typedef struct RcNeEngineHandle RcNeEngineHandle;

/// Start the pure-Rust `rust-clash` engine inside `NEPacketTunnelProvider` using a Clash YAML string.
/// Returns NULL on error and populates `*out_error` (caller frees with `rc_ne_free_string`).
RcNeEngineHandle *rc_ne_start_engine(
    const char *yaml_config,
    uint16_t mtu,
    char **out_error
);

/// Push a single raw L3 IPv4/IPv6 packet read from `NEPacketTunnelFlow` into `smoltcp`.
/// Returns `true` if queued, `false` on backpressure or after `rc_ne_stop_engine`.
bool rc_ne_push_inbound_packet(
    RcNeEngineHandle *handle,
    const uint8_t *packet_ptr,
    size_t packet_len
);

/// Event-driven wait for the next raw L3 IPv4/IPv6 packet emitted by `smoltcp` (`0 Hz` idle wakeups!).
/// - `timeout_ms < 0`: blocks until a packet arrives or `rc_ne_stop_engine` wakes the waiter.
/// - `timeout_ms == 0`: non-blocking poll.
/// - `timeout_ms > 0`: blocks up to `timeout_ms` ms.
/// Returns byte length (`> 0`), `0` on timeout/empty, or `-1` when stopped/invalid.
ssize_t rc_ne_wait_outbound_packet(
    RcNeEngineHandle *handle,
    uint8_t *out_buf,
    size_t buf_cap,
    int32_t timeout_ms
);

/// Non-blockingly pop the next raw L3 IPv4/IPv6 packet emitted by `smoltcp` (for batch coalescing).
/// Copies at most `buf_cap` bytes into `out_buf` and returns the packet byte length (`0` if empty/stopped).
size_t rc_ne_pop_outbound_packet(
    RcNeEngineHandle *handle,
    uint8_t *out_buf,
    size_t buf_cap
);

/// Flush DNS positive/negative caches on minor path updates.
void rc_ne_flush_dns(RcNeEngineHandle *handle);

/// Perform full session recovery (UDP NAT reset + AnyTLS pool eviction + active TCP abort + DNS flush)
/// on macOS sleep/wake (`NEPacketTunnelProvider.wake()`) or physical interface transitions.
bool rc_ne_notify_network_change(RcNeEngineHandle *handle);

/// Return a newly allocated UTF-8 JSON status snapshot (caller frees with `rc_ne_free_string`).
char *rc_ne_get_status_json(RcNeEngineHandle *handle);

/// Gracefully stop and unregister `handle` (idempotent; immediately wakes `rc_ne_wait_outbound_packet`).
void rc_ne_stop_engine(RcNeEngineHandle *handle);

/// Free a UTF-8 C string returned by `rc_ne_*`.
void rc_ne_free_string(char *ptr);

#ifdef __cplusplus
}
#endif

#endif /* RUST_CLASH_NE_BRIDGE_H */
