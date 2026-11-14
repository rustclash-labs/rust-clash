#!/usr/bin/env bash
# Isolated Linux `ip netns` Real Kernel `/dev/net/tun` E2E Test Harness
#
# Safety guarantee:
# Creates two ephemeral Linux network namespaces (`rc_ns_wan` and `rc_ns_cli`) connected by a
# virtual Ethernet pair (`veth-wan` <-> `veth-cli`) plus a namespace-scoped `/etc/netns/<wan>/hosts`,
# and cleans them up unconditionally on EXIT.
# NEVER modifies the host machine's default gateway, physical NIC, DNS, or routing tables!

set -euo pipefail

NS_WAN="rc_ns_wan_$$"
NS_CLI="rc_ns_cli_$$"
WAN_PID=""
SS_PID=""
SS_PASS="MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

cleanup() {
    if [[ -n "${WAN_PID}" ]]; then kill "${WAN_PID}" 2>/dev/null || true; fi
    if [[ -n "${SS_PID}" ]]; then kill "${SS_PID}" 2>/dev/null || true; fi
    sudo ip netns del "${NS_CLI}" 2>/dev/null || true
    sudo ip netns del "${NS_WAN}" 2>/dev/null || true
    sudo rm -rf "/etc/netns/${NS_WAN}" 2>/dev/null || true
}
trap cleanup EXIT

echo "[netns-tun] Building rust-clash CLI & linux_netns_tun_e2e test binary..."
cargo build -p proxy-cli
TEST_BIN=$(cargo test -p proxy-core --test linux_netns_tun_e2e --no-run --message-format=json \
    | python3 -c 'import sys, json; print(next(json.loads(l)["executable"] for l in sys.stdin if l.startswith("{") and json.loads(l).get("executable")))')

echo "[netns-tun] Creating isolated IPv4+IPv6 namespaces ${NS_WAN} <-> ${NS_CLI}..."
sudo mkdir -p "/etc/netns/${NS_WAN}"
cat <<'EOF' | sudo tee "/etc/netns/${NS_WAN}/hosts" >/dev/null
127.0.0.1 localhost
::1 localhost
203.0.113.10 portal.netns.example wan-echo.example
2001:db8:200::10 ipv6-portal.netns.example
EOF

sudo ip netns add "${NS_WAN}"
sudo ip netns add "${NS_CLI}"
sudo ip netns exec "${NS_WAN}" sysctl -qw net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0
sudo ip netns exec "${NS_CLI}" sysctl -qw net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0

sudo ip -n "${NS_WAN}" link set lo up
sudo ip -n "${NS_CLI}" link set lo up

sudo ip link add veth-wan netns "${NS_WAN}" type veth peer name veth-cli netns "${NS_CLI}"
sudo ip -n "${NS_WAN}" addr add 10.200.1.1/24 dev veth-wan
sudo ip -n "${NS_WAN}" -6 addr add fd00:200:1::1/64 dev veth-wan nodad
sudo ip -n "${NS_WAN}" addr add 203.0.113.10/32 dev lo
sudo ip -n "${NS_WAN}" addr add 203.0.113.53/32 dev lo
sudo ip -n "${NS_WAN}" -6 addr add 2001:db8:200::10/128 dev lo nodad
sudo ip -n "${NS_WAN}" -6 addr add 2001:db8:200::53/128 dev lo nodad
sudo ip -n "${NS_WAN}" link set veth-wan up

sudo ip -n "${NS_CLI}" addr add 10.200.1.2/24 dev veth-cli
sudo ip -n "${NS_CLI}" -6 addr add fd00:200:1::2/64 dev veth-cli nodad
sudo ip -n "${NS_CLI}" link set veth-cli up
sudo ip -n "${NS_CLI}" route add default via 10.200.1.1 dev veth-cli
sudo ip -n "${NS_CLI}" -6 route add default via fd00:200:1::1 dev veth-cli

echo "[netns-tun] Starting dual-stack HTTP, UDP echo, trusted DNS (:5353), and canary DNS leak traps inside ${NS_WAN}..."
sudo ip netns exec "${NS_WAN}" python3 -c '
import hashlib, json, socket, struct, threading, urllib.parse

leak_lock = threading.Lock()
leak_counts = {"v4": 0, "v6": 0}
BULK_CHUNK = b"K" * 65536

def read_http_request(conn):
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(8192)
        if not chunk:
            break
        buf += chunk
    if b"\r\n\r\n" not in buf:
        return None, None, {}, b""
    head_bytes, rest = buf.split(b"\r\n\r\n", 1)
    lines = head_bytes.decode("iso-8859-1", errors="replace").split("\r\n")
    parts = lines[0].split()
    if len(parts) < 2:
        return None, None, {}, b""
    method, target = parts[0], parts[1]
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    content_len = int(headers.get("content-length", "0"))
    while len(rest) < content_len:
        more = conn.recv(min(65536, content_len - len(rest)))
        if not more:
            break
        rest += more
    return method, target, headers, rest[:content_len]

def handle_http_conn(conn, family_label):
    try:
        method, target, headers, body = read_http_request(conn)
        if method is None:
            return
        parsed = urllib.parse.urlsplit(target)
        path = parsed.path
        if path == "/netns-tun":
            out = b"NETNS-TUN-OK\n"
            conn.sendall(f"HTTP/1.1 200 OK\r\nContent-Length: {len(out)}\r\nConnection: close\r\n\r\n".encode() + out)
        elif path == "/ipv6-check":
            out = b"IPV6-NETNS-TUN-OK\n"
            conn.sendall(f"HTTP/1.1 200 OK\r\nContent-Length: {len(out)}\r\nConnection: close\r\n\r\n".encode() + out)
        elif path == "/browser":
            payload = json.dumps({
                "ok": True,
                "host": headers.get("host", ""),
                "family": family_label,
                "user_agent": headers.get("user-agent", ""),
            }).encode()
            conn.sendall(
                f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode()
                + payload
            )
        elif path == "/echo":
            digest = hashlib.sha256(body).hexdigest()
            conn.sendall(
                f"HTTP/1.1 200 OK\r\nX-Echo-Sha256: {digest}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                + body
            )
        elif path == "/bytes":
            qs = urllib.parse.parse_qs(parsed.query)
            total = int(qs.get("n", ["65536"])[0])
            conn.sendall(
                f"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {total}\r\nConnection: close\r\n\r\n".encode()
            )
            rem = total
            while rem > 0:
                take = min(len(BULK_CHUNK), rem)
                conn.sendall(BULK_CHUNK[:take])
                rem -= take
        elif path == "/leak-count":
            with leak_lock:
                payload = json.dumps({
                    "dns_leak_v4": leak_counts["v4"],
                    "dns_leak_v6": leak_counts["v6"],
                    "dns_leak_total": leak_counts["v4"] + leak_counts["v6"],
                }).encode()
            conn.sendall(
                f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode()
                + payload
            )
        else:
            conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    finally:
        conn.close()

def tcp_srv(af, bind_addr, family_label):
    s = socket.socket(af, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(bind_addr)
    s.listen(64)
    while True:
        conn, _ = s.accept()
        threading.Thread(target=handle_http_conn, args=(conn, family_label), daemon=True).start()

def udp_srv(af, bind_addr, prefix):
    u = socket.socket(af, socket.SOCK_DGRAM)
    u.bind(bind_addr)
    while True:
        data, peer = u.recvfrom(4096)
        u.sendto(prefix + data, peer)

def parse_qtype(q):
    idx = 12
    while idx < len(q) and q[idx] != 0:
        idx += 1 + q[idx]
    if idx + 5 <= len(q):
        return idx + 5, struct.unpack("!H", q[idx + 1 : idx + 3])[0]
    return len(q), 1

def trusted_dns_srv():
    d = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    d.bind(("10.200.1.1", 5353))
    v6_bytes = socket.inet_pton(socket.AF_INET6, "2001:db8:200::10")
    v4_bytes = socket.inet_pton(socket.AF_INET, "203.0.113.10")
    while True:
        q, peer = d.recvfrom(2048)
        if len(q) >= 17:
            q_end, qtype = parse_qtype(q)
            if qtype == 28:
                ans = struct.pack("!HHHLH", 0xC00C, 28, 1, 60, 16) + v6_bytes
                resp = q[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + q[12:q_end] + ans
            else:
                ans = struct.pack("!HHHLH", 0xC00C, 1, 1, 60, 4) + v4_bytes
                resp = q[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + q[12:q_end] + ans
            d.sendto(resp, peer)

def canary_dns_leak_srv(af, bind_addr, key):
    c = socket.socket(af, socket.SOCK_DGRAM)
    c.bind(bind_addr)
    while True:
        q, peer = c.recvfrom(2048)
        with leak_lock:
            leak_counts[key] += 1
        if len(q) >= 12:
            c.sendto(q[:2] + b"\x81\x83\x00\x00\x00\x00\x00\x00\x00\x00", peer)

threading.Thread(target=tcp_srv, args=(socket.AF_INET, ("203.0.113.10", 18080), "ipv4"), daemon=True).start()
threading.Thread(target=tcp_srv, args=(socket.AF_INET6, ("2001:db8:200::10", 18080), "ipv6"), daemon=True).start()
threading.Thread(target=tcp_srv, args=(socket.AF_INET, ("10.200.1.1", 18082), "ctrl"), daemon=True).start()
threading.Thread(target=udp_srv, args=(socket.AF_INET, ("203.0.113.10", 18081), b"ECHO:"), daemon=True).start()
threading.Thread(target=udp_srv, args=(socket.AF_INET6, ("2001:db8:200::10", 18081), b"ECHO6:"), daemon=True).start()
threading.Thread(target=trusted_dns_srv, daemon=True).start()
threading.Thread(target=canary_dns_leak_srv, args=(socket.AF_INET, ("203.0.113.53", 53), "v4"), daemon=True).start()
canary_dns_leak_srv(socket.AF_INET6, ("2001:db8:200::53", 53), "v6")
' &
WAN_PID=$!

echo "[netns-tun] Starting rust-clash SS-2022 server inside ${NS_WAN} (10.200.1.1:18388)..."
sudo ip netns exec "${NS_WAN}" ./target/debug/rust-clash server ss \
    --listen 10.200.1.1:18388 \
    --cipher 2022-blake3-aes-256-gcm \
    --password "${SS_PASS}" &
SS_PID=$!

WAN_READY=0
for _ in $(seq 1 50); do
    if ! kill -0 "${WAN_PID}" 2>/dev/null; then
        echo "[netns-tun] ERROR: Mock WAN server process (PID ${WAN_PID}) exited prematurely before listening on 10.200.1.1:18082." >&2
        exit 1
    fi
    if ! kill -0 "${SS_PID}" 2>/dev/null; then
        echo "[netns-tun] ERROR: rust-clash SS-2022 server process (PID ${SS_PID}) exited prematurely before listening on 10.200.1.1:18388." >&2
        exit 1
    fi
    if sudo ip netns exec "${NS_WAN}" python3 -c '
import socket
for port in (18082, 18388):
    with socket.create_connection(("10.200.1.1", port), timeout=0.2):
        pass
' 2>/dev/null; then
        WAN_READY=1
        break
    fi
    sleep 0.1
done

if [[ "${WAN_READY}" -ne 1 ]]; then
    echo "[netns-tun] ERROR: Readiness loop exhausted 50 retries without mock WAN (10.200.1.1:18082) and SS-2022 (10.200.1.1:18388) servers listening inside ${NS_WAN}." >&2
    sudo ip netns exec "${NS_WAN}" ss -tuln >&2 || true
    exit 1
fi

echo "[netns-tun] Executing comprehensive real kernel /dev/net/tun E2E suite inside ${NS_CLI}..."
sudo ip netns exec "${NS_CLI}" env \
    RUST_CLASH_NETNS_TUN_TEST=1 \
    RC_NETNS_WAN_IP=10.200.1.1 \
    RC_NETNS_CTRL_PORT=18082 \
    RC_NETNS_TRUSTED_DNS_PORT=5353 \
    RC_NETNS_TARGET_IP=203.0.113.10 \
    RC_NETNS_TARGET_IPV6=2001:db8:200::10 \
    RC_NETNS_CANARY_DNS_IPV4=203.0.113.53 \
    RC_NETNS_CANARY_DNS_IPV6=2001:db8:200::53 \
    RC_NETNS_SS_PORT=18388 \
    RC_NETNS_HTTP_PORT=18080 \
    RC_NETNS_UDP_PORT=18081 \
    RC_NETNS_SS_PASS="${SS_PASS}" \
    "${TEST_BIN}" real_linux_kernel_netns_tun_tcp_udp_dns_and_teardown_e2e --nocapture

echo "[netns-tun] PASS: Real Linux kernel /dev/net/tun HTTP/DNS-leak/TCP/UDP/IPv6/handoff/restart-cycles & clean teardown verified!"
