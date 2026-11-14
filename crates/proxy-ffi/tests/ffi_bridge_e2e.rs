use std::{
    ffi::CString,
    ptr,
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use proxy_core::dns::wire::{QTYPE_A, build_dns_query, extract_ip_answers};
use proxy_ffi::ne_c_api::{
    rc_ne_flush_dns, rc_ne_free_string, rc_ne_get_status_json, rc_ne_notify_network_change,
    rc_ne_pop_outbound_packet, rc_ne_push_inbound_packet, rc_ne_start_engine, rc_ne_stop_engine,
    rc_ne_wait_outbound_packet,
};

#[cfg(unix)]
static SERIAL_ANDROID_FFI_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn build_raw_ipv4_udp_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = (8 + payload.len()) as u16;
    let total_len = 20u16 + udp_len;
    let mut pkt = vec![0u8; usize::from(total_len)];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17; // UDP
    pkt[12..16].copy_from_slice(&src_ip);
    pkt[16..20].copy_from_slice(&dst_ip);

    // IPv4 header checksum
    let mut sum = 0u32;
    for &[hi, lo] in pkt[..20].as_chunks::<2>().0 {
        sum += u32::from(u16::from_be_bytes([hi, lo]));
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let csum = !(sum as u16);
    pkt[10..12].copy_from_slice(&csum.to_be_bytes());

    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[24..26].copy_from_slice(&udp_len.to_be_bytes());
    // UDP checksum = 0 (valid in IPv4)
    pkt[28..].copy_from_slice(payload);
    pkt
}

#[test]
fn macos_ne_c_abi_lifecycle_and_l3_packet_pump_e2e() {
    let yaml = proxy_core::config::ClashConfig::default_starter_yaml();
    let c_yaml = CString::new(yaml).unwrap();
    let mut err_ptr: *mut std::ffi::c_char = ptr::null_mut();

    let handle = unsafe { rc_ne_start_engine(c_yaml.as_ptr(), 1500, &raw mut err_ptr) };
    assert!(!handle.is_null(), "rc_ne_start_engine should succeed");
    assert!(err_ptr.is_null());

    // Push a raw IPv4 UDP DNS query to 198.18.0.1:53 through C ABI and wait via event-driven Condvar!
    let dns_q = build_dns_query(0x5151, "ne-tunnel.example.com", QTYPE_A);
    let raw_l3 = build_raw_ipv4_udp_packet([198, 18, 0, 9], [198, 18, 0, 1], 53000, 53, &dns_q);
    assert!(unsafe { rc_ne_push_inbound_packet(handle, raw_l3.as_ptr(), raw_l3.len()) });

    let mut out_buf = vec![0u8; 4096];
    let got_len =
        unsafe { rc_ne_wait_outbound_packet(handle, out_buf.as_mut_ptr(), out_buf.len(), 2000) };
    assert!(
        got_len > 28,
        "expected outbound L3 DNS reply from event-driven rc_ne_wait_outbound_packet, got {got_len}"
    );
    let answers =
        extract_ip_answers(&out_buf[28..got_len as usize]).expect("valid DNS reply payload");
    assert!(!answers.is_empty());

    let status_ptr = rc_ne_get_status_json(handle);
    assert!(!status_ptr.is_null());
    let status_json = unsafe { std::ffi::CStr::from_ptr(status_ptr) }
        .to_str()
        .unwrap()
        .to_string();
    unsafe { rc_ne_free_string(status_ptr) };
    assert!(status_json.contains("\"fakeIpEntries\":1"));

    assert!(rc_ne_notify_network_change(handle));
    rc_ne_flush_dns(handle);
    rc_ne_stop_engine(handle);

    // Post-stop calls MUST safely fail closed without UAF or double-free!
    assert!(!rc_ne_notify_network_change(handle));
    assert!(rc_ne_get_status_json(handle).is_null());
    assert_eq!(
        unsafe { rc_ne_wait_outbound_packet(handle, out_buf.as_mut_ptr(), out_buf.len(), -1) },
        -1
    );
    rc_ne_stop_engine(handle); // Idempotent double-stop
}

#[test]
fn macos_ne_c_abi_concurrent_uaf_stress_and_zero_hz_blocking_wait() {
    let yaml = proxy_core::config::ClashConfig::default_starter_yaml();
    let c_yaml = CString::new(yaml).unwrap();

    // Part A: Prove `rc_ne_wait_outbound_packet(..., -1)` blocks without busy-spinning and wakes
    // instantaneously (`< 150ms`) returning `-1` when `rc_ne_stop_engine` is invoked on another thread.
    let mut err_ptr: *mut std::ffi::c_char = ptr::null_mut();
    let h_block = unsafe { rc_ne_start_engine(c_yaml.as_ptr(), 1500, &raw mut err_ptr) };
    assert!(!h_block.is_null());
    let addr_block = h_block.addr();

    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let waiter = std::thread::spawn(move || {
        let h = ptr::without_provenance_mut(addr_block);
        let mut buf = vec![0u8; 4096];
        entered_tx.send(()).unwrap();
        let rc = unsafe { rc_ne_wait_outbound_packet(h, buf.as_mut_ptr(), buf.len(), -1) };
        (rc, Instant::now())
    });
    entered_rx.recv().unwrap();
    std::thread::sleep(Duration::from_millis(40));

    let t0 = Instant::now();
    rc_ne_stop_engine(h_block);
    let (rc, woke_at) = waiter.join().expect("waiter thread must not panic");
    let wake_latency = woke_at.saturating_duration_since(t0);
    assert_eq!(rc, -1, "stopped engine must wake Condvar waiter with -1");
    assert!(
        wake_latency < Duration::from_secs(2),
        "Condvar wakeup took {:?} (expected instant wakeup)",
        wake_latency
    );

    // Part B: 10 rounds of 8-thread concurrent UAF torture:
    // Inbound pushers + blocking Condvar egress waiters + non-blocking poppers + IPC status readers +
    // wake/network-handoff callers + 2 competing `rc_ne_stop_engine` callers!
    for round in 0..10u16 {
        let handle = unsafe { rc_ne_start_engine(c_yaml.as_ptr(), 1500, ptr::null_mut()) };
        assert!(!handle.is_null(), "round {round} start_engine");
        let raw_id = handle.addr();

        let barrier = Arc::new(Barrier::new(8));
        let done = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::new();

        // 2 inbound packet pusher threads (simulating NEPacketTunnelFlow.readPackets)
        for t_idx in 0..2u16 {
            let b = Arc::clone(&barrier);
            let d = Arc::clone(&done);
            threads.push(std::thread::spawn(move || {
                let h = ptr::without_provenance_mut(raw_id);
                let dns_q = build_dns_query(0x6000 + round + t_idx, "uaf-stress.example", QTYPE_A);
                let pkt = build_raw_ipv4_udp_packet(
                    [198, 18, 0, 20 + t_idx as u8],
                    [198, 18, 0, 1],
                    54000 + t_idx,
                    53,
                    &dns_q,
                );
                b.wait();
                while !d.load(Ordering::Acquire) {
                    let _ = unsafe { rc_ne_push_inbound_packet(h, pkt.as_ptr(), pkt.len()) };
                    std::thread::yield_now();
                }
                // Post-stop call must also safely return false!
                assert!(!unsafe { rc_ne_push_inbound_packet(h, pkt.as_ptr(), pkt.len()) });
            }));
        }

        // 2 blocking Condvar waiter threads (simulating egressQueue)
        for _ in 0..2 {
            let b = Arc::clone(&barrier);
            let d = Arc::clone(&done);
            threads.push(std::thread::spawn(move || {
                let h = ptr::without_provenance_mut(raw_id);
                let mut buf = vec![0u8; 4096];
                b.wait();
                loop {
                    let n =
                        unsafe { rc_ne_wait_outbound_packet(h, buf.as_mut_ptr(), buf.len(), -1) };
                    if n < 0 || d.load(Ordering::Acquire) {
                        break;
                    }
                }
            }));
        }

        // 1 non-blocking batch popper + status IPC reader thread
        {
            let b = Arc::clone(&barrier);
            let d = Arc::clone(&done);
            threads.push(std::thread::spawn(move || {
                let h = ptr::without_provenance_mut(raw_id);
                let mut buf = vec![0u8; 4096];
                b.wait();
                while !d.load(Ordering::Acquire) {
                    let _ = unsafe { rc_ne_pop_outbound_packet(h, buf.as_mut_ptr(), buf.len()) };
                    let s = rc_ne_get_status_json(h);
                    if !s.is_null() {
                        unsafe { rc_ne_free_string(s) };
                    }
                }
            }));
        }

        // 1 sleep/wake network-change thread
        {
            let b = Arc::clone(&barrier);
            let d = Arc::clone(&done);
            threads.push(std::thread::spawn(move || {
                let h = ptr::without_provenance_mut(raw_id);
                b.wait();
                while !d.load(Ordering::Acquire) {
                    let _ = rc_ne_notify_network_change(h);
                    rc_ne_flush_dns(h);
                    std::thread::yield_now();
                }
            }));
        }

        // 2 competing `rc_ne_stop_engine` threads firing right in the middle of peak traffic!
        for stopper_idx in 0..2u64 {
            let b = Arc::clone(&barrier);
            let d = Arc::clone(&done);
            threads.push(std::thread::spawn(move || {
                let h = ptr::without_provenance_mut(raw_id);
                b.wait();
                std::thread::sleep(Duration::from_millis(4 + stopper_idx));
                rc_ne_stop_engine(h);
                d.store(true, Ordering::Release);
            }));
        }

        for th in threads {
            th.join()
                .expect("concurrent NE FFI worker panicked or hit UAF");
        }
    }
}

#[cfg(unix)]
fn create_tun_like_socketpair() -> (i32, i32, (u64, u64)) {
    let mut fds = [-1i32; 2];
    // Prefer `SOCK_SEQPACKET` on Linux/Android (exact L3 packet boundaries of `/dev/tun`);
    // fall back to `SOCK_STREAM` on macOS/Darwin where XNU `AF_UNIX` does not implement `SOCK_SEQPACKET`.
    // In both modes, `fds[1]` observes `EOF (read == 0)` if and only if *every* descriptor (`tun_fd`,
    // `rx_fd`, and any `dup()`ed `tx_fd`) referencing `fds[0]`'s open file description has been closed.
    let mut rc =
        unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, fds.as_mut_ptr()) };
    if rc != 0 {
        rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    }
    assert_eq!(
        rc, 0,
        "socketpair(AF_UNIX, SOCK_SEQPACKET/SOCK_STREAM) must succeed"
    );
    let id = fd_kernel_inode(fds[0]).expect("valid fstat on newly created socketpair fd");
    (fds[0], fds[1], id)
}

#[cfg(unix)]
fn fd_kernel_inode(fd: i32) -> Option<(u64, u64)> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd, &raw mut st) };
    if rc == 0 {
        Some((st.st_dev as u64, st.st_ino as u64))
    } else {
        None
    }
}

/// Prove that `tun_fd` (with original kernel inode `orig_inode`) AND all `dup()`ed copies of it
/// have been completely closed in the OS kernel, immune to POSIX FD-number reuse and Darwin `soo_stat` `(0, 0)` inodes.
#[cfg(unix)]
fn assert_tun_fd_fully_closed_in_kernel(tun_fd: i32, orig_inode: (u64, u64), peer_fd: i32) {
    // 1. On kernels with unique non-zero socket inodes (Linux `sockfs`), verify `tun_fd` is either
    //    `EBADF` (`None`) or reused by a brand-new kernel inode (`!= orig_inode`).
    //    (Darwin/XNU `soo_stat` reports `(0, 0)` for unnamed `AF_UNIX` `socketpair`s.)
    if orig_inode.1 != 0
        && let Some(current_inode) = fd_kernel_inode(tun_fd)
    {
        assert_ne!(
            current_inode, orig_inode,
            "fd {tun_fd} still points to original kernel TUN inode {orig_inode:?} (FD LEAK!)"
        );
    }

    // 2. `peer_fd` MUST observe immediate `POLLHUP`/`POLLIN` + `EOF` (`read == 0`), proving ZERO
    //    `dup()`ed descriptors (such as `tx_fd`) still hold the open file description alive!
    let mut pfd = libc::pollfd {
        fd: peer_fd,
        events: libc::POLLIN | libc::POLLHUP,
        revents: 0,
    };
    let prc = unsafe { libc::poll(&raw mut pfd, 1, 2000) };
    assert!(
        prc > 0 && (pfd.revents & (libc::POLLHUP | libc::POLLIN)) != 0,
        "peer socket did not observe EOF/HUP after TUN close (prc={prc}, revents={}) — a dup'd fd leaked!",
        pfd.revents
    );
    let flags = unsafe { libc::fcntl(peer_fd, libc::F_GETFL) };
    if flags >= 0 {
        unsafe { libc::fcntl(peer_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    }
    let mut probe = [0u8; 8];
    let n = unsafe {
        libc::read(
            peer_fd,
            probe.as_mut_ptr().cast::<libc::c_void>(),
            probe.len(),
        )
    };
    assert_eq!(
        n, 0,
        "expected EOF (0) on peer socket when all TUN fds are closed, got {n}"
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn android_unix_packet_fd_bridge_and_protect_callback_e2e() {
    let _serial = SERIAL_ANDROID_FFI_LOCK.lock().await;

    use proxy_core::{
        engine::ProxyEngine,
        platform::socket_protect::{clear_global_socket_protector, set_global_socket_protector},
    };
    use proxy_ffi::fd_bridge::{CallbackSocketProtector, UnixPacketFdBridge};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // 1. Install `CallbackSocketProtector` simulating `VpnService.protect(fd)` and verify every outbound socket calls it!
    let protector = Arc::new(CallbackSocketProtector::new_unix(
        "test-android-protect",
        true,
        |fd| {
            assert!(fd >= 0, "valid socket fd passed to protect(fd)");
            Ok(())
        },
    ));
    set_global_socket_protector(Arc::clone(&protector) as _);

    let engine = ProxyEngine::start_demo(
        Some(0),
        Some("127.0.0.1:0".into()),
        Some("127.0.0.1:0".into()),
    )
    .await
    .expect("start demo");

    let mut cfg = engine.config_snapshot();
    cfg.tun.enable = true;
    cfg.tun.auto_route = false;
    engine
        .reload_yaml(&cfg.to_yaml_string().unwrap())
        .await
        .expect("enable virtual tun");

    let vtun = engine
        .take_virtual_tun_handle()
        .expect("take virtual tun handle");

    // 2. Create a Unix `SOCK_SEQPACKET` socketpair emulating Android's `VpnService.Builder.establish()` TUN fd!
    let (vpn_tun_fd, kernel_side_fd, vpn_inode) = create_tun_like_socketpair();

    let mut bridge =
        UnixPacketFdBridge::attach_raw_fd(vpn_tun_fd, vtun).expect("attach UnixPacketFdBridge");

    // Inject raw L3 IPv4 DNS query into `kernel_side_fd` -> `UnixPacketFdBridge` -> `smoltcp` -> reply on `kernel_side_fd`!
    let dns_q = build_dns_query(0x7788, "android-vpn-fd.example", QTYPE_A);
    let raw_l3 = build_raw_ipv4_udp_packet([198, 18, 0, 55], [198, 18, 0, 1], 54123, 53, &dns_q);
    let wrote = unsafe {
        libc::write(
            kernel_side_fd,
            raw_l3.as_ptr().cast::<libc::c_void>(),
            raw_l3.len(),
        )
    };
    assert_eq!(wrote as usize, raw_l3.len());

    let mut reply_buf = [0u8; 2048];
    let mut pfd = libc::pollfd {
        fd: kernel_side_fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let polled = unsafe { libc::poll(&raw mut pfd, 1, 2000) };
    assert!(polled > 0, "received L3 packet back over Android TUN fd");
    let n = unsafe {
        libc::read(
            kernel_side_fd,
            reply_buf.as_mut_ptr().cast::<libc::c_void>(),
            reply_buf.len(),
        )
    };
    assert!(n > 28);
    assert!(bridge.rx_packets() >= 1);
    for _ in 0..20 {
        if bridge.tx_packets() >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(bridge.tx_packets() >= 1);

    // 3. Drive an outbound proxy connection through Mixed Inbound and verify `CallbackSocketProtector` protected the outbound socket!
    let mixed = engine.mixed_addr();
    let origin_url = engine.demo_info().http_benchmark_origin;
    let origin_addr = origin_url.strip_prefix("http://").unwrap();
    let mut stream = tokio::net::TcpStream::connect(mixed)
        .await
        .expect("connect mixed");
    let req = format!(
        "GET {origin_url}/echo HTTP/1.1\r\nHost: {origin_addr}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await.unwrap();
    assert!(String::from_utf8_lossy(&resp).contains("200 OK"));
    assert!(
        protector.tcp_count() + protector.udp_count() >= 1,
        "outbound proxy socket MUST invoke VpnService.protect(fd) callback!"
    );

    bridge.stop();
    assert_tun_fd_fully_closed_in_kernel(vpn_tun_fd, vpn_inode, kernel_side_fd);
    unsafe {
        libc::close(kernel_side_fd);
    }
    engine.shutdown();
    clear_global_socket_protector();
}

#[cfg(unix)]
#[test]
fn android_native_start_vpn_raii_closes_tun_fd_on_all_error_paths_duplicate_start_and_revoke() {
    use std::os::fd::{FromRawFd, OwnedFd};

    use proxy_ffi::{
        android_jni::{
            android_status_json_core, notify_android_network_changed_core, start_android_vpn_core,
            stop_android_vpn_core,
        },
        fd_bridge::CallbackSocketProtector,
    };

    let _serial = SERIAL_ANDROID_FFI_LOCK.blocking_lock();
    let _ = stop_android_vpn_core();

    let make_protector = || {
        Arc::new(CallbackSocketProtector::new_unix(
            "android-raii-test",
            false,
            |_fd| Ok(()),
        ))
    };

    // 1. Error Path A: Invalid YAML profile -> `fd_bad_yaml` MUST be closed immediately!
    let (fd_bad_yaml, peer_bad_yaml, ino_bad_yaml) = create_tun_like_socketpair();
    let owned_bad_yaml = unsafe { OwnedFd::from_raw_fd(fd_bad_yaml) };
    let err_yaml = start_android_vpn_core(
        Some(owned_bad_yaml),
        "not: valid: clash: yaml: [[[",
        false,
        make_protector(),
    )
    .expect_err("invalid YAML must fail");
    assert!(err_yaml.contains("invalid YAML profile"));
    assert_tun_fd_fully_closed_in_kernel(fd_bad_yaml, ino_bad_yaml, peer_bad_yaml);
    unsafe { libc::close(peer_bad_yaml) };

    // 2. Error Path B: `ProxyEngine::start` port-conflict failure -> `fd_conflict` MUST be closed!
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let occupied_port = occupied.local_addr().unwrap().port();
    let conflict_yaml = format!(
        "mixed-port: {occupied_port}\nbind-address: 127.0.0.1\nmode: rule\ndns:\n  enable: false\nproxies: []\nproxy-groups: []\nrules:\n  - MATCH,DIRECT\n"
    );
    let (fd_conflict, peer_conflict, ino_conflict) = create_tun_like_socketpair();
    let owned_conflict = unsafe { OwnedFd::from_raw_fd(fd_conflict) };
    let err_conflict = start_android_vpn_core(
        Some(owned_conflict),
        &conflict_yaml,
        false,
        make_protector(),
    )
    .expect_err("port conflict must fail ProxyEngine::start");
    assert!(err_conflict.contains("ProxyEngine start failed"));
    assert_tun_fd_fully_closed_in_kernel(fd_conflict, ino_conflict, peer_conflict);
    drop(occupied);
    unsafe { libc::close(peer_conflict) };

    // 3. Valid Start #1 (`fd1`) followed by Duplicate Start #2 (`fd2`):
    //    `fd1` (and its dup'd `tx_fd`) MUST be closed in kernel when Session #2 replaces Session #1!
    let valid_yaml = "mixed-port: 0\nbind-address: 127.0.0.1\nmode: rule\ndns:\n  enable: true\n  listen: 127.0.0.1:0\nproxies: []\nproxy-groups: []\nrules:\n  - MATCH,DIRECT\n";
    let (fd1, peer1, ino1) = create_tun_like_socketpair();
    let res1 = start_android_vpn_core(
        Some(unsafe { OwnedFd::from_raw_fd(fd1) }),
        valid_yaml,
        false,
        make_protector(),
    )
    .expect("valid start #1");
    assert_eq!(res1["ok"], true);
    assert_eq!(fd_kernel_inode(fd1), Some(ino1));

    let (fd2, peer2, ino2) = create_tun_like_socketpair();
    let res2 = start_android_vpn_core(
        Some(unsafe { OwnedFd::from_raw_fd(fd2) }),
        valid_yaml,
        false,
        make_protector(),
    )
    .expect("duplicate start #2");
    assert_eq!(res2["ok"], true);
    assert_tun_fd_fully_closed_in_kernel(fd1, ino1, peer1);
    assert_eq!(fd_kernel_inode(fd2), Some(ino2));

    // Verify L3 packet flows across `fd2`, and test Android Wi-Fi -> Cellular handoff!
    let dns_q = build_dns_query(0x9191, "raii-handoff.android.test", QTYPE_A);
    let raw_l3 = build_raw_ipv4_udp_packet([198, 18, 0, 77], [198, 18, 0, 1], 55111, 53, &dns_q);
    let wrote = unsafe { libc::write(peer2, raw_l3.as_ptr().cast(), raw_l3.len()) };
    assert_eq!(wrote as usize, raw_l3.len());
    let mut pfd = libc::pollfd {
        fd: peer2,
        events: libc::POLLIN,
        revents: 0,
    };
    assert!(unsafe { libc::poll(&raw mut pfd, 1, 2000) } > 0);
    let mut rbuf = [0u8; 1024];
    let n = unsafe { libc::read(peer2, rbuf.as_mut_ptr().cast(), rbuf.len()) };
    assert!(n > 28);

    // Baseline Wi-Fi registration (handle=100, wifi=true) -> does NOT count as a handoff transition
    let base_rep = notify_android_network_changed_core(100, true).expect("active runtime");
    assert!(!base_rep.dns_cache_flushed);
    assert_eq!(android_status_json_core()["networkTransitions"], 0);

    // Real Wi-Fi -> Cellular handoff (handle=200, wifi=false) -> full session reset & DNS cache flush!
    let handoff_rep = notify_android_network_changed_core(200, false).expect("active runtime");
    assert!(handoff_rep.dns_cache_flushed);
    let status = android_status_json_core();
    assert_eq!(status["networkTransitions"], 1);
    assert_eq!(status["isWifi"], false);

    // 4. Duplicate Start #3 that FAILS with invalid YAML (`fd3`):
    //    BOTH previous `fd2` AND failed `fd3` MUST be closed in kernel, and runtime cleanly stopped!
    let (fd3, peer3, ino3) = create_tun_like_socketpair();
    let _ = start_android_vpn_core(
        Some(unsafe { OwnedFd::from_raw_fd(fd3) }),
        "broken_yaml: [unclosed",
        false,
        make_protector(),
    )
    .expect_err("failed duplicate start #3");
    assert_tun_fd_fully_closed_in_kernel(fd2, ino2, peer2);
    assert_tun_fd_fully_closed_in_kernel(fd3, ino3, peer3);
    assert_eq!(android_status_json_core()["running"], false);

    // 5. Start #4 (`fd4`) -> System VPN revocation (`onRevoke` / `stop_android_vpn_core`) + idempotent double-stop
    let (fd4, peer4, ino4) = create_tun_like_socketpair();
    start_android_vpn_core(
        Some(unsafe { OwnedFd::from_raw_fd(fd4) }),
        valid_yaml,
        false,
        make_protector(),
    )
    .expect("start #4");
    assert_eq!(fd_kernel_inode(fd4), Some(ino4));

    assert!(
        stop_android_vpn_core(),
        "first stop (onRevoke) returns true"
    );
    assert_tun_fd_fully_closed_in_kernel(fd4, ino4, peer4);
    assert!(
        !stop_android_vpn_core(),
        "idempotent second stop returns false without double-close"
    );

    unsafe {
        libc::close(peer1);
        libc::close(peer2);
        libc::close(peer3);
        libc::close(peer4);
    }
}

#[cfg(unix)]
#[test]
fn android_offline_node_import_select_edit_and_vpn_restart_persistence_e2e() {
    use std::os::fd::{FromRawFd, OwnedFd};

    use base64::{
        Engine as _,
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    };
    use proxy_ffi::{
        android_jni::{
            android_deduplicate_nodes_core, android_delete_node_core, android_import_unified_core,
            android_node_manager_snapshot_core, android_select_proxy_persisted_core,
            android_status_json_core, android_upsert_node_core, start_android_vpn_with_state_dir,
            stop_android_vpn_core,
        },
        fd_bridge::CallbackSocketProtector,
    };
    use uuid::Uuid;

    let _serial = SERIAL_ANDROID_FFI_LOCK.blocking_lock();
    let _ = stop_android_vpn_core();

    let state_dir = std::env::temp_dir().join(format!("rc-android-node-e2e-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&state_dir).unwrap();

    let make_protector = || {
        Arc::new(CallbackSocketProtector::new_unix(
            "android-node-persist-test",
            false,
            |_fd| Ok(()),
        ))
    };

    // 1. OFFLINE (`DISCONNECTED`): blank snapshot has 0 nodes and `DIRECT` effective outbound
    assert_eq!(android_status_json_core()["running"], false);
    let snap0 = android_node_manager_snapshot_core(&state_dir).expect("offline blank snapshot");
    assert_eq!(snap0["vpnRunning"], false);
    assert_eq!(snap0["nodes"].as_array().unwrap().len(), 0);
    assert_eq!(snap0["effectiveOutbound"], "DIRECT");

    // 2. OFFLINE: Import Base64 subscription (`ss://` + `vless://` + `anytls://`) while VPN is OFF!
    let ss_psk = STANDARD.encode([0x31u8; 32]);
    let ss_user = URL_SAFE_NO_PAD.encode(format!("2022-blake3-aes-256-gcm:{ss_psk}"));
    let vless_uuid = Uuid::new_v4();
    let anytls_pass = "android-anytls-secret-8899";
    let raw_uris = format!(
        "ss://{ss_user}@198.51.100.10:8388#Android-SS\nvless://{vless_uuid}@198.51.100.20:443?security=tls&sni=example.com#Android-VLESS\nanytls://{anytls_pass}@198.51.100.30:8443?sni=example.com#Android-AnyTLS"
    );
    let b64_sub = STANDARD.encode(&raw_uris);

    let imp = android_import_unified_core(&state_dir, &b64_sub, true, true)
        .expect("offline Base64 import");
    assert_eq!(imp["ok"], true);
    assert_eq!(imp["vpnRunning"], false);
    assert_eq!(imp["inputKind"], "base64-uri-list");
    assert_eq!(imp["count"], 3);
    assert_eq!(imp["totalNodes"], 3);
    assert_eq!(
        imp["effectiveOutbound"], "Android-SS",
        "PROXY group must auto-switch off DIRECT onto imported concrete node even while offline"
    );

    // Ensure returned snapshot redacts secrets
    let imp_str = imp.to_string();
    assert!(!imp_str.contains(&ss_psk));
    assert!(!imp_str.contains(&vless_uuid.to_string()));
    assert!(!imp_str.contains(anytls_pass));

    // 3. OFFLINE: Select `Android-VLESS` and rename it to `Android-VLESS-Edited` preserving redacted UUID
    let sel_snap = android_select_proxy_persisted_core(&state_dir, "PROXY", "Android-VLESS")
        .expect("offline select proxy");
    assert_eq!(sel_snap["effectiveOutbound"], "Android-VLESS");

    let mut vless_node_json = sel_snap["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["name"] == "Android-VLESS")
        .unwrap()
        .clone();
    vless_node_json["name"] = serde_json::Value::String("Android-VLESS-Edited".into());
    let edited = android_upsert_node_core(
        &state_dir,
        Some("Android-VLESS"),
        &vless_node_json.to_string(),
        false,
    )
    .expect("offline rename node");
    assert_eq!(edited["updatedNode"], "Android-VLESS-Edited");
    assert_eq!(edited["effectiveOutbound"], "Android-VLESS-Edited");

    // 4. OFFLINE: Strict VLESS REALITY rejection must NOT leak PBK/UUID and must NOT corrupt saved nodes
    let bad_reality = "vless://22222222-3333-4444-5555-666666666666@example.com:443?security=reality&pbk=ANDROID_SECRET_PBK_999#Reality";
    let bad_err = android_import_unified_core(&state_dir, bad_reality, true, true)
        .expect_err("VLESS reality must be rejected");
    assert!(!bad_err.contains("22222222-3333-4444-5555-666666666666"));
    assert!(!bad_err.contains("ANDROID_SECRET_PBK_999"));

    // 5. START VPN #1 (`fd1`): Must restore all 3 nodes AND `Android-VLESS-Edited` selection!
    let (fd1, peer1, ino1) = create_tun_like_socketpair();
    let start1 = start_android_vpn_with_state_dir(
        Some(unsafe { OwnedFd::from_raw_fd(fd1) }),
        Some(&state_dir),
        "",
        false,
        make_protector(),
    )
    .expect("start VPN #1 from state_dir");
    assert_eq!(start1["ok"], true);
    assert_eq!(start1["effectiveOutbound"], "Android-VLESS-Edited");
    assert_eq!(
        android_status_json_core()["effectiveOutbound"],
        "Android-VLESS-Edited"
    );

    // 6. LIVE VPN MUTATIONS: Import duplicate + new node, deduplicate, delete, and switch selection
    //    WITHOUT dropping the attached Android TUN `fd1`!
    let live_add = format!("ss://{ss_user}@198.51.100.99:8388#Android-Live-SS");
    let live_imp = android_import_unified_core(&state_dir, &live_add, true, false)
        .expect("live node import while VPN running");
    assert_eq!(live_imp["vpnRunning"], true);
    assert_eq!(live_imp["totalNodes"], 4);
    assert_eq!(live_imp["effectiveOutbound"], "Android-VLESS-Edited");

    let live_sel = android_select_proxy_persisted_core(&state_dir, "PROXY", "Android-AnyTLS")
        .expect("live select proxy");
    assert_eq!(live_sel["effectiveOutbound"], "Android-AnyTLS");

    let _ = android_deduplicate_nodes_core(&state_dir).expect("live deduplicate");
    let after_del =
        android_delete_node_core(&state_dir, "Android-Live-SS").expect("live delete node");
    assert_eq!(after_del["totalNodes"], 3);
    assert_eq!(after_del["effectiveOutbound"], "Android-AnyTLS");

    // Prove `fd1` was NEVER dropped during live node mutations and still processes L3 DNS packets!
    assert_eq!(fd_kernel_inode(fd1), Some(ino1));
    let dns_q = build_dns_query(0x7777, "live-mutation.android.test", QTYPE_A);
    let raw_l3 = build_raw_ipv4_udp_packet([198, 18, 0, 88], [198, 18, 0, 1], 54321, 53, &dns_q);
    let wrote = unsafe { libc::write(peer1, raw_l3.as_ptr().cast(), raw_l3.len()) };
    assert_eq!(wrote as usize, raw_l3.len());
    let mut pfd = libc::pollfd {
        fd: peer1,
        events: libc::POLLIN,
        revents: 0,
    };
    assert!(
        unsafe { libc::poll(&raw mut pfd, 1, 2000) } > 0,
        "Android TUN fd must continue forwarding L3 packets after live node mutations"
    );
    let mut rbuf = [0u8; 1024];
    let n = unsafe { libc::read(peer1, rbuf.as_mut_ptr().cast(), rbuf.len()) };
    assert!(n > 28);

    // 7. STOP VPN #1 -> START VPN #2 (`fd2`): Nodes and `Android-AnyTLS` selection MUST persist!
    assert!(stop_android_vpn_core());
    assert_tun_fd_fully_closed_in_kernel(fd1, ino1, peer1);

    let (fd2, peer2, ino2) = create_tun_like_socketpair();
    let start2 = start_android_vpn_with_state_dir(
        Some(unsafe { OwnedFd::from_raw_fd(fd2) }),
        Some(&state_dir),
        "",
        false,
        make_protector(),
    )
    .expect("start VPN #2 after restart");
    assert_eq!(start2["effectiveOutbound"], "Android-AnyTLS");
    let snap2 = android_node_manager_snapshot_core(&state_dir).unwrap();
    assert_eq!(snap2["nodes"].as_array().unwrap().len(), 3);
    assert_eq!(snap2["effectiveOutbound"], "Android-AnyTLS");

    assert!(stop_android_vpn_core());
    assert_tun_fd_fully_closed_in_kernel(fd2, ino2, peer2);
    unsafe {
        libc::close(peer1);
        libc::close(peer2);
    }
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[cfg(unix)]
#[test]
fn android_jni_split_tunneling_presets_offline_explain_and_diagnostics_e2e() {
    use std::os::fd::{FromRawFd, OwnedFd};

    use proxy_ffi::{
        android_jni::{
            android_clear_diagnostics_core, android_explain_rule_with_state_dir_core,
            android_geodata_status_core, android_get_active_yaml_core,
            android_get_diagnostics_core, android_get_routing_snapshot_core,
            android_import_unified_core, android_node_manager_snapshot_core,
            android_profiles_snapshot_core, android_save_custom_rules_core,
            android_set_routing_preset_core, start_android_vpn_with_state_dir,
            stop_android_vpn_core,
        },
        fd_bridge::CallbackSocketProtector,
    };
    use uuid::Uuid;

    let _serial = SERIAL_ANDROID_FFI_LOCK.blocking_lock();
    let _ = stop_android_vpn_core();

    let state_dir = std::env::temp_dir().join(format!("rc-android-split-e2e-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&state_dir).unwrap();

    // 1. OFFLINE (`DISCONNECTED`): starter profile defaults to `smart-cn` (`智能分流`) with GeoData ready!
    let snap0 = android_node_manager_snapshot_core(&state_dir).expect("offline snapshot");
    assert_eq!(snap0["vpnRunning"], false);
    assert_eq!(snap0["routing"]["active_choice"], "smart-cn");
    assert_eq!(snap0["routing"]["rule_preset"], "smart-cn");
    assert!(
        snap0["geodata"]["geosite_cn_entries"].as_u64().unwrap_or(0) >= 200,
        "built-in GeoSite CN baseline must be loaded offline"
    );

    let geo_st = android_geodata_status_core(&state_dir).expect("offline geodata status");
    assert_eq!(geo_st["ok"], true);
    assert!(geo_st["geodata"]["geoip_cn_ranges"].as_u64().unwrap_or(0) >= 30);

    // 2. OFFLINE: Import VLESS node, then run `android_explain_rule_with_state_dir_core` while VPN is OFF!
    let hk_uuid = Uuid::new_v4();
    let vless_uri = format!(
        "vless://{hk_uuid}@203.0.113.10:443?security=tls&sni=hk.example.com&insecure=1#HK-Split-VLESS"
    );
    let imp = android_import_unified_core(&state_dir, &vless_uri, true, true)
        .expect("import VLESS offline");
    assert_eq!(imp["effectiveOutbound"], "HK-Split-VLESS");

    let ex_cn = android_explain_rule_with_state_dir_core(&state_dir, "www.baidu.com")
        .expect("offline explain CN");
    assert_eq!(ex_cn["vpnRunning"], false);
    assert_eq!(ex_cn["exit_type"], "DIRECT");
    assert_eq!(ex_cn["outbound"], "DIRECT");

    let ex_cn_ip = android_explain_rule_with_state_dir_core(&state_dir, "114.114.114.114:443")
        .expect("offline explain CN IP");
    assert_eq!(ex_cn_ip["exit_type"], "DIRECT");

    let ex_intl = android_explain_rule_with_state_dir_core(&state_dir, "www.google.com")
        .expect("offline explain international");
    assert_eq!(ex_intl["exit_type"], "PROXY");
    assert_eq!(ex_intl["outbound"], "HK-Split-VLESS");

    // 3. OFFLINE: Save custom rules -> switch to `smart-cn` -> switch back to `custom` (zero loss!)
    let custom_rules = "DOMAIN-SUFFIX,corp.example.internal,DIRECT\nMATCH,HK-Split-VLESS";
    let after_custom = android_save_custom_rules_core(&state_dir, custom_rules)
        .expect("save custom rules offline");
    assert_eq!(after_custom["routing"]["active_choice"], "custom");
    assert_eq!(after_custom["routing"]["rule_preset"], "custom");

    let ex_corp = android_explain_rule_with_state_dir_core(&state_dir, "git.corp.example.internal")
        .expect("offline explain custom rule");
    assert_eq!(ex_corp["exit_type"], "DIRECT");

    let after_scn =
        android_set_routing_preset_core(&state_dir, "smart-cn").expect("switch to smart-cn");
    assert_eq!(after_scn["routing"]["active_choice"], "smart-cn");
    assert_eq!(after_scn["routing"]["has_custom_rules_backup"], true);

    let after_restore =
        android_set_routing_preset_core(&state_dir, "custom").expect("restore custom rules");
    assert_eq!(after_restore["routing"]["active_choice"], "custom");
    let yaml_snap = android_get_active_yaml_core(&state_dir).expect("get active redacted yaml");
    assert!(
        !yaml_snap["yaml"]
            .as_str()
            .unwrap()
            .contains(&hk_uuid.to_string())
    );
    assert_eq!(yaml_snap["rules"].as_array().unwrap().len(), 2);

    // Restore `smart-cn` before starting VPN
    let _ = android_set_routing_preset_core(&state_dir, "smart-cn").unwrap();

    // 4. ONLINE (`CONNECTED`): Start Android VPN over `fd_bridge`, switch presets live without dropping TUN fd,
    //    and verify live `explain`, `profiles_snapshot`, and `diagnostics` APIs!
    let (fd1, peer1, ino1) = create_tun_like_socketpair();
    let protector = Arc::new(CallbackSocketProtector::new_unix(
        "android-split-live",
        true,
        |_fd| Ok(()),
    ));
    let start = start_android_vpn_with_state_dir(
        Some(unsafe { OwnedFd::from_raw_fd(fd1) }),
        Some(&state_dir),
        "",
        false,
        protector,
    )
    .expect("start Android VPN");
    assert_eq!(start["ok"], true);

    let live_ex_cn = android_explain_rule_with_state_dir_core(&state_dir, "www.bilibili.com")
        .expect("live explain CN");
    assert_eq!(live_ex_cn["vpnRunning"], true);
    assert_eq!(live_ex_cn["exit_type"], "DIRECT");

    let live_ex_intl = android_explain_rule_with_state_dir_core(&state_dir, "www.youtube.com")
        .expect("live explain YT");
    assert_eq!(live_ex_intl["exit_type"], "PROXY");
    assert_eq!(live_ex_intl["outbound"], "HK-Split-VLESS");

    // Switch live preset `smart-cn` -> `global` -> `direct` -> `smart-cn` while `fd1` remains open!
    let live_glob =
        android_set_routing_preset_core(&state_dir, "global").expect("live switch global");
    assert_eq!(live_glob["routing"]["active_choice"], "global");
    assert_eq!(
        android_explain_rule_with_state_dir_core(&state_dir, "www.baidu.com").unwrap()["exit_type"],
        "PROXY"
    );

    let live_dir =
        android_set_routing_preset_core(&state_dir, "direct").expect("live switch direct");
    assert_eq!(live_dir["routing"]["active_choice"], "direct");
    assert_eq!(
        android_explain_rule_with_state_dir_core(&state_dir, "www.google.com").unwrap()["exit_type"],
        "DIRECT"
    );

    let live_back =
        android_set_routing_preset_core(&state_dir, "smart-cn").expect("live restore smart-cn");
    assert_eq!(live_back["routing"]["active_choice"], "smart-cn");
    assert_eq!(
        android_get_routing_snapshot_core(&state_dir).unwrap()["routing"]["active_choice"],
        "smart-cn"
    );
    assert_eq!(fd_kernel_inode(fd1), Some(ino1));

    let profs = android_profiles_snapshot_core(&state_dir).expect("live profiles snapshot");
    assert_eq!(profs["vpnRunning"], true);
    assert!(
        !profs["profilesSnapshot"]["profiles"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let diag = android_get_diagnostics_core(50);
    assert_eq!(diag["ok"], true);
    assert_eq!(diag["vpnRunning"], true);
    assert!(android_clear_diagnostics_core());

    assert!(stop_android_vpn_core());
    assert_tun_fd_fully_closed_in_kernel(fd1, ino1, peer1);
    unsafe {
        libc::close(peer1);
    }
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[cfg(unix)]
#[test]
fn android_offline_router_cache_and_positive_dns_seed_transfer_to_vpn() {
    use std::{
        net::Ipv4Addr,
        os::fd::{FromRawFd, OwnedFd},
        sync::atomic::AtomicUsize,
    };

    use proxy_core::dns::wire::{DnsAnswerData, DnsQueryPacket, QTYPE_A};
    use proxy_ffi::{
        android_jni::{
            android_flush_dns_core, android_import_unified_core, android_test_latency_core,
            start_android_vpn_with_state_dir, stop_android_vpn_core,
        },
        fd_bridge::CallbackSocketProtector,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
        sync::watch,
    };
    use uuid::Uuid;

    let _serial = SERIAL_ANDROID_FFI_LOCK.blocking_lock();
    let _ = stop_android_vpn_core();
    let _ = android_flush_dns_core();

    let bg_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let (stop_tx, stop_rx) = watch::channel(false);
    let dns_queries = Arc::new(AtomicUsize::new(0));
    let dns_queries_bg = Arc::clone(&dns_queries);

    let (dns_addr, ss_addr, http_addr) = bg_rt.block_on(async {
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let d_addr = udp.local_addr().unwrap();
        let mut d_stop = stop_rx.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                tokio::select! {
                    _ = d_stop.changed() => break,
                    recv = udp.recv_from(&mut buf) => {
                        let Ok((n, peer)) = recv else { break };
                        let pkt = &buf[..n];
                        let Ok(q) = DnsQueryPacket::parse(pkt) else { continue };
                        dns_queries_bg.fetch_add(1, Ordering::SeqCst);
                        let resp = if q.question.name == "gw.seed-test.example" && q.question.qtype == QTYPE_A {
                            q.build_response(pkt, 0, 180, &[DnsAnswerData::A(Ipv4Addr::LOCALHOST)])
                        } else {
                            q.build_response(pkt, 0, 180, &[])
                        };
                        let _ = udp.send_to(&resp, peer).await;
                    }
                }
            }
        });

        let (s_addr, _s_task) = proxy_core::outbound::ss::spawn_ss_server(
            "127.0.0.1:0",
            "chacha20-ietf-poly1305",
            "android-seed-secret",
            stop_rx.clone(),
        )
        .await
        .unwrap();

        let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let h_addr = http_listener.local_addr().unwrap();
        let mut h_stop = stop_rx.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = h_stop.changed() => break,
                    acc = http_listener.accept() => {
                        let Ok((mut sock, _)) = acc else { break };
                        tokio::spawn(async move {
                            let mut buf = Vec::with_capacity(512);
                            let mut tmp = [0u8; 256];
                            loop {
                                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                    let Ok(n) = sock.read(&mut tmp).await else { return };
                                    if n == 0 {
                                        return;
                                    }
                                    buf.extend_from_slice(&tmp[..n]);
                                }
                                let hdr_end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                                buf.drain(..hdr_end);
                                let resp = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n";
                                if sock.write_all(resp).await.is_err() || sock.flush().await.is_err() {
                                    return;
                                }
                            }
                        });
                    }
                }
            }
        });

        (d_addr, s_addr, h_addr)
    });

    let state_dir = std::env::temp_dir().join(format!("rc-android-seed-e2e-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&state_dir).unwrap();

    let yaml = format!(
        r#"mixed-port: 0
mode: rule
unified-delay: true
dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  nameserver:
    - "{dns_addr}"
  proxy-server-nameserver:
    - "{dns_addr}"
proxies:
  - name: "SS-SEED"
    type: ss
    server: gw.seed-test.example
    port: {ss_port}
    cipher: chacha20-ietf-poly1305
    password: "android-seed-secret"
    udp: true
proxy-groups:
  - name: "PROXY"
    type: select
    proxies:
      - "SS-SEED"
rules:
  - MATCH,PROXY
"#,
        ss_port = ss_addr.port(),
    );

    let imp = android_import_unified_core(&state_dir, &yaml, true, true)
        .expect("import custom DNS profile offline");
    assert_eq!(imp["ok"], true);
    assert_eq!(imp["effectiveOutbound"], "SS-SEED");

    let probe_url = format!("http://{http_addr}/generate_204");

    // 1. Offline latency probe #1 -> resolves `gw.seed-test.example` once (`dns_queries == 1`)
    let p1 = android_test_latency_core(&state_dir, None, Some(&probe_url), 3000)
        .expect("offline latency probe #1");
    assert_eq!(p1["ok"], true);
    assert_eq!(p1["tested"], 1);
    assert!(p1["delays"]["SS-SEED"].as_u64().unwrap_or(0) > 0);
    assert_eq!(
        dns_queries.load(Ordering::SeqCst),
        1,
        "first offline latency probe must resolve proxy server hostname once"
    );

    // 2. Offline latency probe #2 -> reuses `OFFLINE_ROUTER_CACHE` (`dns_queries` stays `1`!)
    let p2 = android_test_latency_core(&state_dir, None, Some(&probe_url), 3000)
        .expect("offline latency probe #2");
    assert_eq!(p2["ok"], true);
    assert!(p2["delays"]["SS-SEED"].as_u64().unwrap_or(0) > 0);
    assert_eq!(
        dns_queries.load(Ordering::SeqCst),
        1,
        "repeated offline probe must reuse cached offline Router + proxy_ip_cache without extra DNS lookups"
    );

    // 3. Start Android VPN -> harvests `PositiveDnsCacheSeed` into live `ProxyEngine` (`PreconnectPolicy::Mobile`)!
    //    Neither startup preconnect nor live latency probe #3 needs an extra DNS lookup (`dns_queries` stays `1`!)
    let (fd1, peer1, ino1) = create_tun_like_socketpair();
    let protector = Arc::new(CallbackSocketProtector::new_unix(
        "android-seed-live",
        true,
        |_fd| Ok(()),
    ));
    let started = start_android_vpn_with_state_dir(
        Some(unsafe { OwnedFd::from_raw_fd(fd1) }),
        Some(&state_dir),
        "",
        false,
        protector,
    )
    .expect("start Android VPN with seeded DNS cache");
    assert_eq!(started["ok"], true);
    assert_eq!(started["effectiveOutbound"], "SS-SEED");

    let p3 = android_test_latency_core(&state_dir, None, Some(&probe_url), 3000)
        .expect("live latency probe #3");
    assert_eq!(p3["ok"], true);
    assert!(p3["delays"]["SS-SEED"].as_u64().unwrap_or(0) > 0);
    assert_eq!(
        dns_queries.load(Ordering::SeqCst),
        1,
        "PositiveDnsCacheSeed transferred from offline probe must eliminate redundant DNS query on VPN start"
    );

    // 4. Explicit `android_flush_dns_core()` flushes live cache -> next probe re-queries (`dns_queries == 2`)!
    assert!(android_flush_dns_core());
    let p4 = android_test_latency_core(&state_dir, None, Some(&probe_url), 3000)
        .expect("live latency probe after flush");
    assert_eq!(p4["ok"], true);
    assert!(p4["delays"]["SS-SEED"].as_u64().unwrap_or(0) > 0);
    assert_eq!(
        dns_queries.load(Ordering::SeqCst),
        2,
        "flushing DNS cache must trigger a fresh proxy server resolution on next probe"
    );

    assert!(stop_android_vpn_core());
    assert_tun_fd_fully_closed_in_kernel(fd1, ino1, peer1);
    unsafe {
        libc::close(peer1);
    }
    let _ = stop_tx.send(true);
    bg_rt.shutdown_timeout(Duration::from_millis(200));
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[cfg(unix)]
#[test]
fn android_update_profile_settings_and_manual_overlay_ffi_e2e() {
    use proxy_core::profile::{CreateProfileSpec, ProfileManager};
    use proxy_ffi::android_jni::{
        android_import_unified_core, android_profiles_snapshot_core,
        android_update_profile_settings_core, stop_android_vpn_core,
    };
    use uuid::Uuid;

    let _serial = SERIAL_ANDROID_FFI_LOCK.blocking_lock();
    let _ = stop_android_vpn_core();

    let state_dir =
        std::env::temp_dir().join(format!("rc-android-prof-settings-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&state_dir).unwrap();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let prof_id = rt.block_on(async {
        let mgr = ProfileManager::open_or_init(&state_dir).unwrap();
        let (meta, _) = mgr
            .create_profile(CreateProfileSpec {
                name: "Android Sub".into(),
                yaml: None,
                uris: Some("socks5://127.0.0.1:1080#Base-SOCKS".into()),
                subscription_url: None,
                auto_update_interval_secs: Some(86400),
                activate: true,
            })
            .await
            .unwrap();
        let _ = mgr.set_active_profile(&meta.id).unwrap();
        meta.id
    });

    // Add a manual SOCKS5 node offline via `android_import_unified_core`
    let imp = android_import_unified_core(
        &state_dir,
        "socks5://127.0.0.1:1081#Manual-Android-Node",
        true,
        true,
    )
    .expect("import manual node onto active profile");
    assert_eq!(imp["ok"], true);
    assert_eq!(imp["effectiveOutbound"], "Manual-Android-Node");

    // Rename + disable auto-update (`Some(Some(0))` -> `null`) via `android_update_profile_settings_core`
    let updated_off = android_update_profile_settings_core(
        &state_dir,
        &prof_id,
        Some("主力订阅-已改名".to_string()),
        Some(Some(0)),
    )
    .expect("disable auto-update via FFI helper");
    assert_eq!(updated_off["ok"], true);
    assert_eq!(updated_off["profile"]["name"], "主力订阅-已改名");
    assert!(updated_off["profile"]["auto_update_interval_secs"].is_null());
    assert_eq!(updated_off["profile"]["manual_proxy_count"], 1);

    // Re-enable auto-update (`Some(Some(21600))`) without changing name (`None`)
    let updated_on =
        android_update_profile_settings_core(&state_dir, &prof_id, None, Some(Some(21600)))
            .expect("enable 6h auto-update via FFI helper");
    assert_eq!(updated_on["ok"], true);
    assert_eq!(updated_on["profile"]["name"], "主力订阅-已改名");
    assert_eq!(updated_on["profile"]["auto_update_interval_secs"], 21600);

    // Clamp sub-60s intervals to 60s
    let updated_clamp =
        android_update_profile_settings_core(&state_dir, &prof_id, None, Some(Some(10)))
            .expect("clamp interval via FFI helper");
    assert_eq!(updated_clamp["profile"]["auto_update_interval_secs"], 60);

    let snap = android_profiles_snapshot_core(&state_dir).expect("profiles snapshot");
    let prof_entry = snap["profilesSnapshot"]["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == prof_id)
        .unwrap();
    assert_eq!(prof_entry["manual_proxy_count"], 1);
    assert_eq!(prof_entry["auto_update_interval_secs"], 60);

    let _ = std::fs::remove_dir_all(&state_dir);
}

#[cfg(unix)]
#[test]
fn android_debug_diagnostic_snapshot_live_offline_and_redaction_e2e() {
    use std::{
        net::Ipv4Addr,
        os::fd::{FromRawFd, OwnedFd},
    };

    use proxy_core::dns::wire::{DnsAnswerData, DnsQueryPacket, QTYPE_A};
    use proxy_ffi::{
        android_jni::{
            android_collect_debug_snapshot_core, android_flush_dns_core,
            android_import_unified_core, android_is_debug_logging_core,
            android_set_debug_logging_core, start_android_vpn_with_state_dir,
            stop_android_vpn_core,
        },
        fd_bridge::CallbackSocketProtector,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
        sync::watch,
    };
    use uuid::Uuid;

    let _serial = SERIAL_ANDROID_FFI_LOCK.blocking_lock();
    let _ = stop_android_vpn_core();
    let _ = android_flush_dns_core();
    android_set_debug_logging_core(false);
    assert!(!android_is_debug_logging_core());

    let bg_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let (stop_tx, stop_rx) = watch::channel(false);

    let sub_secret_token = "SUPER_SECRET_SUB_TOKEN_9999";
    let socks_secret_pass = "SOCKS_DEBUG_SECRET_PASS_8888";
    let vless_secret_uuid = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    let (dns_addr, socks_addr, http_origin_addr, dead_port, sub_addr) = bg_rt.block_on(async {
        // 1. Mock authoritative DNS server resolving `api.bilibili.com` -> 127.0.0.1
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let d_addr = udp.local_addr().unwrap();
        let mut d_stop = stop_rx.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                tokio::select! {
                    _ = d_stop.changed() => break,
                    recv = udp.recv_from(&mut buf) => {
                        let Ok((n, peer)) = recv else { break };
                        let pkt = &buf[..n];
                        let Ok(q) = DnsQueryPacket::parse(pkt) else { continue };
                        let resp = if q.question.qtype == QTYPE_A {
                            q.build_response(pkt, 0, 180, &[DnsAnswerData::A(Ipv4Addr::LOCALHOST)])
                        } else {
                            q.build_response(pkt, 0, 180, &[])
                        };
                        let _ = udp.send_to(&resp, peer).await;
                    }
                }
            }
        });

        // 2. Mock authenticated SOCKS5 proxy server (`HK-Node-01`) accepting any domain target
        let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let s_addr = socks_listener.local_addr().unwrap();
        let mut s_stop = stop_rx.clone();
        let expected_pass = socks_secret_pass.to_string();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = s_stop.changed() => break,
                    acc = socks_listener.accept() => {
                        let Ok((mut sock, _)) = acc else { break };
                        let pass_copy = expected_pass.clone();
                        tokio::spawn(async move {
                            let mut hdr = [0u8; 2];
                            if sock.read_exact(&mut hdr).await.is_err() || hdr[0] != 0x05 {
                                return;
                            }
                            let mut methods = vec![0u8; usize::from(hdr[1])];
                            if sock.read_exact(&mut methods).await.is_err() {
                                return;
                            }
                            if methods.contains(&0x02) {
                                if sock.write_all(&[0x05, 0x02]).await.is_err() {
                                    return;
                                }
                                let mut auth_hdr = [0u8; 2];
                                if sock.read_exact(&mut auth_hdr).await.is_err() {
                                    return;
                                }
                                let mut uname = vec![0u8; usize::from(auth_hdr[1])];
                                if sock.read_exact(&mut uname).await.is_err() {
                                    return;
                                }
                                let mut plen = [0u8; 1];
                                if sock.read_exact(&mut plen).await.is_err() {
                                    return;
                                }
                                let mut pw = vec![0u8; usize::from(plen[0])];
                                if sock.read_exact(&mut pw).await.is_err() {
                                    return;
                                }
                                if pw != pass_copy.as_bytes() {
                                    let _ = sock.write_all(&[0x01, 0x01]).await;
                                    return;
                                }
                                if sock.write_all(&[0x01, 0x00]).await.is_err() {
                                    return;
                                }
                            } else if sock.write_all(&[0x05, 0x00]).await.is_err() {
                                return;
                            }

                            let mut req = [0u8; 4];
                            if sock.read_exact(&mut req).await.is_err() {
                                return;
                            }
                            match req[3] {
                                0x01 => {
                                    let mut skip = [0u8; 6];
                                    let _ = sock.read_exact(&mut skip).await;
                                }
                                0x03 => {
                                    let mut dlen = [0u8; 1];
                                    if sock.read_exact(&mut dlen).await.is_err() {
                                        return;
                                    }
                                    let mut skip = vec![0u8; usize::from(dlen[0]) + 2];
                                    let _ = sock.read_exact(&mut skip).await;
                                }
                                0x04 => {
                                    let mut skip = [0u8; 18];
                                    let _ = sock.read_exact(&mut skip).await;
                                }
                                _ => return,
                            }
                            if sock
                                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                                .await
                                .is_err()
                            {
                                return;
                            }
                            let mut http_buf = [0u8; 512];
                            let _ = sock.read(&mut http_buf).await;
                            let _ = sock
                                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nproxy")
                                .await;
                        });
                    }
                }
            }
        });

        // 3. Direct HTTP origin server for `api.bilibili.com` (`DIRECT` rule)
        let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let h_addr = http_listener.local_addr().unwrap();
        let mut h_stop = stop_rx.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = h_stop.changed() => break,
                    acc = http_listener.accept() => {
                        let Ok((mut sock, _)) = acc else { break };
                        tokio::spawn(async move {
                            let mut buf = [0u8; 512];
                            let _ = sock.read(&mut buf).await;
                            let _ = sock
                                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndirect")
                                .await;
                        });
                    }
                }
            }
        });

        // 4. Reserve a closed port so `Dead-VLESS-Node` deterministically fails TCP connect
        let dead_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_port = dead_listener.local_addr().unwrap().port();
        drop(dead_listener);

        // 5. Subscription HTTP server hosting the YAML profile
        let sub_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sub_srv_addr = sub_listener.local_addr().unwrap();
        let sub_yaml = format!(
            r#"mixed-port: 0
mode: rule
unified-delay: true
dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  nameserver:
    - "{d_addr}"
proxies:
  - name: "HK-Node-01"
    type: socks5
    server: 127.0.0.1
    port: {socks_port}
    username: "debuguser"
    password: "{socks_secret_pass}"
    udp: true
  - name: "Dead-VLESS-Node"
    type: vless
    server: 127.0.0.1
    port: {closed_port}
    uuid: "{vless_secret_uuid}"
    tls: true
    servername: dead.example.com
proxy-groups:
  - name: "PROXY"
    type: select
    proxies:
      - "HK-Node-01"
      - "Dead-VLESS-Node"
rules:
  - DOMAIN-SUFFIX,bilibili.com,DIRECT
  - DOMAIN-SUFFIX,broken.example,Dead-VLESS-Node
  - DOMAIN-SUFFIX,google.com,HK-Node-01
  - MATCH,PROXY
"#,
            socks_port = s_addr.port(),
        );
        let mut sub_stop = stop_rx.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = sub_stop.changed() => break,
                    acc = sub_listener.accept() => {
                        let Ok((mut sock, _)) = acc else { break };
                        let body = sub_yaml.clone();
                        tokio::spawn(async move {
                            let mut buf = [0u8; 1024];
                            let _ = sock.read(&mut buf).await;
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: text/yaml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            let _ = sock.write_all(resp.as_bytes()).await;
                        });
                    }
                }
            }
        });

        (d_addr, s_addr, h_addr, closed_port, sub_srv_addr)
    });
    let _ = (dns_addr, socks_addr, dead_port);

    let state_dir = std::env::temp_dir().join(format!("rc-android-debug-e2e-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&state_dir).unwrap();

    // Import subscription URL containing secret query token
    let raw_sub_url = format!("http://{sub_addr}/api/v1/client/subscribe?token={sub_secret_token}");
    let imp = android_import_unified_core(&state_dir, &raw_sub_url, true, true)
        .expect("import subscription profile offline");
    assert_eq!(imp["ok"], true);

    // Enable debug mode BEFORE starting VPN and verify offline snapshot
    assert!(android_set_debug_logging_core(true));
    assert!(android_is_debug_logging_core());

    let offline_snap =
        android_collect_debug_snapshot_core(&state_dir, 0).expect("collect offline debug snapshot");
    assert_eq!(offline_snap["ok"], true);
    assert_eq!(offline_snap["vpnRunning"], false);
    assert_eq!(offline_snap["debugMode"], true);
    assert_eq!(offline_snap["activeProfile"]["proxyCount"], 2);
    let offline_raw_str = offline_snap.to_string();
    assert!(!offline_raw_str.contains(sub_secret_token));
    assert!(!offline_raw_str.contains(socks_secret_pass));
    assert!(!offline_raw_str.contains(vless_secret_uuid));

    // Start Android VPN -> debugMode propagates automatically onto live TelemetryHub
    let since_ms = proxy_core::tracker::TelemetryHub::now_ms().saturating_sub(50);
    let (fd1, peer1, ino1) = create_tun_like_socketpair();
    let protector = Arc::new(CallbackSocketProtector::new_unix(
        "android-debug-live",
        true,
        |_fd| Ok(()),
    ));
    let started = start_android_vpn_with_state_dir(
        Some(unsafe { OwnedFd::from_raw_fd(fd1) }),
        Some(&state_dir),
        "",
        false,
        protector,
    )
    .expect("start Android VPN with debug logging enabled");
    assert_eq!(started["ok"], true);
    let live_api_secret = started["apiSecret"].as_str().unwrap().to_string();
    let mixed_port = started["mixedPort"].as_u64().unwrap() as u16;
    assert!(mixed_port > 0);

    // Pump a Fake-IP L3 DNS query through the attached Android TUN fd (`peer1`) to exercise TUN + Fake-IP counters
    let dns_q = build_dns_query(0x7171, "tun-probe.google.com", QTYPE_A);
    let raw_l3 = build_raw_ipv4_udp_packet([198, 18, 0, 9], [198, 18, 0, 1], 53111, 53, &dns_q);
    let wrote = unsafe { libc::write(peer1, raw_l3.as_ptr().cast(), raw_l3.len()) };
    assert_eq!(wrote as usize, raw_l3.len());
    let mut reply_buf = [0u8; 512];
    for _ in 0..30 {
        let mut pfd = libc::pollfd {
            fd: peer1,
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&raw mut pfd, 1, 50) } > 0 {
            let _ = unsafe { libc::read(peer1, reply_buf.as_mut_ptr().cast(), reply_buf.len()) };
            break;
        }
    }

    // Drive 3 HTTP proxy requests through `mixed_port`:
    //   (a) `www.google.com` -> `HK-Node-01` (PROXY, succeeds)
    //   (b) `api.bilibili.com` -> `DIRECT` (DIRECT, succeeds)
    //   (c) `fail.broken.example` -> `Dead-VLESS-Node` (fails TCP connect)
    bg_rt.block_on(async {
        // (a) Proxy hit via HK-Node-01
        let mut c1 = tokio::net::TcpStream::connect(("127.0.0.1", mixed_port))
            .await
            .unwrap();
        c1.write_all(b"GET http://www.google.com/generate_204 HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut r1 = Vec::new();
        let _ = c1.read_to_end(&mut r1).await;
        assert!(String::from_utf8_lossy(&r1).contains("200 OK"));

        // (b) Direct hit via DIRECT
        let mut c2 = tokio::net::TcpStream::connect(("127.0.0.1", mixed_port))
            .await
            .unwrap();
        let req2 = format!(
            "GET http://api.bilibili.com:{}/feed HTTP/1.1\r\nHost: api.bilibili.com:{}\r\nConnection: close\r\n\r\n",
            http_origin_addr.port(),
            http_origin_addr.port()
        );
        c2.write_all(req2.as_bytes()).await.unwrap();
        let mut r2 = Vec::new();
        let _ = c2.read_to_end(&mut r2).await;
        assert!(String::from_utf8_lossy(&r2).contains("200 OK"));

        // (c) Failed outbound hit via Dead-VLESS-Node
        let mut c3 = tokio::net::TcpStream::connect(("127.0.0.1", mixed_port))
            .await
            .unwrap();
        let _ = c3
            .write_all(b"GET http://fail.broken.example/test HTTP/1.1\r\nHost: fail.broken.example\r\nConnection: close\r\n\r\n")
            .await;
        let mut r3 = Vec::new();
        let _ = c3.read_to_end(&mut r3).await;
    });

    // Give async connection close telemetry a brief moment to settle
    std::thread::sleep(Duration::from_millis(60));

    let live_snap = android_collect_debug_snapshot_core(&state_dir, since_ms)
        .expect("collect live debug snapshot");
    let live_str = live_snap.to_string();

    assert_eq!(live_snap["ok"], true);
    assert_eq!(live_snap["vpnRunning"], true);
    assert_eq!(live_snap["debugMode"], true);
    assert!(live_snap["tun"]["rxPackets"].as_u64().unwrap_or(0) >= 1);
    assert!(live_snap["tun"]["rxBytes"].as_u64().unwrap_or(0) > 0);
    assert!(
        live_snap["tun"]["protectedTcpSockets"]
            .as_u64()
            .unwrap_or(0)
            >= 2
    );
    assert_eq!(
        live_snap["tun"]["protectFailures"].as_u64().unwrap_or(99),
        0
    );
    assert!(live_snap["dns"]["total_queries"].as_u64().unwrap_or(0) >= 1);
    assert!(live_snap["dns"]["fake_ip_hits"].as_u64().unwrap_or(0) >= 1);
    assert!(
        live_snap["traffic"]["establishedConnections"]
            .as_u64()
            .unwrap_or(0)
            >= 2
    );
    assert!(
        live_snap["traffic"]["failedConnections"]
            .as_u64()
            .unwrap_or(0)
            >= 1
    );

    // Visited domains, matched rules, and node names MUST be preserved for mobile optimization analysis
    assert!(
        live_str.contains("www.google.com"),
        "visited domain www.google.com must be preserved"
    );
    assert!(
        live_str.contains("api.bilibili.com"),
        "visited domain api.bilibili.com must be preserved"
    );
    assert!(
        live_str.contains("fail.broken.example"),
        "failed domain fail.broken.example must be preserved"
    );
    assert!(
        live_str.contains("HK-Node-01"),
        "node name HK-Node-01 must be preserved"
    );
    assert!(
        live_str.contains("Dead-VLESS-Node"),
        "failed node name Dead-VLESS-Node must be preserved"
    );

    let hk_stat = live_snap["outboundStats"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["outbound"] == "HK-Node-01")
        .expect("HK-Node-01 outbound stats present");
    assert!(hk_stat["handshakeSamples"].as_u64().unwrap_or(0) >= 1);
    assert!(!hk_stat["handshakeP50Ms"].is_null());
    assert!(hk_stat["downloadBytes"].as_u64().unwrap_or(0) > 0);

    let failed_arr = live_snap["failedConnections"].as_array().unwrap();
    assert!(
        failed_arr
            .iter()
            .any(|c| c["host"] == "fail.broken.example"
                && c["effectiveOutbound"] == "Dead-VLESS-Node"),
        "failedConnections must capture fail.broken.example -> Dead-VLESS-Node"
    );

    // Secrets, UUIDs, passwords, subscription tokens, and ephemeral apiSecret MUST be 100% absent
    assert!(
        !live_str.contains(sub_secret_token),
        "subscription token must be redacted"
    );
    assert!(
        !live_str.contains(socks_secret_pass),
        "proxy password must be redacted"
    );
    assert!(
        !live_str.contains(vless_secret_uuid),
        "VLESS UUID must be redacted"
    );
    assert!(
        !live_str.contains(&live_api_secret),
        "ephemeral apiSecret must never appear in debug snapshot"
    );

    android_set_debug_logging_core(false);
    assert!(!android_is_debug_logging_core());
    assert!(stop_android_vpn_core());
    assert_tun_fd_fully_closed_in_kernel(fd1, ino1, peer1);
    unsafe {
        libc::close(peer1);
    }
    let _ = stop_tx.send(true);
    bg_rt.shutdown_timeout(Duration::from_millis(200));
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[cfg(unix)]
#[test]
fn android_diagnose_site_offline_and_live_demo_e2e() {
    use std::os::fd::{FromRawFd, OwnedFd};

    use proxy_ffi::{
        android_jni::{
            android_diagnose_site_core, android_save_custom_rules_core,
            start_android_vpn_with_state_dir, stop_android_vpn_core,
        },
        fd_bridge::CallbackSocketProtector,
    };
    use uuid::Uuid;

    let _serial = SERIAL_ANDROID_FFI_LOCK.blocking_lock();
    let _ = stop_android_vpn_core();

    let state_dir =
        std::env::temp_dir().join(format!("rc-android-sitedoctor-e2e-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&state_dir).unwrap();

    // 1. Offline REJECT rule diagnosis works without starting VPN
    android_save_custom_rules_core(&state_dir, "DOMAIN-SUFFIX,blocked-ad.example,REJECT")
        .expect("save custom reject rule");
    let offline_diag =
        android_diagnose_site_core(&state_dir, "blocked-ad.example").expect("offline diagnose");
    assert_eq!(offline_diag["ok"], true);
    assert_eq!(offline_diag["vpnRunning"], false);
    assert_eq!(offline_diag["diagnosis"]["diagnosis_code"], "rule_rejected");
    assert_eq!(offline_diag["diagnosis"]["exit_type"], "REJECT");

    // 2. Start live VPN in `--demo` sandbox mode and diagnose demo HTTP origin
    let (fd1, peer1, ino1) = create_tun_like_socketpair();
    let protector = Arc::new(CallbackSocketProtector::new_unix(
        "android-site-doctor-test",
        false,
        |_fd| Ok(()),
    ));
    let started = start_android_vpn_with_state_dir(
        Some(unsafe { OwnedFd::from_raw_fd(fd1) }),
        Some(&state_dir),
        "",
        true,
        protector,
    )
    .expect("start demo android vpn");
    assert_eq!(started["ok"], true);

    // SSRF guard must still block IMDS on Android FFI
    let ssrf_err =
        android_diagnose_site_core(&state_dir, "http://169.254.169.254/latest/meta-data/")
            .expect_err("IMDS must be blocked");
    assert!(ssrf_err.contains("blocked by SSRF protection"));

    assert!(stop_android_vpn_core());
    assert_tun_fd_fully_closed_in_kernel(fd1, ino1, peer1);
    unsafe {
        libc::close(peer1);
    }
    let _ = std::fs::remove_dir_all(&state_dir);
}
