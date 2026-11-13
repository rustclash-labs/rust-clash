#[cfg(unix)]
use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

pub use proxy_core::platform::socket_protect::CallbackSocketProtector;

/// Event-driven, non-blocking Unix L3 packet file-descriptor bridge connecting an Android
/// `VpnService` `ParcelFileDescriptor` (or Unix `SOCK_DGRAM` socketpair in tests) to `VirtualTunHandle`.
///
/// Ownership & RAII guarantees:
/// - Accepts an `OwnedFd` (or wraps `RawFd` into `OwnedFd` on line 1 of `attach_raw_fd`) so the
///   underlying kernel file descriptor is ALWAYS closed across every error return, thread spawn
///   failure, duplicate start, `onRevoke()`, or `Drop`.
/// - Uses a dedicated wakeup pipe (`poll([rx_fd, wake_rd], 2, -1)`) instead of periodic timer
///   polling (`0 Hz` idle wakeups while screen is off, `< 1 ms` deterministic wakeup on `stop()`).
#[cfg(unix)]
pub struct UnixPacketFdBridge {
    stop_flag: Arc<AtomicBool>,
    stop_watch_tx: tokio::sync::watch::Sender<bool>,
    wake_wr_fd: Option<OwnedFd>,
    stopped: bool,
    rx_packets: Arc<AtomicU64>,
    tx_packets: Arc<AtomicU64>,
    rx_bytes: Arc<AtomicU64>,
    tx_bytes: Arc<AtomicU64>,
    tx_write_drops: Arc<AtomicU64>,
    rx_thread: Option<std::thread::JoinHandle<()>>,
    tx_thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(unix)]
fn set_nonblocking(fd: RawFd) {
    // SAFETY: Standard POSIX `fcntl` flags update on a valid open descriptor.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 {
            let _ = libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
}

#[cfg(unix)]
fn create_wakeup_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1i32; 2];
    // SAFETY: `libc::pipe` initializes `fds[0]` (read) and `fds[1]` (write) on success.
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Both descriptors were just created by `pipe` and are exclusively owned here.
    let rd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let wr = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    set_nonblocking(rd.as_raw_fd());
    set_nonblocking(wr.as_raw_fd());
    unsafe {
        let _ = libc::fcntl(rd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);
        let _ = libc::fcntl(wr.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);
    }
    Ok((rd, wr))
}

#[cfg(unix)]
impl UnixPacketFdBridge {
    /// Take immediate RAII ownership of `raw_fd` (such as `ParcelFileDescriptor.detachFd()` on Android)
    /// and launch bounded event-driven RX/TX packet pumps attached to `handle`.
    ///
    /// Note: If `raw_fd >= 0`, it is wrapped in `OwnedFd` on entry so even if `dup`, `pipe`, or thread
    /// spawning fails, `raw_fd` is guaranteed to be closed before this function returns `Err`.
    pub fn attach_raw_fd(
        raw_fd: RawFd,
        handle: proxy_core::inbound::tun::VirtualTunHandle,
    ) -> io::Result<Self> {
        if raw_fd < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid negative packet fd {raw_fd}"),
            ));
        }
        // SAFETY: Caller transfers exclusive ownership of `raw_fd` (e.g. `detachFd()`).
        let owned = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        Self::attach_owned_fd(owned, handle)
    }

    /// Take an already-wrapped `OwnedFd` and launch bounded event-driven RX/TX packet pumps.
    pub fn attach_owned_fd(
        rx_fd: OwnedFd,
        handle: proxy_core::inbound::tun::VirtualTunHandle,
    ) -> io::Result<Self> {
        // SAFETY: `dup` creates an independent descriptor for concurrent TX writes; `rx_fd` stays RAII-owned.
        let tx_dup = unsafe { libc::dup(rx_fd.as_raw_fd()) };
        if tx_dup < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `tx_dup >= 0` is newly allocated and owned exclusively by `tx_fd`.
        let tx_fd = unsafe { OwnedFd::from_raw_fd(tx_dup) };
        let (wake_rd_fd, wake_wr_fd) = create_wakeup_pipe()?;

        set_nonblocking(rx_fd.as_raw_fd());

        let stop_flag = Arc::new(AtomicBool::new(false));
        let (stop_watch_tx, mut stop_watch_rx) = tokio::sync::watch::channel(false);
        let rx_packets = Arc::new(AtomicU64::new(0));
        let tx_packets = Arc::new(AtomicU64::new(0));
        let rx_bytes = Arc::new(AtomicU64::new(0));
        let tx_bytes = Arc::new(AtomicU64::new(0));
        let tx_write_drops = Arc::new(AtomicU64::new(0));

        let proxy_core::inbound::tun::VirtualTunHandle {
            ingress_tx,
            mut egress_rx,
        } = handle;

        let stop_rx = Arc::clone(&stop_flag);
        let rx_cnt = Arc::clone(&rx_packets);
        let rx_byte_cnt = Arc::clone(&rx_bytes);
        let rx_thread = std::thread::Builder::new()
            .name("tun-ffi-rx".into())
            .spawn(move || {
                let mut buf = vec![0u8; 65536];
                while !stop_rx.load(Ordering::Acquire) {
                    let mut pfds = [
                        libc::pollfd {
                            fd: rx_fd.as_raw_fd(),
                            events: libc::POLLIN,
                            revents: 0,
                        },
                        libc::pollfd {
                            fd: wake_rd_fd.as_raw_fd(),
                            events: libc::POLLIN,
                            revents: 0,
                        },
                    ];
                    // SAFETY: `pfds` borrows `rx_fd` and `wake_rd_fd` owned by this thread (`-1` = 0 Hz idle).
                    let prc = unsafe { libc::poll(pfds.as_mut_ptr(), 2, -1) };
                    if prc < 0 {
                        let err = io::Error::last_os_error();
                        if err.kind() == io::ErrorKind::Interrupted {
                            continue;
                        }
                        return;
                    }
                    if (pfds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)) != 0 {
                        return;
                    }
                    if (pfds[0].revents & (libc::POLLERR | libc::POLLNVAL)) != 0 {
                        return;
                    }
                    if (pfds[0].revents & (libc::POLLIN | libc::POLLHUP)) == 0 {
                        continue;
                    }
                    loop {
                        // SAFETY: `read` writes at most `buf.len()` bytes into `buf`.
                        let n = unsafe {
                            libc::read(
                                rx_fd.as_raw_fd(),
                                buf.as_mut_ptr().cast::<libc::c_void>(),
                                buf.len(),
                            )
                        };
                        if n < 0 {
                            let err = io::Error::last_os_error();
                            if err.kind() == io::ErrorKind::WouldBlock
                                || err.kind() == io::ErrorKind::Interrupted
                            {
                                break;
                            }
                            return;
                        }
                        if n == 0 {
                            return;
                        }
                        let len = n as usize;
                        let first = buf[0] >> 4;
                        if first == 4 || first == 6 {
                            rx_cnt.fetch_add(1, Ordering::Release);
                            rx_byte_cnt.fetch_add(len as u64, Ordering::Relaxed);
                            if ingress_tx.blocking_send(buf[..len].to_vec()).is_err() {
                                return;
                            }
                        }
                    }
                }
            })?;

        let stop_tx = Arc::clone(&stop_flag);
        let tx_cnt = Arc::clone(&tx_packets);
        let tx_byte_cnt = Arc::clone(&tx_bytes);
        let tx_drop_cnt = Arc::clone(&tx_write_drops);
        let tx_spawn_res = std::thread::Builder::new()
            .name("tun-ffi-tx".into())
            .spawn(move || {
                let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    return;
                };
                rt.block_on(async move {
                    loop {
                        tokio::select! {
                            biased;
                            _ = stop_watch_rx.wait_for(|&stopped| stopped) => break,
                            maybe_pkt = egress_rx.recv() => {
                                let Some(pkt) = maybe_pkt else { break };
                                if pkt.is_empty() {
                                    continue;
                                }
                                if write_packet_pollout_safe(tx_fd.as_raw_fd(), &pkt, &stop_tx) {
                                    tx_cnt.fetch_add(1, Ordering::Release);
                                    tx_byte_cnt.fetch_add(pkt.len() as u64, Ordering::Relaxed);
                                } else if stop_tx.load(Ordering::Acquire) {
                                    break;
                                } else {
                                    tx_drop_cnt.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                });
            });
        let tx_thread = match tx_spawn_res {
            Ok(h) => h,
            Err(spawn_err) => {
                // Cleanly stop & join `rx_thread` so `rx_fd` is closed synchronously before returning!
                stop_flag.store(true, Ordering::Release);
                let wake_byte = [1u8; 1];
                unsafe {
                    let _ = libc::write(
                        wake_wr_fd.as_raw_fd(),
                        wake_byte.as_ptr().cast::<libc::c_void>(),
                        1,
                    );
                }
                drop(wake_wr_fd);
                let _ = rx_thread.join();
                return Err(spawn_err);
            }
        };

        Ok(Self {
            stop_flag,
            stop_watch_tx,
            wake_wr_fd: Some(wake_wr_fd),
            stopped: false,
            rx_packets,
            tx_packets,
            rx_bytes,
            tx_bytes,
            tx_write_drops,
            rx_thread: Some(rx_thread),
            tx_thread: Some(tx_thread),
        })
    }

    pub fn rx_packets(&self) -> u64 {
        self.rx_packets.load(Ordering::Acquire)
    }

    pub fn tx_packets(&self) -> u64 {
        self.tx_packets.load(Ordering::Acquire)
    }

    pub fn rx_bytes(&self) -> u64 {
        self.rx_bytes.load(Ordering::Acquire)
    }

    pub fn tx_bytes(&self) -> u64 {
        self.tx_bytes.load(Ordering::Acquire)
    }

    pub fn tx_write_drops(&self) -> u64 {
        self.tx_write_drops.load(Ordering::Acquire)
    }

    pub fn stop(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        self.stop_flag.store(true, Ordering::Release);
        let _ = self.stop_watch_tx.send(true);
        if let Some(wake_wr) = self.wake_wr_fd.take() {
            let wake_byte = [1u8; 1];
            // SAFETY: Writing 1 byte (and then dropping `wake_wr` -> POLLHUP) wakes `poll(-1)` immediately.
            unsafe {
                let _ = libc::write(
                    wake_wr.as_raw_fd(),
                    wake_byte.as_ptr().cast::<libc::c_void>(),
                    1,
                );
            }
            drop(wake_wr);
        }
        if let Some(h) = self.rx_thread.take() {
            let _ = h.join();
        }
        if let Some(h) = self.tx_thread.take() {
            let _ = h.join();
        }
    }
}

#[cfg(unix)]
fn write_packet_pollout_safe(fd: RawFd, pkt: &[u8], stop_flag: &AtomicBool) -> bool {
    let mut enobufs_retries: u32 = 0;
    loop {
        if stop_flag.load(Ordering::Acquire) {
            return false;
        }
        // SAFETY: `write` reads at most `pkt.len()` bytes from `pkt` on valid `fd`.
        let written = unsafe { libc::write(fd, pkt.as_ptr().cast::<libc::c_void>(), pkt.len()) };
        if written > 0 {
            return true;
        }
        if written == 0 {
            return false;
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if err.kind() == io::ErrorKind::WouldBlock {
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            // Poll in 50ms slices so `stop()` can interrupt stalled kernel queues deterministically.
            // SAFETY: `pfd` borrows valid `fd` for the duration of `poll`.
            let prc = unsafe { libc::poll(&raw mut pfd, 1, 50) };
            if prc < 0 {
                let perr = io::Error::last_os_error();
                if perr.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return false;
            }
            if (pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)) != 0 {
                return false;
            }
            continue;
        }
        // On Darwin/XNU (`AF_UNIX` `SOCK_DGRAM` and `utun`), full kernel receive queues return `ENOBUFS`
        // while `poll(POLLOUT)` still reports writable immediately; back off briefly until space drains.
        if err.raw_os_error() == Some(libc::ENOBUFS) && enobufs_retries < 4_000 {
            enobufs_retries += 1;
            std::thread::sleep(std::time::Duration::from_micros(250));
            continue;
        }
        return false;
    }
}

#[cfg(unix)]
impl Drop for UnixPacketFdBridge {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn shared_nonblocking_fd_burst_does_not_drop_egress_packets_on_eagain() {
        let mut fds = [-1i32; 2];
        let mut rc =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, fds.as_mut_ptr()) };
        if rc != 0 {
            rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        }
        assert_eq!(rc, 0);

        // Shrink send buffer aggressively so burst writes hit `EAGAIN` on the shared O_NONBLOCK open file description!
        let small_sndbuf: libc::c_int = 4096;
        unsafe {
            let _ = libc::setsockopt(
                fds[0],
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&raw const small_sndbuf).cast::<libc::c_void>(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        let (ingress_tx, _ingress_rx) = tokio::sync::mpsc::channel(64);
        let (egress_tx, egress_rx) = tokio::sync::mpsc::channel(512);
        let vtun = proxy_core::inbound::tun::VirtualTunHandle {
            ingress_tx,
            egress_rx,
        };

        let mut bridge = UnixPacketFdBridge::attach_raw_fd(fds[0], vtun).expect("attach bridge");
        let peer_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };

        let total_packets = 128usize;
        let payload = vec![0x45u8; 1200];
        let producer = std::thread::spawn(move || {
            for _ in 0..total_packets {
                egress_tx.blocking_send(payload.clone()).unwrap();
            }
            egress_tx
        });

        // Delay reading briefly so the kernel send buffer fills and triggers `EAGAIN` + `POLLOUT` wait
        std::thread::sleep(std::time::Duration::from_millis(25));

        let mut received = 0usize;
        let mut rbuf = vec![0u8; 2048];
        while received < total_packets {
            let mut pfd = libc::pollfd {
                fd: peer_fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let prc = unsafe { libc::poll(&raw mut pfd, 1, 2000) };
            assert!(prc > 0, "timed out waiting for packet #{received}");
            let n = unsafe {
                libc::read(
                    peer_fd.as_raw_fd(),
                    rbuf.as_mut_ptr().cast::<libc::c_void>(),
                    rbuf.len(),
                )
            };
            assert_eq!(n, 1200);
            received += 1;
        }

        let tx_keepalive = producer.join().unwrap();
        bridge.stop();
        drop(tx_keepalive);
        assert_eq!(bridge.tx_packets(), total_packets as u64);
    }
}
