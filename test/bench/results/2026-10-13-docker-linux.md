# Citrus load benchmark: 2026-10-13, docker-linux

- Host: linux/amd64, 28 CPUs, go1.26.9
- Citrus: dev (commit 41273e18)
- Server GOMAXPROCS: 4; inbound on ::1; duration budget per scenario: 20s; idle steps: [1000 5000 10000]; connection-rate workers: 64
- Command: `bench -scenario all -duration 20s -out results`; total 418 s
- Everything on loopback: server = Citrus inbound -> DIRECT -> local sink; client = Citrus outbound in the driver process. Memory, goroutines and CPU are the server process only. KB = 1024 bytes, MB/s = 10^6 bytes/s.

## Idle connections (per connection, after GC, minus the baseline)

| Scenario | Variant | Conns | RSS KB/conn | Heap KB/conn | Stack KB/conn | Goroutines/conn | Server RSS MB | Open s | Errors | Goroutines left after close |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| vless-reality-vision | stats-on | 1000 | 69.8 | 48.3 | 20.5 | 2.00 | 102.7 | 0.5 | 0 | 18 (base 21) |
| vless-reality-vision | stats-on | 5000 | 78.1 | 48.1 | 20.4 | 2.00 | 415.8 | 0.9 | 0 | 18 (base 21) |
| vless-reality-vision | stats-on | 10000 | 74.5 | 47.9 | 20.3 | 2.00 | 762.3 | 1.0 | 0 | 18 (base 21) |
| vless-xhttp-stream-one | stats-on | 1000 | 57.5 | 52.5 | 24.3 | 3.01 | 90.9 | 0.2 | 0 | 18 (base 27) |
| vless-xhttp-stream-one | stats-on | 5000 | 60.8 | 52.5 | 24.1 | 3.01 | 331.7 | 0.4 | 0 | 18 (base 27) |
| vless-xhttp-stream-one | stats-on | 10000 | 56.4 | 52.5 | 24.1 | 3.01 | 585.6 | 0.5 | 0 | 18 (base 27) |
| vless-xhttp-packet-up | stats-on | 1000 | 62.7 | 54.5 | 24.2 | 3.01 | 96.4 | 0.1 | 0 | 18 (base 27) |
| vless-xhttp-packet-up | stats-on | 5000 | 66.6 | 54.5 | 24.1 | 3.01 | 360.4 | 0.4 | 0 | 18 (base 27) |
| vless-xhttp-packet-up | stats-on | 10000 | 61.4 | 54.5 | 24.1 | 3.01 | 634.5 | 0.4 | 0 | 18 (base 27) |
| trojan-tls | stats-on | 1000 | 53.6 | 46.8 | 19.6 | 2.00 | 85.1 | 0.3 | 0 | 17 (base 17) |
| trojan-tls | stats-on | 5000 | 60.3 | 46.7 | 19.9 | 2.00 | 327.0 | 0.4 | 0 | 17 (base 17) |
| trojan-tls | stats-on | 10000 | 58.7 | 46.7 | 20.0 | 2.00 | 606.2 | 0.6 | 0 | 17 (base 17) |
| hysteria2 | stats-on | 1000 | 33.6 | 43.0 | 20.0 | 2.08 | 68.2 | 0.2 | 0 | 21 (base 26) |
| hysteria2 | stats-on | 5000 | 32.1 | 43.0 | 20.2 | 2.08 | 192.2 | 0.3 | 0 | 21 (base 26) |
| hysteria2 | stats-on | 10000 | 32.5 | 43.0 | 20.3 | 2.08 | 353.2 | 0.2 | 0 | 21 (base 26) |
| ss2022 | stats-on | 1000 | 59.3 | 186.8 | 20.0 | 2.00 | 91.7 | 0.2 | 0 | 18 (base 18) |
| ss2022 | stats-on | 5000 | 57.2 | 186.8 | 20.0 | 2.00 | 313.3 | 0.3 | 0 | 18 (base 18) |
| ss2022 | stats-on | 10000 | 59.8 | 186.7 | 20.0 | 2.00 | 617.4 | 0.3 | 0 | 18 (base 18) |
| tuic-v5 | stats-on | 1000 | 28.4 | 43.0 | 12.4 | 2.09 | 62.0 | 0.1 | 0 | 963 (base 27) |
| tuic-v5 | stats-on | 5000 | 27.7 | 43.0 | 12.3 | 2.09 | 169.4 | 0.2 | 0 | 963 (base 27) |
| tuic-v5 | stats-on | 10000 | 27.8 | 42.9 | 12.3 | 2.09 | 306.2 | 0.2 | 0 | 963 (base 27) |
| vless-reality-vision | stats-off | 1000 | 72.3 | 48.3 | 20.5 | 2.00 | 104.7 | 0.2 | 0 | 18 (base 21) |
| vless-reality-vision | stats-on | 1000 | 73.0 | 48.3 | 20.6 | 2.00 | 105.7 | 0.3 | 0 | 18 (base 21) |
| vless-reality-vision | stats-on+limit | 1000 | 90.5 | 80.1 | 22.2 | 2.00 | 122.5 | 0.3 | 0 | 18 (base 21) |
| trojan-tls | stats-off | 1000 | 59.3 | 46.8 | 19.8 | 2.00 | 91.4 | 0.2 | 0 | 17 (base 17) |
| trojan-tls | stats-on | 1000 | 57.8 | 46.8 | 19.9 | 2.00 | 90.3 | 0.2 | 0 | 17 (base 17) |
| trojan-tls | stats-on+limit | 1000 | 63.6 | 78.6 | 19.6 | 2.00 | 95.4 | 0.3 | 0 | 17 (base 17) |

## Throughput (server CPU per 10^9 bytes relayed)

| Scenario | Variant | Phase | MB/s | Gbit/s | Server CPU s/GB | Server cores | Server RSS MB | Errors |
|---|---|---|---:|---:|---:|---:|---:|---:|
| vless-reality-vision | stats-on | down-1 | 2204 | 17.63 | 0.48 | 1.06 | 86.4 | 0 |
| vless-reality-vision | stats-on | down-16 | 7622 | 60.98 | 0.53 | 4.07 | 91.4 | 0 |
| vless-reality-vision | stats-on | up-16 | 7463 | 59.70 | 0.55 | 4.07 | 91.2 | 0 |
| vless-xhttp-stream-one | stats-on | down-1 | 588 | 4.71 | 2.34 | 1.38 | 83.1 | 0 |
| vless-xhttp-stream-one | stats-on | down-16 | 2401 | 19.21 | 1.44 | 3.46 | 89.9 | 0 |
| vless-xhttp-stream-one | stats-on | up-16 | 3244 | 25.95 | 1.06 | 3.45 | 94.3 | 0 |
| vless-xhttp-packet-up | stats-on | down-1 | 599 | 4.79 | 2.31 | 1.38 | 103.7 | 0 |
| vless-xhttp-packet-up | stats-on | down-16 | 2454 | 19.63 | 1.41 | 3.46 | 108.7 | 0 |
| vless-xhttp-packet-up | stats-on | up-16 | 520 | 4.16 | 2.17 | 1.13 | 177.4 | 0 |
| trojan-tls | stats-on | down-1 | 2167 | 17.34 | 0.49 | 1.06 | 79.7 | 0 |
| trojan-tls | stats-on | down-16 | 7627 | 61.02 | 0.53 | 4.07 | 83.9 | 0 |
| trojan-tls | stats-on | up-16 | 7751 | 62.01 | 0.52 | 4.06 | 84.6 | 0 |
| hysteria2 | stats-on | down-1 | 756 | 6.05 | 2.40 | 1.82 | 76.9 | 0 |
| hysteria2 | stats-on | down-16 | 670 | 5.36 | 2.66 | 1.78 | 78.6 | 0 |
| hysteria2 | stats-on | up-16 | 686 | 5.49 | 3.91 | 2.69 | 78.4 | 0 |
| ss2022 | stats-on | down-1 | 2692 | 21.53 | 0.40 | 1.07 | 83.8 | 0 |
| ss2022 | stats-on | down-16 | 8850 | 70.80 | 0.46 | 4.07 | 94.1 | 0 |
| ss2022 | stats-on | up-16 | 7829 | 62.64 | 0.52 | 4.07 | 92.5 | 0 |
| tuic-v5 | stats-on | down-1 | 720 | 5.76 | 2.55 | 1.83 | 128.4 | 0 |
| tuic-v5 | stats-on | down-16 | 642 | 5.14 | 2.66 | 1.71 | 129.3 | 0 |
| tuic-v5 | stats-on | up-16 | 488 | 3.91 | 4.04 | 1.97 | 129.3 | 0 |
| vless-reality-vision | stats-off | down-16 | 7377 | 59.01 | 0.55 | 4.07 | 45.4 | 0 |
| vless-reality-vision | stats-on | down-16 | 7653 | 61.23 | 0.53 | 4.06 | 45.7 | 0 |
| vless-reality-vision | stats-on+limit | down-16 | 7670 | 61.36 | 0.53 | 4.06 | 46.7 | 0 |
| trojan-tls | stats-off | down-16 | 7586 | 60.69 | 0.54 | 4.07 | 43.2 | 0 |
| trojan-tls | stats-on | down-16 | 7681 | 61.45 | 0.53 | 4.07 | 44.7 | 0 |
| trojan-tls | stats-on+limit | down-16 | 7890 | 63.12 | 0.51 | 4.06 | 44.8 | 0 |

## Connection rate (new connection, short request, sink answers and closes)

| Scenario | Variant | Conn/s | p50 ms | p99 ms | Server CPU ms/conn | Server cores | Errors |
|---|---|---:|---:|---:|---:|---:|---:|
| vless-reality-vision | stats-on | 5941 | 10.62 | 19.63 | 0.657 | 3.90 | 0 |
| vless-xhttp-stream-one | stats-on | 23565 | 2.33 | 7.67 | 0.166 | 3.90 | 0 |
| vless-xhttp-packet-up | stats-on | 16868 | 3.10 | 11.63 | 0.229 | 3.87 | 0 |
| trojan-tls | stats-on | 11836 | 5.08 | 12.19 | 0.328 | 3.89 | 0 |
| hysteria2 | stats-on | 32940 | 1.84 | 4.66 | 0.091 | 3.00 | 0 |
| ss2022 | stats-on | 20350 | 2.84 | 7.59 | 0.185 | 3.76 | 0 |
| tuic-v5 | stats-on | 27172 | 2.31 | 6.08 | 0.123 | 3.34 | 0 |
| vless-reality-vision | stats-off | 5938 | 10.63 | 20.13 | 0.642 | 3.81 | 0 |
| vless-reality-vision | stats-on | 5987 | 10.55 | 20.10 | 0.638 | 3.82 | 0 |
| vless-reality-vision | stats-on+limit | 5630 | 11.12 | 21.77 | 0.678 | 3.81 | 0 |
| trojan-tls | stats-off | 10601 | 5.69 | 12.89 | 0.356 | 3.78 | 0 |
| trojan-tls | stats-on | 10866 | 5.57 | 12.44 | 0.348 | 3.78 | 0 |
| trojan-tls | stats-on+limit | 11536 | 5.30 | 11.70 | 0.330 | 3.81 | 0 |

## Scenario notes

- vless-xhttp-stream-one: REALITY + h2, client default xmux (streams share h2 connections)
- vless-xhttp-packet-up: REALITY + h2, client default xmux (streams share h2 connections)
- hysteria2: QUIC: one connection per 64 streams; per-conn figures are per stream
- ss2022: 2022-blake3-aes-128-gcm, multi-user (EIH)
- tuic-v5: QUIC: one connection per 64 streams; per-conn figures are per stream

## Reading this run

- Docker Desktop (WSL2 VM) on a 28-thread Windows host, server held to 4 cores. Other workloads on
  the host add noise: between three identical runs the connection rate moved by up to 25% and
  CPU s/GB by up to 30%; the memory figures were stable to about 5%. The stats-off/on/limit
  differences in CPU and throughput above are within that noise; the memory difference of the
  limit is not.
- Every TCP protocol costs 2 goroutines per connection (XHTTP 3), about 20 KB of goroutine stack
  and 43-55 KB of live heap; Shadowsocks 2022 is the exception with 187 KB of live heap (most of
  it buffers never touched, so RSS stays about 58 KB).
- `user-stats` costs nothing measurable (no bytes per connection, under 2% of CPU in the
  profiles). A `user-limits` entry with a speed limit or a quota costs about 31 KB of heap per
  connection (item 1 below), not CPU.
- tuic-v5 "goroutines left after close" (963): the TUIC outbound has no `Close`, so the client
  keeps its QUIC connections and the server reaps them only at its idle timeout. Not a server
  leak; hysteria2, whose outbound closes them, drops back to the baseline.

## Top 5 optimization opportunities

From this baseline plus a second run with `-pprof` (CPU profiles of the server during the
16-stream download and the connection-rate phases, heap profile and goroutine dump at 10000
idle connections, allocation profile after the connection-rate phase). Percentages are of the
server's CPU samples in that phase; bytes are per connection. Not implemented, ordered by
expected value for a node with many mostly idle users.

1. **A pooled 32 KB read buffer is held for the whole life of every idle connection.**
   The goroutine dump at 10000 idle Trojan connections shows the client-to-upstream copy
   parked in `bufio.CopyExtendedWithPool -> ExtendedReaderWrapper.ReadBuffer -> tls.(*Conn).Read`:
   it takes a buffer from `common/pool` before it blocks. The other direction (upstream socket)
   uses `syscallReadWaiter`, which takes a buffer only when the socket is readable. Heap profile:
   `pool.NewAllocator.func10` is 62-72% of in-use heap at idle (about 31-35 KB of the 47-48 KB
   live heap per connection, Trojan and VLESS+REALITY+Vision alike). With a speed limit or a
   quota, `tcpTracker.UnwrapReader/UnwrapWriter` hand the copy loop `trackerReader/trackerWriter`,
   which lose the read waiter on the other side too: live heap goes from 46.8 to 78.6 KB (Trojan)
   and 48.3 to 80.1 KB (VLESS) per connection. Wait for readability first (a read waiter for TLS,
   REALITY and VLESS conns that fills the record buffer before asking for a pool buffer), and keep
   the read waiter under limits by charging the count function after the read. Expected: about
   -30 KB per idle connection (-300 MB at 10000), -60 KB with limits.
2. **Shadowsocks 2022 allocates 128 KB of buffers per connection up front.**
   `shadowaead_2022.(*MultiService).NewConnection` calls `shadowaead.NewReader` and `NewWriter`
   with `MaxPacketSize = 65535`, each a `make([]byte, 64 KB + overhead)`: 733 + 708 MB in use at
   10000 idle connections (78% of the heap, 187 KB live heap per connection against 43-55 KB for
   the other protocols), 77% of all bytes allocated in the connection-rate phase (6.2 + 6.2 of
   16.2 GB). At 20000 conn/s, `runtime.mallocgc` is 28% of server CPU (`memclrNoHeapPointers`
   7%, GC assist 9%), against 8-12% for the other protocols. Pool the buffers or grow them on
   demand (most records are far below 64 KB) in the sing-shadowsocks fork. Expected: about
   -140 KB of heap per connection, -20 to -25% CPU per new connection.
3. **REALITY does avoidable work on every handshake (getmikan/utls `reality.go`).**
   (a) `curve25519.X25519(config.PrivateKey, peerPub)` (line 449) goes through
   `ecdh.X25519().NewPrivateKey`, which recomputes the server's static public key with a scalar
   base multiplication every time: 1.64 s of 29.9 s, 5.5% of server CPU in the VLESS+REALITY
   connection-rate phase. Parse the key once into an `*ecdh.PrivateKey` and call `ECDH`.
   (b) `RealityServer.func2` allocates two 17 KB slices (`s2cSaved`, `buf`) per connection:
   1.9 GB of 6.0 GB allocated in that phase (32%, largest allocation site). Pool them.
   VLESS+REALITY is the most expensive handshake here (0.64-0.89 ms CPU per connection against
   0.33-0.45 ms for Trojan TLS, both with X25519MLKEM768). Expected: -6 to -8% CPU per
   connection, a third fewer allocated bytes.
4. **Bulk TCP+TLS relay makes one write(2) per 16 KB TLS record.**
   Download over 16 streams, Trojan and VLESS+Vision: 68-69% of server CPU is
   `syscall.Syscall6`; the write side (`tls.(*Conn).Write -> writeRecordLocked -> net.(*conn).Write`)
   is 47% against 27% for the read side (`syscallReadWaiter`), for the same bytes. The copy reads
   up to 32 KB and `metacubex/tls` (and utls) write each record with its own `conn.Write`
   (`c.buffering` is only set during the handshake), so about two write syscalls per read.
   Seal all records of one `WriteBuffer` into one output buffer and write once (or `writev`).
   AES-GCM itself is only 20%. Expected: -15 to -20% CPU per GB for Trojan and VLESS+TLS/REALITY (likely
   AnyTLS too; currently 0.48-0.55 s/GB).
5. **XHTTP downloads cost about 3x the CPU per GB of raw VLESS.**
   1.41-1.44 s/GB on 16 streams and 2.3 s/GB on one stream (590 MB/s) against 0.48-0.53 s/GB and
   2200 MB/s for VLESS+Vision. Profile: 57% of server CPU under
   `http2serverConn.writeFrameAsync -> http2bufferedWriter.Write -> utls.(*Conn).Write`;
   `syscall.write` is 45% against 14% for `syscall.read`, about three writes per read: each
   DATA frame (16 KB max) is flushed as its own TLS record and syscall, and the frame hand-off
   between the handler and the serve goroutine adds `selectgo`/`lock2` (about 11%). Let the
   writer coalesce queued frames before flushing, send larger DATA frames when the client's
   SETTINGS_MAX_FRAME_SIZE allows it, and write larger chunks from the handler. Builds on item 4.
   Expected: XHTTP toward 0.7-0.9 s/GB.

Not in the top 5, worth a look later: QUIC (hysteria2, tuic-v5) at 2.4-4 s/GB and 650-750 MB/s
on loopback, with GSO and `recvmmsg` already in use and the server only at 1.8 of 4 cores
(client-bound or congestion control on loopback, needs a client on another machine);
`common/net/deadline.(*Conn).pipeRead` allocating on every read before the first byte (208 MB
in the VLESS connection-rate phase); `blake3.newHasher` 1.6 GB (10%) of the Shadowsocks 2022
allocations; the two goroutines per relayed connection (20 KB of stack) could be one with read
waiters on both sides.
