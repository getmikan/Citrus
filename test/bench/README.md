# Citrus load benchmark

A reproducible load harness for the server side of Citrus: memory and
goroutines per connection, throughput, connections per second and CPU per
gigabyte, per inbound protocol. It exists so that optimizations are measured
before and after, on the same machine.

```sh
cd test/bench
go run ./cmd/bench -scenario all -duration 20s       # about 7 to 8 minutes
go run ./cmd/bench -scenario trojan-tls,hysteria2 -duration 8s -idle 1000 -variants none
go run ./cmd/bench -scenario vless-reality-vision -pprof /tmp/prof   # + server profiles
```

Results go to `results/<date>-<host>.md` (tables) and `.json` (everything,
including the raw server figures). `BENCH_HOST` overrides the host name in the
file name, `BENCH_COMMIT` the commit (for runs where `git` is not available).

A module of its own, like `test/interop`, so that the main `go.mod` does not
change; it uses the repository through `replace ../..`. Keep its `replace`
lines for `utls`, `http` and `protobuf` in sync with the main `go.mod`.

## How it works

- **Server**: the Citrus core in a child process — the same executable started
  with `-role server`, which calls `hub.Parse` exactly as the `citrus` binary
  does — with one inbound, `rules: [MATCH,DIRECT]`, `log-level: warning`, and
  `GOMAXPROCS=4` (`-server-procs`, to look like a small node rather than the
  benchmark machine). It also serves `/stats` (goroutines, live heap, stacks,
  RSS, process CPU time, read inside the server process) and `/debug/pprof`
  on a separate loopback port.
- **Client**: Citrus outbounds (`adapter.ParseProxy`) in the driver process.
  QUIC scenarios open one proxy instance (one QUIC connection) per 64
  streams; XHTTP uses the client's default xmux (streams share h2
  connections), as real clients do.
- **Sink**: a TCP server in the driver process that every proxied connection
  reaches through DIRECT: echo, endless download, upload sink, or a 64-byte
  answer followed by a close (the sink closes first). The REALITY target is a
  local TLS 1.3 server; REALITY contacts it on every connection, as in
  production.
- The inbound listens on `::1` and the sink on `127.0.0.1`. With everything
  on one address, a client port that happens to equal the local port of one
  of the server's own DIRECT connections trips Citrus's loopback detector (a
  proxy-loop guard) and the connection is rejected; real clients never come
  from the server's own address. Without IPv6 the harness falls back to
  `127.0.0.1` and sets `DISABLE_LOOPBACK_DETECTOR` for the server.

Scenarios: `vless-reality-vision`, `vless-xhttp-stream-one`,
`vless-xhttp-packet-up` (both XHTTP over REALITY, h2), `trojan-tls`,
`hysteria2`, `ss2022` (`2022-blake3-aes-128-gcm`, multi-user) and `tuic-v5`.

## What it measures

Per scenario, against a fresh server process:

1. **Idle connections**: opens 1000, 5000, 10000 connections (`-idle`; 1000,
   5000 on Windows), each after one echo round trip so it is authenticated and
   has its upstream connection, then idles. After a GC, per connection:
   RSS, live heap, goroutine stacks and goroutines, minus a baseline taken
   after a warm-up. Then all are closed and the goroutine count is checked
   against the baseline (a leak shows up there).
2. **Throughput**: download over 1 stream and 16 streams, upload over 16
   streams. MB/s (10^6 bytes) and server CPU seconds per 10^9 bytes relayed;
   `server cores` is the average number of cores the server kept busy.
3. **Connection rate**: 64 workers (`-workers`), each a new connection, a
   3-byte request, a 64-byte answer, close. Connections per second, p50/p99
   latency, server CPU milliseconds per connection. Off by default on Windows
   (`-rate auto`; `-rate on` forces it), see the caveats.
4. **User accounting and limits** (`-variants`, default
   `vless-reality-vision,trojan-tls`): idle at the first step, download over
   16 streams and connection rate with `user-stats: false`, `user-stats: true`
   (the default) and `user-stats: true` plus a `user-limits` entry for every
   user of the inbound that never binds (100 GB/s, a million connections, 1000
   addresses, 1000 TB). The difference is the cost of the accounting and of
   the limit checks, not of throttling.

`-duration` is the timed budget of one scenario: 25% download over 1 stream,
25% download over 16, 20% upload over 16, 30% connection rate. A variant uses
it half for the download, half for the connection rate.

`-pprof DIR` saves, per scenario, CPU profiles of the server during the
16-stream download (`*-cpu-d16.pb.gz`), the 16-stream upload and the
connection rate (`*-cpu-rate.pb.gz`), the cumulative allocations after the
connection rate (`*-allocs-rate.pb.gz`), and a heap profile and a goroutine
dump at the largest idle step. Profiling costs a few percent of CPU, so keep
the baseline numbers from a run without `-pprof`.

```sh
go tool pprof -top -nodecount=30 DIR/trojan-tls-stats-on-cpu-d16.pb.gz
go tool pprof -top -sample_index=alloc_space DIR/trojan-tls-stats-on-allocs-rate.pb.gz
```

## Caveats

- **Loopback.** No real network: no latency, no loss, MTU 64 KiB, and the
  client, the sink and the server share the machine's CPUs. Absolute numbers
  are an upper bound; compare runs on the same machine, not across machines.
  CPU per GB and memory per connection carry over better than MB/s.
- **Windows vs Linux.** Production is Linux; prefer Linux numbers (natively or
  in Docker, see below). On Windows: 16384 ephemeral ports and a 120-second
  TIME_WAIT, so a connection-rate phase runs out of ports within seconds
  (`Only one usage of each socket address`) and leaves the next scenarios
  without ports for two minutes; that is why it is off there by default.
  Idle steps above about 6000 run out too (each idle connection takes two
  ports, plus the REALITY target connections). QUIC has no GSO/GRO there and
  is far slower; the working set is not the same thing as RSS. Anything else
  on the machine that opens many loopback connections (tests, a local proxy)
  makes it worse.
- **QUIC and XHTTP multiplex.** For `hysteria2` and `tuic-v5` a "connection"
  is a stream (64 per QUIC connection); for XHTTP a stream of an h2
  connection. The per-connection memory is per stream, plus a share of the
  shared connection.
- **Noise.** Run twice; differences under about 5% (throughput) or 10%
  (connection rate) are noise. The first idle step is the least precise
  (the baseline is a larger share of it).
- `log-level: warning`: the per-connection `info` lines of a production node
  are not included.

### Linux in Docker

```sh
docker run --rm -v "$PWD:/src" -w /src/test/bench golang:1.26 \
  sh -c 'go build -o /tmp/bench ./cmd/bench && BENCH_HOST=docker-linux /tmp/bench -scenario all -duration 20s'
```

The container's loopback is its own, so it is not disturbed by the host's
other connections. `/proc/self/statm` gives RSS, `getrusage` the CPU time.

## CI

`.github/workflows/bench.yml` is manual only (`workflow_dispatch`): a shorter
run on `ubuntu-latest` (`-server-procs 2`, 8 s per scenario), results in the
job summary and as the `bench-results` artifact. Shared runners are noisy;
use it to check that the harness still runs and for rough comparisons.
