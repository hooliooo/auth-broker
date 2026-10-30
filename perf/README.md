# Measuring the edge and the hub

- [`REPORT.md`](REPORT.md): what the measurements show, and what they mean for capacity.
- [`results.md`](results.md): the raw numbers of the last run, written by the load test.

## Running it

The measurements run against the docker compose stack, not the local cluster: they read each
container's CPU from Docker. The two share host ports, so take the cluster down first
(`dev/k8s/down.sh`). The compose stack reads its own registry, `dev/registry-compose`, which the
key script writes alongside the cluster's.

```sh
dev/generate-dev-keys.sh                       # once
docker compose -f docker-compose.yml -f docker-compose.perf.yml up -d --build
cargo test --release -p e2e --features load --test load -- --nocapture --test-threads=1
docker compose -f docker-compose.yml -f docker-compose.perf.yml down
```

The run takes about five minutes and writes `perf/results.md`. Run it on an otherwise idle
machine; the load generator shares it with the stack.

## What measures what

| Question                   | How                                                                                                                                                                                                      |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Heap allocated per request | `alloc-stats` feature (`common::alloc`): a counting global allocator; `<service>_heap_*` on each metrics page; differences over a scenario ÷ its requests                                                |
| Threads and stacks         | `<service>_process_threads` from `/proc`; future sizes per handler with `cargo +nightly rustc --release -p edge --bin edge -- -Zprint-type-sizes` (and `-p hub --bin hub`), filtered for `async fn body` |
| Connection overhead        | the test opens 2,000 idle keep-alive connections and compares `heap_live_bytes`, `process_resident_bytes` and `process_open_fds`                                                                         |
| Session and context data   | Redis `MEMORY USAGE` per session key, `INFO memory`, and the hub's and edge's live heap before and after                                                                                                 |
| Requests per second        | open-loop load at fixed arrival rates (latency counted from the scheduled send time); CPU per container from the Docker API's cumulative counters, before and after each step                            |

The measurement stack differs from the normal one only in the `alloc-stats` build, `RUST_LOG=info`,
and the edges' metrics ports (8092 inspection, 8093 billing, 8094 maintenance; the hub's is 8091).
Never deploy the `alloc-stats` build: every allocation pays for the counting.
