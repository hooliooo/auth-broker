# Edge and hub capacity

What one request costs the edge, the hub, Redis and Keycloak, and what that means for how many
requests per second each can handle. Measured on 2026-10-16 with `crates/e2e/tests/load.rs`
against the measurement stack (`docker-compose.perf.yml`); the raw numbers of the last run are in
[`results.md`](results.md). How to run it: [`README.md`](README.md).

## The short version

| Path                                       | CPU per request                                    | Requests per second per core | Sustained here, errors 0   |
| ------------------------------------------ | -------------------------------------------------- | ---------------------------- | -------------------------- |
| Edge, direct API call, token cached        | edge 0.16–0.19 ms                                  | ≈ 5,000 per edge core        | 12,000/s on 2.3 edge cores |
| Edge, API call forwarded by the hub        | edge 0.17–0.21 ms, hub 0.25–0.28 ms, Redis 0.03 ms | ≈ 3,500 per hub core         | 8,000/s on 2.3 hub cores   |
| Hub, access token for an edge (no refresh) | hub 0.23–0.31 ms, Redis 0.04 ms                    | ≈ 3,500 per hub core         | 8,000/s on 2.5 hub cores   |
| Hub, token refresh at Keycloak             | hub ≈ 1 ms, Keycloak 9–13 ms, Redis 0.3–0.6 ms     | ≈ 90 per Keycloak core       | 200/s, p99 13 ms           |
| Sign-in                                    | hub 220 KiB heap, Keycloak most of the 62 ms       | (Keycloak-bound)             | p50 62 ms                  |

- **None of the edge and hub limits were reached.** Every collapse in the runs came from the
  load generator and Docker Desktop's port forwarding on the same machine: when the forwarded
  path failed at 6,000/s with a 4-thread generator, the edge, hub and API were nearly idle;
  with an 8-thread generator the same path ran 8,000/s cleanly and the direct path 12,000/s.
  The figures above are therefore lower bounds; CPU per request is the number that carries over.
- **Keycloak is the bottleneck,** as the auth hub RFC predicted: a refresh costs Keycloak 40–60
  times the CPU it costs the hub. (Keycloak ran in dev mode with its embedded database; with
  PostgreSQL its cost per refresh will differ and must be measured there.)
- **The hub and the edge scale out:** they keep nothing per request but Redis reads and writes,
  so instances add capacity linearly until Redis or Keycloak is the limit. One Redis core
  serves roughly 25,000–30,000 of these requests per second.

## 1. Heap allocated per request

Measured with a counting global allocator (`common::alloc`, feature `alloc-stats`), reported on
each service's metrics page; bytes per request are the difference over a whole scenario divided
by its requests.

| Path                          | Edge                             | Hub                              |
| ----------------------------- | -------------------------------- | -------------------------------- |
| Direct API call, token cached | 34–42 KiB in 115–136 allocations | none                             |
| Forwarded by the hub          | 24–41 KiB in 92–158 allocations  | 35–60 KiB in 110–189 allocations |
| Access token for an edge      |                                  | 57 KiB in 146 allocations        |
| Token refresh at Keycloak     |                                  | 152 KiB in ≈ 410 allocations     |
| Sign-in (whole flow)          |                                  | 220 KiB in ≈ 720 allocations     |

This is memory allocated and freed during the request, mostly HTTP buffers for the outgoing call
and JSON; it is churn, not memory held. At 12,000 requests a second the edge churns ≈ 450 MB/s
through the allocator at 0.19 ms CPU per request, so allocation is not what limits it. Reducing
it (reusing buffers, streaming the token response) would lower CPU per request slightly; it is
not urgent.

## 2. Thread stack

- Every process runs **11 threads**: tokio's 10 worker threads (one per CPU the container sees)
  and the main thread. Tokio's blocking pool stays empty: nothing blocks. Each thread has a 2 MiB
  stack reserved; only the pages used become resident, so the threads cost a few hundred KiB.
- Requests have **no stack of their own**: each is a future on the heap. Its size, from
  `-Zprint-type-sizes` (nightly), for the largest handlers:

  | Service | Handler | Size |
  |---|---|---|
  | edge | `proxy::api` (any `/api/*`, direct or through the hub) | 3.0 KiB |
  | edge | `auth::handoff` | 1.8 KiB |
  | edge | `auth::login` | 0.3 KiB |
  | hub | `proxy::api` | 3.7 KiB |
  | hub | `broker::token` | 3.2 KiB |
  | hub | `login::callback` | 2.0 KiB |
  | hub | `broker::redeem` | 1.8 KiB |

  So an in-flight request holds roughly its future (≤ 4 KiB) plus the buffers of its connection.
- To size threads: CPU, not threads, is the limit. Give each instance the cores its traffic
  needs; tokio uses one worker per core it sees, so set a CPU limit and the workers follow.

## 3. Connection overhead

2,000 keep-alive connections opened to each service, one request each, then held idle:

|      | Heap live per idle connection | Resident per idle connection | File descriptors |
| ---- | ----------------------------- | ---------------------------- | ---------------- |
| Edge | 27.4 KiB                      | 1.4–1.7 KiB                  | 1                |
| Hub  | 27.4 KiB                      | 11.7–12.4 KiB                | 1                |

- The heap figure is hyper's per-connection buffers and state: allocated, but mostly untouched
  pages, which is why resident memory grows much less. Plan with the heap figure as the worst
  case: 10,000 idle browser connections cost an edge ≤ 270 MiB.
- Outgoing connections are pooled and were reused throughout: edge → API, edge → hub,
  hub → Redis, hub → Keycloak. A load generator that opened a new connection per request (the
  first version of this test) made the hub fail at 2,000/s; the same hub with pooled connections
  served 8,000/s. Keep edges' and the hub's pools warm, and terminate browser TLS at the load
  balancer, where connection setup is cheapest.

## 4. Session and context data

|                                                                            | Size                                                |
| -------------------------------------------------------------------------- | --------------------------------------------------- |
| One session in Redis (`MEMORY USAGE`, sealed value plus key and overhead)  | 4.1 KiB                                             |
| of which the sealed value: ID, access and refresh tokens and session facts | 3.8 KiB                                             |
| Back-channel logout index entry                                            | ≈ 130 B                                             |
| Redis `used_memory` growth per session                                     | 4.1–5.6 KiB                                         |
| Hub process memory per session                                             | ≈ 0.6 KiB (allocator noise: sessions live in Redis) |
| Edge token cache entry, per active session and site                        | 0.6–2.1 KiB, for at most 60 s                       |
| Pending sign-in and handoff (Redis, ≤ 5 min and ≤ 60 s)                    | well under one session each                         |

So 1 million active sessions need ≈ 4–6 GiB of Redis, and an edge caching tokens for 100,000
active sessions needs ≈ 60–200 MiB.

## What this means in production

Requests in flight = requests per second × latency (Little's law). At 12,000/s and ≈ 2 ms each,
an edge holds ≈ 24 requests at a time: memory per request is negligible; **connections and CPU
decide**.

Load each part sees, for `S` active sessions with 2-minute access tokens:

| Part              | Load                                           | Capacity per core (measured) | Cores for S = 100,000 |
| ----------------- | ---------------------------------------------- | ---------------------------- | --------------------- |
| Edge              | every API call                                 | ≈ 5,000/s                    | API calls/s ÷ 5,000   |
| Hub, token fetch  | ≈ S ÷ 60 per second (edge cache of ≤ 60 s)     | ≈ 3,500/s                    | ≈ 0.5                 |
| Hub, refresh      | ≈ S ÷ 60 per second (refresh when < 60 s left) | ≈ 1,000/s                    | ≈ 1.7                 |
| Keycloak, refresh | ≈ S ÷ 60 per second                            | ≈ 90/s (dev database)        | ≈ 18                  |
| Redis             | one or two operations per hub request          | ≈ 25,000–30,000/s per core   | < 0.2                 |

Longer access tokens cut the hub's and Keycloak's refresh load proportionally (5 minutes: ≈ 2.5
times less), at the cost of revocation taking longer, as the auth hub RFC's performance section
weighs.

## Finding: the edge needs a limit on requests in flight

After the overloaded step (16,000/s), the inspection edge's heap peaked at **641 MiB** and its
resident memory stayed at 378 MiB afterwards. The hub has a per-kind limit on calls in flight
(`max_concurrency`, answering 503 when full); the edge's direct API calls have none, so under
overload requests queue without bound and memory grows with them. Recommended: a limit on
in-flight requests per edge instance (or per site), answering 503 when full, so an overloaded
edge sheds load instead of growing; plus a total timeout on its API calls matching the hub's.

**Since implemented, not yet re-measured:** the edge now gives each site its own slots for direct
API calls, sized by the kind's `max_concurrency` (default 256) per edge instance, and answers
503 after a 2-second wait when they are full, as the hub does for forwarded kinds
(`crates/edge/src/direct.rs`). A total timeout was not added: like the hub's API calls, the
edge's stream long responses and are bounded by the read timeout instead.

## Caveats

- Everything ran on one laptop (Docker with 10 CPUs) with the load generator alongside; the
  generator and Docker Desktop's port forwarding gave out before the services did.
- The counting allocator adds a few atomic operations per allocation; production builds
  without it use slightly less CPU than measured.
- Keycloak ran with `start-dev` and its embedded database, so its cost per refresh is indicative
  only; measure it again with the production database.
- The stand-in APIs answer instantly; a real API's own time adds to latency but not to the edge's
  CPU.
