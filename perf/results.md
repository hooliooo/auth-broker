# Edge and hub capacity: measurements

Measured on 2026-10-16 20:02 against the measurement stack (`docker-compose.perf.yml`), with the load generator on the same machine. Docker has 10 CPUs. Rates are a lower bound; CPU time and heap per request carry over.

## Sessions

|                                                                         | Value                        |
| ----------------------------------------------------------------------- | ---------------------------- |
| sign-in, browser → edge → hub → Keycloak → hub → edge (p50 / p90 / max) | 62 / 69 / 94 ms              |
| Redis key per session, `MEMORY USAGE` (p50 / max)                       | 4.1 KiB / 4.1 KiB            |
| of which the sealed value (p50)                                         | 3.8 KiB                      |
| back-channel logout index, per session                                  | 381 B                        |
| Redis `used_memory` growth per session                                  | 4.1 KiB                      |
| hub heap still live per session after sign-in                           | 572 B                        |
| hub heap allocated per sign-in                                          | 220.6 KiB in 718 allocations |
| inspection edge heap live per cached token                              | 582 B                        |

## Edge, direct API call (token cached)

`browser → inspection edge → inspection API`

| rate /s | done /s | errors | p50 ms  | p99 ms   | max ms  | edge-inspection CPU      | api-inspection CPU       | hub CPU                  | redis CPU                |
| ------- | ------- | ------ | ------- | -------- | ------- | ------------------------ | ------------------------ | ------------------------ | ------------------------ |
| 500     | 500     | 0      | 1.75    | 6.97     | 17.5    | 0.15 cores, 0.293 ms/req | 0.12 cores, 0.248 ms/req | 0.00 cores, 0.000 ms/req | 0.01 cores, 0.012 ms/req |
| 1000    | 1000    | 0      | 1.54    | 10.06    | 18.9    | 0.23 cores, 0.233 ms/req | 0.18 cores, 0.182 ms/req | 0.00 cores, 0.000 ms/req | 0.01 cores, 0.005 ms/req |
| 2000    | 1999    | 0      | 1.81    | 6.18     | 14.4    | 0.33 cores, 0.166 ms/req | 0.28 cores, 0.139 ms/req | 0.00 cores, 0.000 ms/req | 0.00 cores, 0.002 ms/req |
| 4000    | 3997    | 0      | 1.86    | 11.17    | 56.9    | 0.70 cores, 0.175 ms/req | 0.55 cores, 0.138 ms/req | 0.01 cores, 0.003 ms/req | 0.01 cores, 0.002 ms/req |
| 8000    | 7991    | 0      | 1.84    | 190.46   | 1027.6  | 1.46 cores, 0.183 ms/req | 1.09 cores, 0.137 ms/req | 0.00 cores, 0.000 ms/req | 0.01 cores, 0.001 ms/req |
| 12000   | 11983   | 0      | 2.08    | 12.72    | 71.8    | 2.33 cores, 0.194 ms/req | 1.61 cores, 0.134 ms/req | 0.00 cores, 0.000 ms/req | 0.01 cores, 0.000 ms/req |
| 16000   | 3491    | 75457  | 6926.34 | 33046.53 | 33685.5 | 0.66 cores, 0.188 ms/req | 0.36 cores, 0.104 ms/req | 0.00 cores, 0.001 ms/req | 0.01 cores, 0.002 ms/req |

Heap allocated per request: hub 95 B in 0 allocations; inspection edge 34.3 KiB in 115 allocations.

## Edge and hub, API call forwarded by the hub

`browser → billing edge → hub (Redis) → billing API`

| rate /s | done /s | errors | p50 ms | p99 ms | max ms | edge-billing CPU         | hub CPU                  | redis CPU                | api-billing CPU          |
| ------- | ------- | ------ | ------ | ------ | ------ | ------------------------ | ------------------------ | ------------------------ | ------------------------ |
| 250     | 250     | 0      | 2.97   | 10.95  | 14.3   | 0.08 cores, 0.332 ms/req | 0.13 cores, 0.506 ms/req | 0.03 cores, 0.137 ms/req | 0.05 cores, 0.215 ms/req |
| 500     | 500     | 0      | 2.26   | 9.43   | 17.5   | 0.12 cores, 0.242 ms/req | 0.19 cores, 0.375 ms/req | 0.05 cores, 0.100 ms/req | 0.08 cores, 0.164 ms/req |
| 1000    | 1000    | 0      | 2.42   | 6.20   | 57.4   | 0.21 cores, 0.205 ms/req | 0.33 cores, 0.326 ms/req | 0.08 cores, 0.075 ms/req | 0.14 cores, 0.142 ms/req |
| 2000    | 1999    | 0      | 1.98   | 10.85  | 75.5   | 0.34 cores, 0.170 ms/req | 0.53 cores, 0.265 ms/req | 0.10 cores, 0.048 ms/req | 0.22 cores, 0.110 ms/req |
| 4000    | 3997    | 0      | 2.61   | 8.71   | 127.6  | 0.82 cores, 0.206 ms/req | 1.17 cores, 0.293 ms/req | 0.15 cores, 0.037 ms/req | 0.51 cores, 0.128 ms/req |
| 6000    | 5996    | 0      | 2.67   | 17.54  | 150.0  | 1.20 cores, 0.199 ms/req | 1.69 cores, 0.282 ms/req | 0.19 cores, 0.032 ms/req | 0.72 cores, 0.120 ms/req |
| 8000    | 7992    | 0      | 3.74   | 44.03  | 298.8  | 1.65 cores, 0.207 ms/req | 2.26 cores, 0.283 ms/req | 0.25 cores, 0.031 ms/req | 0.96 cores, 0.120 ms/req |

Heap allocated per request: hub 60.2 KiB in 188 allocations; billing edge 40.5 KiB in 158 allocations.

## Hub, access token for an edge (no refresh)

`edge → hub /broker/token (Redis)`

| rate /s | done /s | errors | p50 ms | p99 ms | max ms | hub CPU                  | redis CPU                |
| ------- | ------- | ------ | ------ | ------ | ------ | ------------------------ | ------------------------ |
| 500     | 500     | 0      | 2.31   | 10.11  | 26.6   | 0.22 cores, 0.438 ms/req | 0.09 cores, 0.187 ms/req |
| 1000    | 1000    | 0      | 1.44   | 32.64  | 95.2   | 0.32 cores, 0.325 ms/req | 0.10 cores, 0.104 ms/req |
| 2000    | 2000    | 0      | 1.91   | 8.85   | 67.5   | 0.51 cores, 0.256 ms/req | 0.13 cores, 0.065 ms/req |
| 4000    | 3997    | 0      | 2.25   | 75.58  | 221.4  | 1.05 cores, 0.264 ms/req | 0.21 cores, 0.052 ms/req |
| 6000    | 5996    | 0      | 2.07   | 16.89  | 178.8  | 1.49 cores, 0.249 ms/req | 0.25 cores, 0.042 ms/req |
| 8000    | 7992    | 0      | 4.18   | 162.30 | 247.4  | 2.47 cores, 0.309 ms/req | 0.28 cores, 0.035 ms/req |

Heap allocated per request: hub 57.4 KiB in 146 allocations.

## Hub, token refresh at Keycloak

`edge → hub /broker/token → Keycloak refresh (rotating refresh token) → Redis`; 100 sessions, all expired, each fetched once per step.

| rate /s | done /s | errors | p50 ms | p99 ms | hub CPU                 | keycloak CPU             | redis CPU               |
| ------- | ------- | ------ | ------ | ------ | ----------------------- | ------------------------ | ----------------------- |
| 25      | 25      | 0      | 11.5   | 17.0   | 0.03 cores, 1.30 ms/req | 0.22 cores, 8.69 ms/req  | 0.04 cores, 1.70 ms/req |
| 50      | 50      | 0      | 11.3   | 15.2   | 0.06 cores, 1.25 ms/req | 0.63 cores, 12.48 ms/req | 0.03 cores, 0.54 ms/req |
| 100     | 100     | 0      | 10.3   | 16.0   | 0.11 cores, 1.06 ms/req | 1.08 cores, 10.80 ms/req | 0.04 cores, 0.42 ms/req |
| 200     | 198     | 0      | 9.7    | 12.8   | 0.20 cores, 1.02 ms/req | 1.69 cores, 8.56 ms/req  | 0.07 cores, 0.36 ms/req |

Hub heap allocated per refresh: 152.2 KiB in 413 allocations.

## Idle connections

2000 keep-alive connections opened, one request each, then held.

|                 | resident per connection | heap live per connection | file descriptors added |
| --------------- | ----------------------- | ------------------------ | ---------------------- |
| inspection edge | 1.4 KiB                 | 27.4 KiB                 | 2000                   |
| hub             | 12.4 KiB                | 27.4 KiB                 | 2000                   |

## Processes

|                 | threads | resident at idle | resident at the end | heap peak |
| --------------- | ------- | ---------------- | ------------------- | --------- |
| hub             | 11      | 90.7 MiB         | 164.9 MiB           | 156.0 MiB |
| inspection edge | 11      | 378.3 MiB        | 578.1 MiB           | 641.1 MiB |
| billing edge    | 11      | 49.3 MiB         | 59.8 MiB            | 46.7 MiB  |
