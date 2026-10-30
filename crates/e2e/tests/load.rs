//! Capacity measurements for the edge and the hub, against the measurement stack, whose hub and
//! edges count their heap allocations:
//!
//! docker compose -f docker-compose.yml -f docker-compose.perf.yml up -d --build
//! cargo test --release -p e2e --features load --test load -- --nocapture --test-threads=1
//!
//! One test runs every scenario in order and writes `perf/results.md`:
//!
//! - sessions: sign-in latency, and what one session costs in Redis and in the hub's memory;
//! - each request path at a series of fixed arrival rates (open loop: requests are sent on
//!   schedule whatever the answers do, and latency counts from the scheduled time, so a slow
//!   server cannot hide its queue), with each container's CPU and the heap allocated per request;
//! - idle connections: what one open keep-alive connection costs the edge and the hub;
//! - threads: what each process runs on.
//!
//! The load generator runs on the same machine as the stack, so the absolute rates are a lower
//! bound for one machine; the costs per request (CPU time, heap) are what carry over.

#![cfg(feature = "load")]

mod support;

use std::{
    collections::HashMap,
    fmt::Write as _,
    future::Future,
    process::Command,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use hdrhistogram::Histogram;
use redis::AsyncCommands;
use reqwest::StatusCode;
use support::*;
use tokio::{io::AsyncWriteExt, task::JoinSet};

/// The inspection edge's metrics (docker-compose.perf.yml).
const EDGE_INSPECTION_METRICS: &str = "http://localhost:8092/metrics";
/// The billing edge's metrics.
const EDGE_BILLING_METRICS: &str = "http://localhost:8093/metrics";
/// Sessions at the inspection kind (direct API calls) and at billing (through the hub).
const INSPECTION_SESSIONS: usize = 100;
const BILLING_SESSIONS: usize = 40;
/// How long each rate step runs.
const STEP: Duration = Duration::from_secs(8);
/// Idle connections opened for the connection-overhead measurement.
const IDLE_CONNECTIONS: usize = 2000;

// ---- metrics ----

/// One scrape of a metrics page: every sample by its full series name.
struct Scrape(HashMap<String, f64>);

impl Scrape {
    /// The value of series `name` (with labels, as printed), or 0.
    fn get(&self, name: &str) -> f64 {
        self.0.get(name).copied().unwrap_or(0.0)
    }

    /// Process counters of the binary with metric prefix `prefix`.
    fn process(&self, prefix: &str) -> Process {
        Process {
            allocations: self.get(&format!("{prefix}_heap_allocations_total")),
            allocated: self.get(&format!("{prefix}_heap_allocated_bytes_total")),
            live: self.get(&format!("{prefix}_heap_live_bytes")),
            peak: self.get(&format!("{prefix}_heap_peak_live_bytes")),
            resident: self.get(&format!("{prefix}_process_resident_bytes")),
            threads: self.get(&format!("{prefix}_process_threads")),
            fds: self.get(&format!("{prefix}_process_open_fds")),
        }
    }
}

/// A process's heap and operating-system counters at one moment.
#[derive(Clone, Copy, Debug)]
struct Process {
    allocations: f64,
    allocated: f64,
    live: f64,
    peak: f64,
    resident: f64,
    threads: f64,
    fds: f64,
}

/// Reads the metrics page at `url`.
async fn scrape(url: &str) -> Scrape {
    let text = reqwest::get(url).await.unwrap().text().await.unwrap();
    Scrape(
        text.lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .filter_map(|line| {
                let (name, value) = line.rsplit_once(' ')?;
                Some((name.to_owned(), value.parse().ok()?))
            })
            .collect(),
    )
}

/// The processes measured: the hub and the two edges under load.
async fn processes() -> [Process; 3] {
    [
        scrape(HUB_METRICS).await.process("hub"),
        scrape(EDGE_INSPECTION_METRICS).await.process("edge"),
        scrape(EDGE_BILLING_METRICS).await.process("edge"),
    ]
}

/// The containers whose CPU is measured, by compose service name.
const SERVICES: [&str; 7] = [
    "edge-inspection",
    "edge-billing",
    "hub",
    "redis",
    "keycloak",
    "api-inspection",
    "api-billing",
];

/// CPU seconds each of [`SERVICES`] has used since it started, from the Docker API's cumulative
/// counter (exact, unlike a sampled percentage).
fn cpu_seconds() -> HashMap<String, f64> {
    SERVICES
        .iter()
        .filter_map(|service| {
            let url = format!(
                "http://localhost/containers/auth-broker-kind-edge-{service}-1/stats?stream=false&one-shot=true"
            );
            let output = Command::new("curl")
                .args(["-s", "--unix-socket", "/var/run/docker.sock", &url])
                .output()
                .ok()?;
            let stats: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
            let nanos = stats["cpu_stats"]["cpu_usage"]["total_usage"].as_f64()?;
            Some(((*service).to_owned(), nanos / 1e9))
        })
        .collect()
}

/// Per service: cores used and CPU milliseconds per request, between `before` and `after`
/// over `seconds` and `requests`.
fn cpu_between(
    before: &HashMap<String, f64>,
    after: &HashMap<String, f64>,
    seconds: f64,
    requests: f64,
) -> HashMap<String, (f64, f64)> {
    after
        .iter()
        .filter_map(|(service, end)| {
            let used = end - before.get(service)?;
            Some((service.clone(), (used / seconds, used * 1000.0 / requests)))
        })
        .collect()
}

// ---- load ----

/// The outcome of one rate step.
struct Step {
    /// The scheduled arrival rate, per second.
    rate: u32,
    /// Answers with the expected status, and all others (including timeouts).
    ok: u64,
    errors: u64,
    /// Requests completed per second over the step.
    achieved: f64,
    /// Latency from the scheduled send time, in microseconds.
    latency: Histogram<u64>,
    /// Per container: cores used, and CPU milliseconds per request.
    cpu: HashMap<String, (f64, f64)>,
}

/// Sends `rate` requests a second for [`STEP`], request `n` made by `send(n)`, which says whether
/// the answer was right; measures each container's CPU over the step.
async fn run_step<F, Fut>(rate: u32, send: F) -> Step
where
    F: Fn(u64) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = bool> + Send + 'static,
{
    let send = Arc::new(send);
    let total = u64::from(rate) * STEP.as_secs();
    let interval = Duration::from_secs_f64(1.0 / f64::from(rate));
    let latency = Arc::new(Mutex::new(
        Histogram::<u64>::new_with_bounds(1, 120_000_000, 3).unwrap(),
    ));
    let cpu_before = tokio::task::spawn_blocking(cpu_seconds).await.unwrap();
    let started = Instant::now();
    let mut tasks = JoinSet::new();
    for n in 0..total {
        let scheduled = started + interval.mul_f64(n as f64);
        tokio::time::sleep_until(scheduled.into()).await;
        let (send, latency) = (send.clone(), latency.clone());
        tasks.spawn(async move {
            let ok = send(n).await;
            let micros = scheduled.elapsed().as_micros() as u64;
            latency.lock().unwrap().saturating_record(micros.max(1));
            ok
        });
    }
    let (mut ok, mut errors) = (0, 0);
    while let Some(result) = tasks.join_next().await {
        if result.unwrap_or(false) {
            ok += 1;
        } else {
            errors += 1;
        }
    }
    let elapsed = started.elapsed().as_secs_f64();
    let cpu_after = tokio::task::spawn_blocking(cpu_seconds).await.unwrap();
    Step {
        rate,
        ok,
        errors,
        achieved: (ok + errors) as f64 / elapsed,
        latency: Arc::try_unwrap(latency).unwrap().into_inner().unwrap(),
        cpu: cpu_between(&cpu_before, &cpu_after, elapsed, (ok + errors) as f64),
    }
}

/// One scenario: its rate steps and the heap allocated per request by each measured process.
struct Scenario {
    name: &'static str,
    path: &'static str,
    steps: Vec<Step>,
    /// Per process (hub, inspection edge, billing edge): heap bytes and allocations per request,
    /// over all steps.
    heap_per_request: [(f64, f64); 3],
    /// Containers whose CPU the scenario reports.
    containers: &'static [&'static str],
}

/// Runs `send` at each of `rates`, measuring the heap between the first and last step.
async fn scenario<F, Fut>(
    name: &'static str,
    path: &'static str,
    containers: &'static [&'static str],
    rates: &[u32],
    send: F,
) -> Scenario
where
    F: Fn(u64) -> Fut + Send + Sync + Clone + 'static,
    Fut: Future<Output = bool> + Send + 'static,
{
    let before = processes().await;
    let mut steps = Vec::new();
    for &rate in rates {
        let step = run_step(rate, send.clone()).await;
        println!(
            "{name} @ {rate}/s: {:.0}/s done, {} errors, p50 {:.2} ms, p99 {:.2} ms",
            step.achieved,
            step.errors,
            step.latency.value_at_quantile(0.5) as f64 / 1000.0,
            step.latency.value_at_quantile(0.99) as f64 / 1000.0
        );
        let overloaded =
            step.errors > step.ok / 100 || step.latency.value_at_quantile(0.99) > 1_000_000;
        steps.push(step);
        // Past the knee: higher rates only measure the queue.
        if overloaded {
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    let after = processes().await;
    let requests: u64 = steps.iter().map(|s| s.ok + s.errors).sum();
    let per = |i: usize| {
        (
            (after[i].allocated - before[i].allocated) / requests as f64,
            (after[i].allocations - before[i].allocations) / requests as f64,
        )
    };
    Scenario {
        name,
        path,
        steps,
        heap_per_request: [per(0), per(1), per(2)],
        containers,
    }
}

// ---- sessions ----

/// Signs `count` fresh users in at `site`; returns their session handles and each sign-in's
/// duration in milliseconds.
async fn sign_in_many(site: &str, count: usize) -> (Vec<String>, Vec<f64>) {
    let (mut handles, mut millis) = (Vec::new(), Vec::new());
    for _ in 0..count {
        let mut browser = Browser::new();
        let started = Instant::now();
        let handoff = sign_in(&mut browser, site, &fresh_user()).await;
        millis.push(started.elapsed().as_secs_f64() * 1000.0);
        assert_eq!(handoff.status(), StatusCode::SEE_OTHER, "sign-in at {site}");
        handles.push(browser.cookie(site, SESSION).unwrap());
    }
    (handles, millis)
}

/// Redis's own size of `key`, in bytes.
async fn memory_usage(redis: &mut redis::aio::MultiplexedConnection, key: &str) -> u64 {
    redis::cmd("MEMORY")
        .arg("USAGE")
        .arg(key)
        .query_async(redis)
        .await
        .unwrap_or(0)
}

/// Redis's `used_memory`.
async fn redis_used_memory(redis: &mut redis::aio::MultiplexedConnection) -> f64 {
    let info: String = redis::cmd("INFO")
        .arg("memory")
        .query_async(redis)
        .await
        .unwrap();
    info.lines()
        .find_map(|l| l.strip_prefix("used_memory:"))
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

/// The `p`-th percentile of `values`.
fn percentile(values: &[f64], p: f64) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    sorted[((sorted.len() - 1) as f64 * p).round() as usize]
}

// ---- idle connections ----

/// Opens `count` keep-alive connections to `port`, each after one complete request for `host`,
/// and holds them; returns them so the caller decides when they close.
async fn open_idle(port: u16, host: &str, count: usize) -> Vec<tokio::net::TcpStream> {
    use tokio::io::AsyncReadExt;
    let mut connections = Vec::new();
    for _ in 0..count {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        stream
            .write_all(format!("GET /health HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut buffer = [0u8; 512];
        let _ = stream.read(&mut buffer).await.unwrap();
        connections.push(stream);
    }
    connections
}

/// What `count` idle connections cost the process behind `metrics` (prefix `prefix`): resident
/// and heap bytes per connection, and file descriptors added.
async fn connection_cost(port: u16, host: &str, metrics: &str, prefix: &str) -> (f64, f64, f64) {
    tokio::time::sleep(Duration::from_secs(2)).await;
    let before = scrape(metrics).await.process(prefix);
    let connections = open_idle(port, host, IDLE_CONNECTIONS).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let after = scrape(metrics).await.process(prefix);
    drop(connections);
    let n = IDLE_CONNECTIONS as f64;
    (
        (after.resident - before.resident) / n,
        (after.live - before.live) / n,
        after.fds - before.fds,
    )
}

/// A signed `POST /broker/token` for inspection session `handle`, as the inspection edge sends
/// it, on the shared client `http` (one connection pool, as an edge has).
fn token_request(http: &reqwest::Client, handle: &str) -> reqwest::RequestBuilder {
    let signed = signer("plant-a")
        .sign("POST", "/broker/token", Some(handle), now())
        .unwrap();
    let mut headers = reqwest::header::HeaderMap::new();
    signed.apply(&mut headers);
    http.post(format!("{HUB}/broker/token"))
        .headers(headers)
        .header("x-session-handle", handle)
}

// ---- report ----

/// Bytes as `12.3 KiB`.
fn bytes(n: f64) -> String {
    if n.abs() >= 1024.0 * 1024.0 {
        format!("{:.1} MiB", n / 1024.0 / 1024.0)
    } else if n.abs() >= 1024.0 {
        format!("{:.1} KiB", n / 1024.0)
    } else {
        format!("{n:.0} B")
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn capacity() {
    wait_for_stack().await;
    let mut report = String::new();
    let mut redis = redis().await;

    // -- sessions --
    let idle = processes().await;
    let redis_before = redis_used_memory(&mut redis).await;
    let (inspection, inspection_ms) = sign_in_many(PLANT_A, INSPECTION_SESSIONS).await;
    let (billing, billing_ms) = sign_in_many(PLANT_C, BILLING_SESSIONS).await;
    let redis_after = redis_used_memory(&mut redis).await;
    let signed_in = processes().await;
    let sessions = (INSPECTION_SESSIONS + BILLING_SESSIONS) as f64;

    let mut session_sizes = Vec::new();
    let mut sealed_sizes = Vec::new();
    for handle in inspection.iter().chain(&billing) {
        let key = format!("hub:session:{{{}}}", common::crypto::hash_key(handle));
        session_sizes.push(memory_usage(&mut redis, &key).await as f64);
        let sealed: usize = redis.strlen(&key).await.unwrap();
        sealed_sizes.push(sealed as f64);
    }
    let index_keys: Vec<String> = redis.keys("hub:iam-sid:*").await.unwrap();
    let mut index_bytes = 0.0;
    for key in &index_keys {
        index_bytes += memory_usage(&mut redis, key).await as f64;
    }
    let sign_ins: Vec<f64> = inspection_ms.iter().chain(&billing_ms).copied().collect();

    // -- request paths --
    let inspection = Arc::new(inspection);
    let billing = Arc::new(billing);
    let http = client();
    // One call per inspection session first, so the edge's token cache is warm.
    for handle in inspection.iter() {
        let response = http
            .get(format!("{PLANT_A}/api/warm"))
            .header("cookie", format!("{SESSION}={handle}"))
            .header(common::csrf::CSRF_HEADER, "1")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let warmed = scrape(EDGE_INSPECTION_METRICS).await.process("edge");

    let edge_direct = {
        let (http, sessions) = (http.clone(), inspection.clone());
        scenario(
            "Edge, direct API call (token cached)",
            "browser → inspection edge → inspection API",
            &["edge-inspection", "api-inspection", "hub", "redis"],
            &[500, 1000, 2000, 4000, 8000, 12000, 16000],
            move |n| {
                let (http, handle) = (http.clone(), sessions[n as usize % sessions.len()].clone());
                async move {
                    http.get(format!("{PLANT_A}/api/orders"))
                        .header("cookie", format!("{SESSION}={handle}"))
                        .header(common::csrf::CSRF_HEADER, "1")
                        .send()
                        .await
                        .is_ok_and(|r| r.status() == StatusCode::OK)
                }
            },
        )
        .await
    };

    let through_hub = {
        let (http, sessions) = (http.clone(), billing.clone());
        scenario(
            "Edge and hub, API call forwarded by the hub",
            "browser → billing edge → hub (Redis) → billing API",
            &["edge-billing", "hub", "redis", "api-billing"],
            &[250, 500, 1000, 2000, 4000, 6000, 8000],
            move |n| {
                let (http, handle) = (http.clone(), sessions[n as usize % sessions.len()].clone());
                async move {
                    http.get(format!("{PLANT_C}/api/invoices"))
                        .header("cookie", format!("{SESSION}={handle}"))
                        .header(common::csrf::CSRF_HEADER, "1")
                        .send()
                        .await
                        .is_ok_and(|r| r.status() == StatusCode::OK)
                }
            },
        )
        .await
    };

    let token_fetch = {
        let (http, sessions) = (http.clone(), inspection.clone());
        scenario(
            "Hub, access token for an edge (no refresh)",
            "edge → hub /broker/token (Redis)",
            &["hub", "redis"],
            &[500, 1000, 2000, 4000, 6000, 8000],
            move |n| {
                let (http, handle) = (http.clone(), sessions[n as usize % sessions.len()].clone());
                async move {
                    token_request(&http, &handle)
                        .send()
                        .await
                        .is_ok_and(|r| r.status() == StatusCode::OK)
                }
            },
        )
        .await
    };

    // -- refreshes: every session's token expired, then each fetched once, at a fixed rate --
    let http = client();
    let hub_before_refresh = scrape(HUB_METRICS).await.process("hub");
    let mut refresh_steps = Vec::new();
    for rate in [25, 50, 100, 200] {
        // Keycloak only spots a reused refresh token across whole seconds.
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        for handle in inspection.iter() {
            let mut session = read_session(handle).await.unwrap();
            session["expires_at"] = 0.into();
            write_session(handle, &session).await;
        }
        let sessions = inspection.clone();
        let interval = Duration::from_secs_f64(1.0 / f64::from(rate));
        let cpu_before = tokio::task::spawn_blocking(cpu_seconds).await.unwrap();
        let started = Instant::now();
        let mut tasks = JoinSet::new();
        for (n, handle) in sessions.iter().cloned().enumerate() {
            let scheduled = started + interval.mul_f64(n as f64);
            tokio::time::sleep_until(scheduled.into()).await;
            let http = http.clone();
            tasks.spawn(async move {
                let ok = token_request(&http, &handle)
                    .send()
                    .await
                    .is_ok_and(|r| r.status() == StatusCode::OK);
                (ok, scheduled.elapsed().as_secs_f64() * 1000.0)
            });
        }
        let mut latencies = Vec::new();
        let mut errors = 0;
        while let Some(result) = tasks.join_next().await {
            let (ok, ms) = result.unwrap();
            latencies.push(ms);
            errors += u32::from(!ok);
        }
        let elapsed = started.elapsed().as_secs_f64();
        let achieved = latencies.len() as f64 / elapsed;
        let cpu_after = tokio::task::spawn_blocking(cpu_seconds).await.unwrap();
        let cpu = cpu_between(&cpu_before, &cpu_after, elapsed, latencies.len() as f64);
        println!(
            "refresh @ {rate}/s: {achieved:.0}/s done, {errors} errors, p50 {:.1} ms, p99 {:.1} ms",
            percentile(&latencies, 0.5),
            percentile(&latencies, 0.99)
        );
        refresh_steps.push((rate, achieved, errors, latencies, cpu));
    }
    let hub_after_refresh = scrape(HUB_METRICS).await.process("hub");
    let refreshes = (inspection.len() * refresh_steps.len()) as f64;

    // -- idle connections --
    let edge_connection = connection_cost(
        5201,
        "plant-a.localhost:5201",
        EDGE_INSPECTION_METRICS,
        "edge",
    )
    .await;
    let hub_connection = connection_cost(8090, "localhost:8090", HUB_METRICS, "hub").await;
    let end = processes().await;

    // -- report --
    let _ = writeln!(report, "# Edge and hub capacity: measurements\n");
    let _ = writeln!(
        report,
        "Measured on {} against the measurement stack (`docker-compose.perf.yml`), with the load \
         generator on the same machine. Docker has {} CPUs. Rates are a lower bound; CPU time and \
         heap per request carry over.\n",
        chrono_like_now(),
        String::from_utf8_lossy(
            &Command::new("docker")
                .args(["info", "--format", "{{.NCPU}}"])
                .output()
                .unwrap()
                .stdout
        )
        .trim()
    );

    let _ = writeln!(report, "## Sessions\n");
    let _ = writeln!(report, "| | Value |\n|---|---|");
    let _ = writeln!(
        report,
        "| sign-in, browser → edge → hub → Keycloak → hub → edge (p50 / p90 / max) | {:.0} / {:.0} / {:.0} ms |",
        percentile(&sign_ins, 0.5),
        percentile(&sign_ins, 0.9),
        percentile(&sign_ins, 1.0)
    );
    let _ = writeln!(
        report,
        "| Redis key per session, `MEMORY USAGE` (p50 / max) | {} / {} |",
        bytes(percentile(&session_sizes, 0.5)),
        bytes(percentile(&session_sizes, 1.0))
    );
    let _ = writeln!(
        report,
        "| of which the sealed value (p50) | {} |",
        bytes(percentile(&sealed_sizes, 0.5))
    );
    let _ = writeln!(
        report,
        "| back-channel logout index, per session | {} |",
        bytes(index_bytes / sessions)
    );
    let _ = writeln!(
        report,
        "| Redis `used_memory` growth per session | {} |",
        bytes((redis_after - redis_before) / sessions)
    );
    let _ = writeln!(
        report,
        "| hub heap still live per session after sign-in | {} |",
        bytes((signed_in[0].live - idle[0].live) / sessions)
    );
    let _ = writeln!(
        report,
        "| hub heap allocated per sign-in | {} in {:.0} allocations |",
        bytes((signed_in[0].allocated - idle[0].allocated) / sessions),
        (signed_in[0].allocations - idle[0].allocations) / sessions
    );
    let _ = writeln!(
        report,
        "| inspection edge heap live per cached token | {} |",
        bytes((warmed.live - signed_in[1].live) / INSPECTION_SESSIONS as f64)
    );
    let _ = writeln!(report);

    for s in [&edge_direct, &through_hub, &token_fetch] {
        let _ = writeln!(report, "## {}\n\n`{}`\n", s.name, s.path);
        let mut header = String::from("| rate /s | done /s | errors | p50 ms | p99 ms | max ms |");
        let mut rule = String::from("|---|---|---|---|---|---|");
        for c in s.containers {
            let _ = write!(header, " {c} CPU |");
            rule.push_str("---|");
        }
        let _ = writeln!(report, "{header}\n{rule}");
        for step in &s.steps {
            let mut row = format!(
                "| {} | {:.0} | {} | {:.2} | {:.2} | {:.1} |",
                step.rate,
                step.achieved,
                step.errors,
                step.latency.value_at_quantile(0.5) as f64 / 1000.0,
                step.latency.value_at_quantile(0.99) as f64 / 1000.0,
                step.latency.max() as f64 / 1000.0
            );
            for c in s.containers {
                let (cores, per) = step.cpu.get(*c).copied().unwrap_or_default();
                let _ = write!(row, " {cores:.2} cores, {per:.3} ms/req |");
            }
            let _ = writeln!(report, "{row}");
        }
        let names = ["hub", "inspection edge", "billing edge"];
        let heap: Vec<String> = s
            .heap_per_request
            .iter()
            .zip(names)
            .filter(|((b, _), _)| *b > 64.0)
            .map(|((b, a), name)| format!("{name} {} in {a:.0} allocations", bytes(*b)))
            .collect();
        let _ = writeln!(
            report,
            "\nHeap allocated per request: {}.\n",
            heap.join("; ")
        );
    }

    let _ = writeln!(
        report,
        "## Hub, token refresh at Keycloak\n\n`edge → hub /broker/token → Keycloak refresh (rotating refresh token) → Redis`; {} sessions, all expired, each fetched once per step.\n",
        inspection.len()
    );
    let _ = writeln!(
        report,
        "| rate /s | done /s | errors | p50 ms | p99 ms | hub CPU | keycloak CPU | redis CPU |\n|---|---|---|---|---|---|---|---|"
    );
    for (rate, achieved, errors, latencies, cpu) in &refresh_steps {
        let core = |c: &str| {
            let (cores, per) = cpu.get(c).copied().unwrap_or_default();
            format!("{cores:.2} cores, {per:.2} ms/req")
        };
        let _ = writeln!(
            report,
            "| {rate} | {achieved:.0} | {errors} | {:.1} | {:.1} | {} | {} | {} |",
            percentile(latencies, 0.5),
            percentile(latencies, 0.99),
            core("hub"),
            core("keycloak"),
            core("redis")
        );
    }
    let _ = writeln!(
        report,
        "\nHub heap allocated per refresh: {} in {:.0} allocations.\n",
        bytes((hub_after_refresh.allocated - hub_before_refresh.allocated) / refreshes),
        (hub_after_refresh.allocations - hub_before_refresh.allocations) / refreshes
    );

    let _ = writeln!(
        report,
        "## Idle connections\n\n{IDLE_CONNECTIONS} keep-alive connections opened, one request each, then held.\n"
    );
    let _ = writeln!(
        report,
        "| | resident per connection | heap live per connection | file descriptors added |\n|---|---|---|---|"
    );
    let _ = writeln!(
        report,
        "| inspection edge | {} | {} | {:.0} |",
        bytes(edge_connection.0),
        bytes(edge_connection.1),
        edge_connection.2
    );
    let _ = writeln!(
        report,
        "| hub | {} | {} | {:.0} |",
        bytes(hub_connection.0),
        bytes(hub_connection.1),
        hub_connection.2
    );
    let _ = writeln!(report);

    let _ = writeln!(
        report,
        "## Processes\n\n| | threads | resident at idle | resident at the end | heap peak |\n|---|---|---|---|---|"
    );
    for (i, name) in ["hub", "inspection edge", "billing edge"]
        .iter()
        .enumerate()
    {
        let _ = writeln!(
            report,
            "| {name} | {:.0} | {} | {} | {} |",
            end[i].threads,
            bytes(idle[i].resident),
            bytes(end[i].resident),
            bytes(end[i].peak)
        );
    }

    let report = align_tables(&report);
    println!("\n{report}");
    let dir = format!("{}/../../perf", env!("CARGO_MANIFEST_DIR"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(format!("{dir}/results.md"), &report).unwrap();
}

/// `markdown` with every table's columns aligned: each cell padded to its column's widest, so
/// the tables read as tables in the source too, as the hand-written docs' do.
fn align_tables(markdown: &str) -> String {
    /// The cells of table row `line`, trimmed.
    fn cells(line: &str) -> Vec<String> {
        let inner = line.trim().trim_start_matches('|').trim_end_matches('|');
        inner
            .split('|')
            .map(|cell| cell.trim().to_owned())
            .collect()
    }
    /// Whether `cells` are a header rule such as `---`, `:--` or `--:`.
    fn is_rule(cells: &[String]) -> bool {
        cells.iter().all(|cell| {
            let dashes = cell.trim_start_matches(':').trim_end_matches(':');
            !dashes.is_empty() && dashes.chars().all(|c| c == '-')
        })
    }

    let lines: Vec<&str> = markdown.split('\n').collect();
    let mut out = Vec::with_capacity(lines.len());
    let mut i = 0;
    while i < lines.len() {
        let starts_table = lines[i].starts_with('|')
            && lines
                .get(i + 1)
                .is_some_and(|next| next.starts_with('|') && is_rule(&cells(next)));
        if !starts_table {
            out.push(lines[i].to_owned());
            i += 1;
            continue;
        }
        let end = (i..lines.len())
            .find(|&j| !lines[j].starts_with('|'))
            .unwrap_or(lines.len());
        let rows: Vec<Vec<String>> = lines[i..end].iter().map(|line| cells(line)).collect();
        let columns = rows.iter().map(Vec::len).max().unwrap_or(0);
        let width = |column: usize| {
            rows.iter()
                .enumerate()
                .filter(|(row, _)| *row != 1)
                .filter_map(|(_, cells)| cells.get(column))
                .map(|cell| cell.chars().count())
                .max()
                .unwrap_or(0)
                .max(3)
        };
        let widths: Vec<usize> = (0..columns).map(width).collect();
        let right_aligned: Vec<bool> = (0..columns)
            .map(|column| rows[1].get(column).is_some_and(|rule| rule.ends_with(':')))
            .collect();
        for (row, cells) in rows.iter().enumerate() {
            let parts: Vec<String> = (0..columns)
                .map(|column| {
                    let w = widths[column];
                    if row == 1 {
                        let colon = if right_aligned[column] { ":" } else { "" };
                        return format!("{}{colon}", "-".repeat(w - colon.len()));
                    }
                    let text = cells.get(column).map_or("", String::as_str);
                    let pad = " ".repeat(w - text.chars().count());
                    if right_aligned[column] {
                        format!("{pad}{text}")
                    } else {
                        format!("{text}{pad}")
                    }
                })
                .collect();
            out.push(format!("| {} |", parts.join(" | ")));
        }
        i = end;
    }
    out.join("\n")
}

/// Today's date and time, from the system's `date`.
fn chrono_like_now() -> String {
    String::from_utf8_lossy(
        &Command::new("date")
            .arg("+%Y-%m-%d %H:%M")
            .output()
            .unwrap()
            .stdout,
    )
    .trim()
    .to_owned()
}

#[test]
fn given_a_ragged_table_then_its_columns_are_aligned() {
    let report = "# Results\n\n| Path | p50 |\n|---|--:|\n| direct | 1.2 ms |\n| through the hub | 12 ms |\nafter";
    assert_eq!(
        align_tables(report),
        "# Results\n\n\
         | Path            |    p50 |\n\
         | --------------- | -----: |\n\
         | direct          | 1.2 ms |\n\
         | through the hub |  12 ms |\n\
         after"
    );
}

#[test]
fn given_the_last_results_then_they_are_already_aligned() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../perf/results.md");
    let results = std::fs::read_to_string(path).unwrap();
    assert_eq!(align_tables(&results), results);
}
