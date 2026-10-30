//! Prometheus metrics, served on their own address so they never share the public port. Ported
//! from the Rust BFF's `metrics`, with the metric names given by each binary.
//!
//! Every binary records `<prefix>_http_requests_total{route, method, status}` and
//! `<prefix>_http_request_duration_seconds{route, method}` through [`track`], labelled by route
//! template, plus the counters it describes to [`serve`]. Without the `metrics` feature every
//! recording function is a no-op, so callers need no `cfg` of their own.

#[cfg(feature = "metrics")]
pub use imp::{serve, track};

/// One metric a binary records: its name, Prometheus type and description.
pub type Description = (&'static str, &'static str, &'static str);

/// Adds one to counter `name` with `labels`.
pub fn counter(name: &'static str, labels: &[(&'static str, &str)]) {
    #[cfg(feature = "metrics")]
    imp::count(name, labels);
    #[cfg(not(feature = "metrics"))]
    let _ = (name, labels);
}

/// The registry, the request middleware and the metrics server; only with the `metrics`
/// feature.
#[cfg(feature = "metrics")]
mod imp {
    use std::{
        collections::BTreeMap,
        fmt::Write,
        net::SocketAddr,
        sync::{LazyLock, Mutex, OnceLock, PoisonError},
        time::Instant,
    };

    use axum::{
        Router,
        extract::{MatchedPath, Request},
        http::{HeaderValue, header::CONTENT_TYPE},
        middleware::Next,
        response::{IntoResponse, Response},
        routing::get,
    };
    use tokio::net::TcpListener;
    use tracing::{info, warn};

    use super::Description;

    /// Upper bounds of the request duration buckets, in seconds.
    const BUCKETS: [f64; 10] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 10.0];

    /// Label names and values of one time series.
    type Labels = Vec<(&'static str, String)>;

    /// One histogram's bucket counts, total count and sum.
    #[derive(Default)]
    struct Histogram {
        /// Observations at or below each of [`BUCKETS`].
        buckets: [u64; BUCKETS.len()],
        /// All observations.
        count: u64,
        /// Sum of all observed values, in seconds.
        sum: f64,
    }

    /// All recorded values.
    #[derive(Default)]
    struct Registry {
        /// Counter values by metric name and labels.
        counters: BTreeMap<(String, Labels), u64>,
        /// Request durations by labels.
        durations: BTreeMap<Labels, Histogram>,
    }

    /// The process-wide registry; the lock is held only to update or copy values.
    static REGISTRY: LazyLock<Mutex<Registry>> = LazyLock::new(Mutex::default);
    /// The binary's metric name prefix and its counters, set once by [`serve`].
    static NAMES: OnceLock<(&'static str, &'static [Description])> = OnceLock::new();

    /// The metric name prefix, e.g. `hub`; `app` until [`serve`] ran.
    fn prefix() -> &'static str {
        NAMES.get().map_or("app", |(prefix, _)| prefix)
    }

    /// Runs `f` on the registry, also after a panic elsewhere left the lock poisoned.
    fn with_registry<T>(f: impl FnOnce(&mut Registry) -> T) -> T {
        f(&mut REGISTRY.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Adds one to counter `name` with `labels` in the registry.
    pub(super) fn count(name: &'static str, labels: &[(&'static str, &str)]) {
        let labels = labels
            .iter()
            .map(|(key, value)| (*key, (*value).to_owned()))
            .collect();
        with_registry(|registry| {
            *registry
                .counters
                .entry((name.to_owned(), labels))
                .or_default() += 1;
        });
    }

    /// Middleware: counts `request` and times it through `next`, labelled with the route
    /// template (e.g. `/api/{*rest}`) rather than the actual path, so the number of series stays
    /// bounded.
    pub async fn track(request: Request, next: Next) -> Response {
        let route = request
            .extensions()
            .get::<MatchedPath>()
            .map_or("unmatched", MatchedPath::as_str)
            .to_owned();
        let method = request.method().as_str().to_owned();
        let started = Instant::now();
        let response = next.run(request).await;
        let seconds = started.elapsed().as_secs_f64();

        let status = response.status().as_u16().to_string();
        with_registry(|registry| {
            let labels: Labels = vec![("route", route), ("method", method)];
            let mut with_status = labels.clone();
            with_status.push(("status", status));
            *registry
                .counters
                .entry((format!("{}_http_requests_total", prefix()), with_status))
                .or_default() += 1;
            let histogram = registry.durations.entry(labels).or_default();
            for (bound, bucket) in BUCKETS.iter().zip(histogram.buckets.iter_mut()) {
                if seconds <= *bound {
                    *bucket += 1;
                }
            }
            histogram.count += 1;
            histogram.sum += seconds;
        });
        response
    }

    /// `labels` in Prometheus syntax, e.g. `{route="/health",method="GET"}`; empty without labels.
    fn format_labels(labels: &[(&str, String)]) -> String {
        if labels.is_empty() {
            return String::new();
        }
        let pairs: Vec<String> = labels
            .iter()
            .map(|(key, value)| {
                let escaped = value
                    .replace('\\', "\\\\")
                    .replace('"', "\\\"")
                    .replace('\n', "\\n");
                format!("{key}=\"{escaped}\"")
            })
            .collect();
        format!("{{{}}}", pairs.join(","))
    }

    /// Everything recorded so far, in the Prometheus text exposition format.
    pub fn render() -> String {
        let prefix = prefix();
        let counters = NAMES.get().map_or(&[][..], |(_, counters)| counters);
        let requests = format!("{prefix}_http_requests_total");
        let durations = format!("{prefix}_http_request_duration_seconds");
        with_registry(|registry| {
            let mut out = String::new();
            let _ = writeln!(
                out,
                "# HELP {requests} Requests handled, by route template, method and status.\n# TYPE {requests} counter"
            );
            for ((counter, labels), value) in &registry.counters {
                if *counter == requests {
                    let _ = writeln!(out, "{requests}{} {value}", format_labels(labels));
                }
            }
            let _ = writeln!(
                out,
                "# HELP {durations} Time to answer a request, by route template and method.\n# TYPE {durations} histogram"
            );
            for (labels, histogram) in &registry.durations {
                for (bound, count) in BUCKETS.iter().zip(histogram.buckets) {
                    let mut with_le = labels.clone();
                    with_le.push(("le", bound.to_string()));
                    let _ = writeln!(out, "{durations}_bucket{} {count}", format_labels(&with_le));
                }
                let mut with_le = labels.clone();
                with_le.push(("le", "+Inf".to_owned()));
                let _ = writeln!(
                    out,
                    "{durations}_bucket{} {}",
                    format_labels(&with_le),
                    histogram.count
                );
                let labels = format_labels(labels);
                let _ = writeln!(out, "{durations}_sum{labels} {}", histogram.sum);
                let _ = writeln!(out, "{durations}_count{labels} {}", histogram.count);
            }
            #[cfg(feature = "alloc-stats")]
            {
                let heap = crate::alloc::snapshot();
                for (name, kind, help, value) in [
                    (
                        "heap_allocations_total",
                        "counter",
                        "Heap allocations and reallocations since start.",
                        heap.allocations,
                    ),
                    (
                        "heap_allocated_bytes_total",
                        "counter",
                        "Heap bytes allocated since start.",
                        heap.allocated_bytes,
                    ),
                    (
                        "heap_live_bytes",
                        "gauge",
                        "Heap bytes allocated and not yet freed.",
                        heap.live_bytes,
                    ),
                    (
                        "heap_peak_live_bytes",
                        "gauge",
                        "The most heap bytes live at once since start.",
                        heap.peak_live_bytes,
                    ),
                ] {
                    let _ = writeln!(
                        out,
                        "# HELP {prefix}_{name} {help}\n# TYPE {prefix}_{name} {kind}\n{prefix}_{name} {value}"
                    );
                }
            }
            for (name, help, value) in process_gauges() {
                let _ = writeln!(
                    out,
                    "# HELP {prefix}_{name} {help}\n# TYPE {prefix}_{name} gauge\n{prefix}_{name} {value}"
                );
            }
            for (name, kind, help) in counters {
                let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
                for ((counter, labels), value) in &registry.counters {
                    if counter == name {
                        let _ = writeln!(out, "{name}{} {value}", format_labels(labels));
                    }
                }
            }
            out
        })
    }

    /// The process's threads, resident memory and open file descriptors, from `/proc` on
    /// Linux; none elsewhere.
    fn process_gauges() -> Vec<(&'static str, &'static str, u64)> {
        let mut gauges = Vec::new();
        let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
            return gauges;
        };
        // `VmRSS:     12345 kB`, `Threads:  12`.
        let field = |name: &str| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|n| n.parse::<u64>().ok())
        };
        if let Some(threads) = field("Threads:") {
            gauges.push(("process_threads", "Operating system threads.", threads));
        }
        if let Some(kb) = field("VmRSS:") {
            gauges.push(("process_resident_bytes", "Resident memory.", kb * 1024));
        }
        if let Ok(fds) = std::fs::read_dir("/proc/self/fd") {
            gauges.push((
                "process_open_fds",
                "Open file descriptors, sockets included.",
                fds.count() as u64,
            ));
        }
        gauges
    }

    /// `GET /metrics`.
    async fn metrics() -> Response {
        let mut response = render().into_response();
        response.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4"),
        );
        response
    }

    /// Names this binary's metrics `<prefix>_…`, describes its `counters`, and serves
    /// `GET /metrics` on `address` until the process exits; logs if it cannot bind.
    pub async fn serve(
        address: SocketAddr,
        prefix: &'static str,
        counters: &'static [Description],
    ) {
        let _ = NAMES.set((prefix, counters));
        let listener = match TcpListener::bind(address).await {
            Ok(listener) => listener,
            Err(error) => {
                warn!(%error, %address, "metrics are not served");
                return;
            }
        };
        info!("Metrics on {address}/metrics");
        let app = Router::new().route("/metrics", get(metrics));
        if let Err(error) = axum::serve(listener, app).await {
            warn!(%error, "metrics server stopped");
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn given_label_values_then_quotes_backslashes_and_newlines_are_escaped() {
            let labels = vec![("route", "a\"b\\c\nd".to_owned())];
            assert_eq!(format_labels(&labels), r#"{route="a\"b\\c\nd"}"#);
            assert_eq!(format_labels(&[]), "");
        }
    }
}
