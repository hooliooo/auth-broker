//! Measures the registry at 10,000, 100,000 and 1,000,000 installations, half web-app and half
//! native with two keys each, plus installations with 500 and 5,000 workstation keys: reload time,
//! memory held by a hub and by one kind's edge, lookups at random installations, and signature
//! checks. Sizes come from the arguments, if any:
//!
//! cargo run --release -p common --example registry_scale --features alloc-stats [-- 10000 100000]
use base64::Engine;
use common::{
    alloc,
    registry::Registry,
    signing::{EdgeSigner, SignatureInput, generate_key, verify},
};
use std::{hint::black_box, time::Instant};

#[global_allocator]
static A: alloc::Counting = alloc::Counting;

fn dummy(n: u32, tag: u8) -> String {
    let mut b = [tag; 32];
    b[..4].copy_from_slice(&n.to_be_bytes());
    format!(
        "ed25519:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
    )
}
fn mb(b: u64) -> String {
    format!("{:.1} MB", b as f64 / 1e6)
}
fn per(rounds: u32, mut f: impl FnMut(u32)) -> String {
    let t = Instant::now();
    for i in 0..rounds {
        f(i)
    }
    format!("{:?}", t.elapsed() / rounds)
}

fn main() {
    // Two big installations with real keys, for signature checks: 500 and 5,000 workstations.
    let big: Vec<(&str, Vec<EdgeSigner>)> = [("big-500", 500), ("big-5000", 5000)]
        .into_iter()
        .map(|(id, n)| {
            (
                id,
                (0..n)
                    .map(|_| EdgeSigner::from_base64(id, &generate_key().unwrap()).unwrap())
                    .collect(),
            )
        })
        .collect();
    let sizes: Vec<u32> = std::env::args()
        .skip(1)
        .filter_map(|a| a.parse().ok())
        .collect();
    let sizes = if sizes.is_empty() {
        vec![10_000, 100_000, 1_000_000]
    } else {
        sizes
    };
    for n in sizes {
        let half = n / 2;
        let mut native: Vec<String> = (0..half).map(|i| format!(
            r#"{{"id":"inst-{i}","tenant":"t","api_url":"https://api.example","keys":["{}","{}"]}}"#, dummy(i, 1), dummy(i, 2))).collect();
        for (id, signers) in &big {
            let keys: Vec<String> = signers
                .iter()
                .map(|s| format!(r#""{}""#, s.public_key()))
                .collect();
            native.push(format!(
                r#"{{"id":"{id}","tenant":"t","api_url":"https://api.example","keys":[{}]}}"#,
                keys.join(",")
            ));
        }
        let native = format!(
            r#"{{"app":{{"id":"planner","client_id":"hub-planner","native":{{}},"api_audience":"p"}},"sites":[{}]}}"#,
            native.join(",")
        );
        let web: Vec<String> = (0..half).map(|i| format!(
            r#"{{"id":"web-{i}","origin":"https://web-{i}.inspection.example","tenant":"t","api_url":"https://api.example"}}"#)).collect();
        let web = format!(
            r#"{{"app":{{"id":"inspection","client_id":"hub-inspection","edge_public_key":"{}","api_audience":"i"}},"sites":[{}]}}"#,
            dummy(0, 9),
            web.join(",")
        );
        let json = (native.len() + web.len()) as u64;

        let before = alloc::snapshot();
        let t = Instant::now();
        let r = Registry::from_documents([
            ("planner.json", native.as_str()),
            ("inspection.json", web.as_str()),
        ])
        .unwrap();
        let load = t.elapsed();
        let after = alloc::snapshot();
        let keys = half * 2 + 5500;
        println!(
            "\n== {} installations ({} web, {} native), {} keys, registry JSON {}",
            r.site_count(),
            half,
            half + 2,
            keys,
            mb(json)
        );
        println!("load + validate + index: {load:?}");
        println!(
            "memory held by the registry: {}   (peak extra during load: {})",
            mb(after.live_bytes - before.live_bytes),
            mb(after.peak_live_bytes.saturating_sub(before.live_bytes))
        );

        // Lookups at random positions, so no cache luck.
        let mut x: u64 = 0x9e3779b97f4a7c15;
        let ids: Vec<(String, String)> = (0..20_000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let i = (x % half as u64) as u32;
                (format!("inst-{i}"), format!("web-{i}.inspection.example"))
            })
            .collect();
        println!(
            "installation by id (random):        {}",
            per(1_000_000, |i| {
                black_box(r.enabled(&ids[i as usize % ids.len()].0));
            })
        );
        println!(
            "web installation by host (random):  {}",
            per(1_000_000, |i| {
                black_box(r.site_for_host("inspection", &ids[i as usize % ids.len()].1));
            })
        );
        for (id, signers) in &big {
            let (site, app) = r.enabled(id).unwrap();
            let s = signers.last().unwrap();
            let signed = s.sign_with(
                id,
                "POST",
                "/broker/token",
                Some("h"),
                1,
                "nonce-nonce-nonce-nonce",
            );
            let input = SignatureInput {
                site_id: id,
                method: "POST",
                path_and_query: "/broker/token",
                timestamp: 1,
                nonce: "nonce-nonce-nonce-nonce",
                handle: Some("h"),
            };
            println!(
                "{id}: key by id + verify:     {}",
                per(2_000, |_| {
                    black_box(verify(
                        site.verifying_key(app, Some(&signed.key_id)).unwrap(),
                        &input,
                        &signed.signature,
                    ));
                })
            );
            println!(
                "{id}: unknown key id refused:  {}",
                per(100_000, |_| {
                    black_box(site.verifying_key(app, Some("not-a-key-id-xx")));
                })
            );
            println!(
                "{id}: clone of the site:       {}",
                per(20_000, |_| {
                    black_box(site.clone());
                })
            );
        }
        drop(r);
        let b = alloc::snapshot();
        let edge = Registry::from_documents([
            ("planner.json", native.as_str()),
            ("inspection.json", web.as_str()),
        ])
        .unwrap()
        .only_kind("inspection");
        println!(
            "memory held by one kind's edge (half the installations): {}",
            mb(alloc::snapshot().live_bytes - b.live_bytes)
        );
        drop(edge);
    }
}
