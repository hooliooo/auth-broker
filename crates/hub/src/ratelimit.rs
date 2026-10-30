//! Fixed-window counters in Redis, shared by every hub instance.

use redis::aio::ConnectionManager;

use crate::{error::AppError, session::now};

/// Length of one counting window.
const WINDOW_SECS: u64 = 60;

/// Counts one call for `key` in `redis`; `true` while no more than `limit` were counted in the
/// current minute.
pub async fn allow(redis: &mut ConnectionManager, key: &str, limit: u64) -> Result<bool, AppError> {
    let window = now() / WINDOW_SECS;
    let key = format!("hub:rl:{key}:{window}");
    // EXPIRE NX sets the expiry only on the first hit, so the key dies with its window.
    let (count,): (u64,) = redis::pipe()
        .atomic()
        .incr(&key, 1)
        .cmd("EXPIRE")
        .arg(&key)
        .arg(WINDOW_SECS)
        .arg("NX")
        .ignore()
        .query_async(redis)
        .await?;
    Ok(count <= limit)
}
