//! Client authentication (token) and auth-phase deadlines.
use super::*;

/// Wall-clock budget for the handshake wait of a connection that holds
/// one of the [`MAX_UNAUTH_CONNECTIONS`] slots. The token exchange gets its
/// own fresh [`AUTH_TIMEOUT`] deadline re-armed after the handshake completes,
/// so a slow handshake cannot consume the authentication budget and fail a
/// healthy client with `unauthorized`. Without re-arming, one 5 s deadline for
/// both phases let handshake latency starve the token read.
pub(crate) const PRE_AUTH_TIMEOUT: Duration = Duration::from_secs(5);
/// Fresh budget for the token exchange (`accept_uni` + token read) once the
/// handshake has completed. Re-armed from handshake completion — no extra RTT,
/// only a deadline re-arm — and the pre-auth slot stays held until
/// `authenticate` returns.
pub(crate) const AUTH_TIMEOUT: Duration = Duration::from_secs(5);
/// Budget for completing the QUIC handshake when **no** pre-auth slot is held
/// (`auth_token` unset, so there is no memory budget to defend). With
/// authentication enabled, [`PRE_AUTH_TIMEOUT`] bounds the handshake instead.
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// One-way token authentication: the client opens a uni stream and writes the
/// configured shared secret before any other traffic. Empty = disabled.
pub(crate) const AUTH_MAX_BYTES: usize = 256;

pub(crate) async fn authenticate(
    conn: &quinn::Connection,
    expected: &[u8],
    deadline: tokio::time::Instant,
) -> Result<()> {
    if expected.is_empty() {
        return Ok(());
    }
    let got = tokio::time::timeout_at(deadline, async {
        let mut uni = conn.accept_uni().await?;
        uni.read_to_end(AUTH_MAX_BYTES)
            .await
            .map_err(anyhow::Error::from)
    })
    .await
    .context("auth timeout")??;
    if !ct_eq(&got, expected) {
        anyhow::bail!("auth token mismatch");
    }
    Ok(())
}

/// Constant-time token compare that never short-circuits on the first
/// mismatching byte: mismatched lengths contribute a single flag and the loop
/// runs over `max(len)` bytes with zero padding.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    // Length inequality is folded in as a 0/1 flag: casting `(len_a ^ len_b)`
    // to u8 could wrap to 0 for lengths 256 apart (e.g. 256 vs 0) and compare
    // equal if every common byte matched. Only *whether* the lengths differ
    // is revealed, never the token bytes.
    let mut diff = if a.len() == b.len() { 0u8 } else { 1u8 };
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= x ^ y;
    }
    diff == 0
}
