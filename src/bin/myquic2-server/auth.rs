//! Client authentication (token) and auth-phase deadlines.
use super::*;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

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
    // Wipe the received bytes on drop: a bearer secret should not linger in a
    // freed heap block.
    let got = Zeroizing::new(got);
    // Constant-time per-byte compare; a length mismatch folds into the result,
    // so only *whether* the lengths differ is revealed, never the token bytes.
    if !bool::from(got.ct_eq(expected)) {
        anyhow::bail!("auth token mismatch");
    }
    Ok(())
}
