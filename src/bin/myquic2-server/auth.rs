//! Client authentication (token) and auth-phase deadlines.
use super::*;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Wall-clock budget for the handshake of a connection that holds one of the
/// [`MAX_UNAUTH_CONNECTIONS`] slots. The token exchange gets its own fresh
/// [`AUTH_TIMEOUT`] deadline re-armed when the connection is accepted, so a slow
/// handshake cannot consume the authentication budget and fail a healthy client
/// with `unauthorized`.
///
/// Since the accept path starts `authenticate` on the 0.5-RTT `Connection`
/// *without* awaiting the handshake, this budget no longer gates the token read
/// at all: it bounds the detached handshake monitor (which closes a handshake
/// that never settles), while the token exchange is bounded by [`AUTH_TIMEOUT`]
/// in parallel. Without the re-arm, one 5 s deadline for both phases let
/// handshake latency starve the token read.
pub(crate) const PRE_AUTH_TIMEOUT: Duration = Duration::from_secs(5);
/// Fresh budget for the token exchange (`accept_uni` + token read), armed when
/// the connection is accepted — i.e. **before** the handshake completes on a
/// resumed connection, so 0-RTT early-data tokens are accepted while the
/// handshake is still in flight. The pre-auth slot stays held until
/// `authenticate` returns.
pub(crate) const AUTH_TIMEOUT: Duration = Duration::from_secs(5);
/// Budget for completing the QUIC handshake when **no** pre-auth slot is held
/// (`auth_token` unset, so there is no memory budget to defend). With
/// authentication enabled, [`PRE_AUTH_TIMEOUT`] bounds the handshake instead.
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Upper bound on the client uni streams `authenticate` will look at before
/// giving up.
///
/// A 0-RTT-rejected dial legitimately produces two: the early token stream
/// (reset/discarded) and the 1-RTT re-send. The pre-auth uni credit is
/// [`SERVER_UNI_STREAM_CREDIT`], so a peer cannot hold more than that many open
/// at once; streams may still be completed and re-opened over a 5 s window, so
/// this bound keeps a hostile peer from parking a permanent stream-accept loop
/// on the auth path. Sixteen is several times what a real client can need.
const MAX_AUTH_STREAMS: usize = 16;

/// Read the auth token from the client's first complete uni stream and compare
/// it in constant time.
///
/// The token stream is the first client→server uni stream in the protocol, but
/// the connection may still be handshaking while this runs (0-RTT): on a
/// resumed dial the client writes the token in its first flight, and this
/// function accepts it **before** the handshake completes.
///
/// Early data may be discarded by the TLS layer (no resumption state, e.g. a
/// server restart) even though the QUIC connection itself survives: quinn then
/// resets the early streams and reports the read as an error. The client
/// re-sends the token on a fresh 1-RTT stream as soon as the handshake
/// completes, so a reset/failed read is **not** an auth failure — keep
/// `accept_uni`ing within the deadline and authenticate the first complete
/// token that matches. Only a complete stream with the wrong bytes is a
/// mismatch (fail closed; the token is written as the stream's whole content).
///
/// `deadline` bounds the whole exchange: `accept_uni`, every tolerated reset,
/// and the token read all share it, so a peer cannot extend the pre-auth window
/// by opening streams.
pub(crate) async fn authenticate(
    conn: &quinn::Connection,
    expected: &[u8],
    deadline: tokio::time::Instant,
) -> Result<()> {
    if expected.is_empty() {
        return Ok(());
    }
    for _ in 0..MAX_AUTH_STREAMS {
        let read = tokio::time::timeout_at(deadline, async {
            let mut uni = conn.accept_uni().await?;
            uni.read_to_end(AUTH_TOKEN_MAX_BYTES)
                .await
                .map_err(anyhow::Error::from)
        })
        .await;
        let got = match read {
            Ok(Ok(got)) => got,
            // A reset stream, a read that could not complete, or an early-data
            // rejection: not a credential verdict. The 1-RTT re-send may still
            // arrive, so keep watching until the deadline.
            Ok(Err(e)) => {
                tracing::debug!("auth stream unusable ({e:#}); waiting for another");
                continue;
            }
            Err(_) => anyhow::bail!("auth timeout"),
        };
        // Wipe the received bytes on drop: a bearer secret should not linger in
        // a freed heap block.
        let got = Zeroizing::new(got);
        // Constant-time per-byte compare; a length mismatch folds into the
        // result, so only *whether* the lengths differ is revealed, never the
        // token bytes.
        if !bool::from(got.ct_eq(expected)) {
            anyhow::bail!("auth token mismatch");
        }
        return Ok(());
    }
    anyhow::bail!("too many auth streams without a complete token")
}
