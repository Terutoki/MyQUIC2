//! Datagram forwarding to the target.
use super::*;

/// Relay one datagram to its target. `Some((dst, life_ms))` is the address
/// actually used plus the remaining life of the cache entry it came from, so the
/// caller's own pin cannot outlive it (see [`pin_life_ms`]); `None` means the
/// datagram was dropped (SSRF filter, negative cache, DNS overload, or no
/// session slot).
pub(crate) async fn forward_server_dgram(
    ss: &SessTable,
    cd: &quinn::Connection,
    conn_id: usize,
    s: u32,
    addr: TargetAddrRef<'_>,
    payload: Bytes,
    allow_private: bool,
) -> Option<(SocketAddr, u64)> {
    match addr {
        TargetAddrRef::Ip(dst) => {
            if !allow_private && !is_global_ip_cached(dst.ip()) {
                dgram_drops::bump(&dgram_drops::REFUSED);
                return None;
            } // No destination memo for an IP target: `resolve_pin` — the memo's
              // only reader on the datagram path — consults it for domain targets
              // exclusively (an IP target's address is already in the datagram, so
              // it takes the `TargetAddrRef::Ip` arm and never reaches the memo).
              // An entry keyed `("", port)` *is* readable in principle — see
              // `session_dest_memo_distinguishes_ip_and_domain_targets`, which
              // stores and reads exactly that — but nothing on the datagram path
              // would ever ask for it, because the wire decoder refuses a
              // zero-length domain, so the lookup that could match it is
              // unreachable. Storing it was a shard write lock plus a 72-byte memo
              // write per datagram that nothing could read back.
            let sock = get_or_create_sess(ss, cd, conn_id, s, None).await?;
            remember_dst(ss, s, dst);
            udp_try_send(&sock, map_for_dual(dst), payload);
            // An IP target has no DNS entry behind it: the pin's own TTL is the
            // only bound there is.
            Some((dst, DNS_CACHE_TTL_MS))
        }
        TargetAddrRef::Domain(h, p) => match lookup_cached_fast_with_ttl(h, p) {
            (CachedLookup::Negative, _) => {
                dgram_drops::bump(&dgram_drops::REFUSED);
                None
            }
            (CachedLookup::Addr(dst), life) if allow_private || is_global_ip_cached(dst.ip()) => {
                let sock = get_or_create_sess(ss, cd, conn_id, s, Some((h, p, dst, life))).await?;
                remember_dst(ss, s, dst);
                udp_try_send(&sock, map_for_dual(dst), payload);
                Some((dst, life))
            }
            // Uncached, or a memoized first address the SSRF filter rejects.
            // Spawn a waiter that this datagram is delivered by once the
            // resolution completes: moka coalesces every concurrent waiter for
            // the name into one upstream query, and each waiter delivers its
            // own payload — no queue, no in-flight probe, no stranded
            // followers. The budget gate stays fail-fast exactly as before.
            _ => {
                let permit = match dns_slow_path_limiter().clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        dgram_drops::bump(&dgram_drops::DNS_BUDGET);
                        return None;
                    }
                };
                let ss = ss.clone();
                let cd = cd.clone();
                let host = h.to_owned();
                tokio::spawn(async move {
                    let _permit = permit;
                    let dst = match resolve_all_cached(&host, p).await {
                        Ok(v) => match v
                            .iter()
                            .copied()
                            .find(|a| allow_private || is_global_ip(a.ip()))
                        {
                            Some(v) => v,
                            // Every record filtered: policy refusal, counted
                            // like the inline negative arm.
                            None => {
                                dgram_drops::bump(&dgram_drops::REFUSED);
                                return;
                            }
                        },
                        Err(_) => {
                            dgram_drops::bump(&dgram_drops::REFUSED);
                            return;
                        }
                    };
                    let sock = match get_or_create_sess(
                        &ss,
                        &cd,
                        conn_id,
                        s,
                        Some((&host, p, dst, DNS_CACHE_TTL_MS)),
                    )
                    .await
                    {
                        Some(v) => Some(v),
                        // `get_or_create_sess` already bumps the
                        // specific budget counter for every resource
                        // refusal (FAIR_SHARE / SESSION_FULL /
                        // SESS_CREATE_FAILED); the only silent None is
                        // the no-DATAGRAM path, counted here so the
                        // spawned datagram never vanishes from the 60 s
                        // budget line. Guarded (not unconditional) so a
                        // refusal is never bumped twice.
                        None => {
                            if cd.max_datagram_size().is_none() {
                                dgram_drops::bump(&dgram_drops::SESS_CREATE_FAILED);
                            }
                            None
                        }
                    };
                    if let Some(sock) = sock {
                        remember_dst(&ss, s, dst);
                        udp_try_send(&sock, map_for_dual(dst), payload);
                    }
                });
                // The resolution happens in the spawned task above (it awaits),
                // so this datagram is delivered there and there is no pin for
                // the caller to record yet. The next datagram for this session
                // finds the answer in the DNS cache -- or, once one datagram has
                // completed this path, in the session's own destination memo.
                None
            }
        },
    }
}
