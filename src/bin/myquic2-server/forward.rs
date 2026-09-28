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
            }
            // No destination memo for an IP target: `resolve_pin` — the memo's
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
            // Filtered first address or uncached: scan the full cached set
            // synchronously so this reader never awaits DNS on a cache hit.
            // Only a set that is not synchronously visible (contended lock or
            // expired entry) reaches the resolving send below.
            _ => {
                let full = lookup_cached_all_fast_with_ttl(h, p);
                let usable = full.as_ref().and_then(|(v, life)| {
                    v.iter()
                        .copied()
                        .find(|a| allow_private || is_global_ip_cached(a.ip()))
                        .map(|a| (a, *life))
                });
                match usable {
                    Some((d2, life)) => {
                        let sock =
                            get_or_create_sess(ss, cd, conn_id, s, Some((h, p, d2, life))).await?;
                        remember_dst(ss, s, d2);
                        udp_try_send(&sock, map_for_dual(d2), payload);
                        Some((d2, life))
                    }
                    None if full.is_some() => {
                        dgram_drops::bump(&dgram_drops::REFUSED);
                        None
                    }
                    None => {
                        match dns_inflight_status(h, p) {
                            // Single-flight: the packet that spawned the
                            // resolver is delivered by that task, this one has
                            // no owner. Counted so the loss shows up in the
                            // 60 s budget line instead of being invisible.
                            DnsInflight::Inflight => {
                                dgram_drops::bump(&dgram_drops::DNS_INFLIGHT);
                                return None;
                            }
                            // Contended shard mutex: nothing is known, so this
                            // is not an inflight drop. Count it apart and fall
                            // through to the spawn path below, not a return.
                            DnsInflight::Contended => {
                                dgram_drops::bump(&dgram_drops::DNS_CONTENTION);
                            }
                            DnsInflight::Absent => {}
                        }
                        // Fail fast on the slow-path budget with exactly one bump
                        // per refusal: `try_acquire_owned` is the only check,
                        // so a permit freed between a probe and the acquire is
                        // still usable and an exhausted budget is counted once
                        // (a separate `available_permits() == 0` pre-check both
                        // dropped usable permits and double-counted the race).
                        let permit = match dns_slow_path_limiter().clone().try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                dgram_drops::bump(&dgram_drops::SESSION_FULL);
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
                                    None => {
                                        dgram_drops::bump(&dgram_drops::REFUSED);
                                        return;
                                    }
                                },
                                Err(e) => {
                                    if is_dns_contended(&e) {
                                        dgram_drops::bump(&dgram_drops::DNS_CONTENTION);
                                    } else {
                                        dgram_drops::bump(&dgram_drops::REFUSED);
                                    }
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
                                Some(v) => v,
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
                                    return;
                                }
                            };
                            remember_dst(&ss, s, dst);
                            udp_try_send(&sock, map_for_dual(dst), payload);
                        });
                        // The resolution happens in the spawned task above (it awaits),
                        // so this datagram is delivered there and there is no pin for
                        // the caller to record yet. The next datagram for this session
                        // finds the answer in the DNS cache -- or, once one datagram has
                        // completed this path, in the session's own destination memo.
                        None
                    }
                }
            }
        },
    }
}
