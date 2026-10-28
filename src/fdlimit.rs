//! The process's file-descriptor budget.
//!
//! Both shipped binaries size fixed pools by design, and every unit in them is
//! an fd: the server runs one UDP socket per session (8192 slots) plus one TCP
//! socket per relayed flow (16384), the client accepts up to 8192 SOCKS relays
//! and holds 4032 UDP associations. A stock unix soft `RLIMIT_NOFILE` is far
//! below either figure (1024 on a Linux login session, 256 on macOS), and
//! `EMFILE` arrives long before the documented capacity does — *silently*:
//! session creation and the SOCKS accept loop treat the error as transient and
//! keep serving, so the proxy looks healthy while it refuses new work at a
//! fraction of its limits.
//!
//! [`raise_nofile_limit`] raises only the *soft* limit (no privilege needed —
//! only the hard ceiling needs `CAP_SYS_RESOURCE`, and that is left untouched)
//! and then reports the limit actually in force, so the startup log answers
//! "how many more fds may this process open?" without a `/proc` round trip.

use std::io;

/// A `RLIMIT_NOFILE` reading: the soft limit in force, the hard ceiling above
/// it, and the soft limit as it stood before [`raise_nofile_limit`] touched it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoFileLimit {
    /// Soft limit in force now.
    pub soft: u64,
    /// Hard ceiling. Never raised here: that needs `CAP_SYS_RESOURCE`.
    pub hard: u64,
    /// Soft limit before the raise, for the log line.
    pub original_soft: u64,
}

impl NoFileLimit {
    /// Fds still missing between the limit in force and `want` (0 when the
    /// limit already covers the designed capacity).
    pub fn shortfall(&self, want: u64) -> u64 {
        want.saturating_sub(self.soft)
    }

    /// The startup log line: what is in force, and — when it is short of the
    /// designed capacity — the exact remediation, because a soft limit that is
    /// too low is an operator action, not a code path.
    pub fn describe(&self, want: u64) -> String {
        let short = self.shortfall(want);
        if short == 0 {
            return format!(
                "nofile: soft {} (hard {}, raised from {}); the designed capacity needs {want} \
                 fd(s)",
                self.soft, self.hard, self.original_soft
            );
        }
        format!(
            "nofile: soft {} (hard {}, raised from {}) is {short} fd(s) below the {want} fd(s) \
             the designed capacity needs: new sessions and relays fail with EMFILE once about \
             {} fds are open. Raise it for the process (`ulimit -n {want}`) or for the service \
             (systemd `LimitNOFILE={want}`, Docker `--ulimit nofile={want}:{want}`)",
            self.soft, self.hard, self.original_soft, self.soft
        )
    }
}

/// Read the current `RLIMIT_NOFILE`.
pub fn nofile_limit() -> io::Result<NoFileLimit> {
    let (soft, hard) = sys::get()?;
    Ok(NoFileLimit {
        soft,
        hard,
        original_soft: soft,
    })
}

/// Raise the soft `RLIMIT_NOFILE` toward `want`, capped by the hard limit, and
/// return the limit in force afterwards.
///
/// Best effort by construction: the soft limit only ever moves *up* (a caller
/// with a small `want` cannot shrink what the environment granted), a failed
/// `setrlimit` leaves the previous limit in place instead of failing startup,
/// and the returned struct is always a fresh reading, so the caller logs the
/// truth rather than the intent.
pub fn raise_nofile_limit(want: u64) -> io::Result<NoFileLimit> {
    let (original_soft, hard) = sys::get()?;
    let target = want.min(hard).max(original_soft);
    if target > original_soft {
        // `EPERM` here means a container/seccomp policy denies the raise; the
        // re-read below reports what is actually in force and the caller warns.
        let _ = sys::set(target, hard);
    }
    let (soft, hard) = sys::get()?;
    Ok(NoFileLimit {
        soft,
        hard,
        original_soft,
    })
}

#[cfg(unix)]
mod sys {
    use std::io;

    use nix::sys::resource::{Resource, getrlimit, setrlimit};

    pub(super) fn get() -> io::Result<(u64, u64)> {
        let (soft, hard) = getrlimit(Resource::RLIMIT_NOFILE).map_err(io::Error::from)?;
        Ok((soft, hard))
    }

    pub(super) fn set(soft: u64, hard: u64) -> io::Result<()> {
        setrlimit(Resource::RLIMIT_NOFILE, soft as _, hard as _).map_err(io::Error::from)
    }
}

#[cfg(not(unix))]
mod sys {
    use std::io;

    /// `RLIMIT_NOFILE` is a unix resource limit; the Windows builds of this
    /// crate do not ship a server/client pair, so there is nothing to raise.
    fn unsupported() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "RLIMIT_NOFILE is a unix limit; no fd budget to raise here",
        )
    }

    pub(super) fn get() -> io::Result<(u64, u64)> {
        Err(unsupported())
    }

    pub(super) fn set(_soft: u64, _hard: u64) -> io::Result<()> {
        Err(unsupported())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortfall_is_zero_once_the_limit_covers_the_capacity() {
        let lim = NoFileLimit {
            soft: 24_840,
            hard: 24_840,
            original_soft: 1024,
        };
        assert_eq!(lim.shortfall(24_840), 0);
        assert_eq!(lim.shortfall(25_000), 160);

        let tight = NoFileLimit {
            soft: 1024,
            hard: 1024,
            original_soft: 1024,
        };
        assert_eq!(tight.shortfall(24_840), 23_816);
    }

    #[test]
    fn describe_names_the_numbers_and_the_remediation_only_when_short() {
        let ok = NoFileLimit {
            soft: 65_536,
            hard: 65_536,
            original_soft: 1024,
        };
        let line = ok.describe(24_840);
        assert!(line.contains("65536"), "{line}");
        assert!(line.contains("24840"), "{line}");
        assert!(
            !line.contains("ulimit"),
            "an adequate limit needs no fix: {line}"
        );

        let short = NoFileLimit {
            soft: 1024,
            hard: 4096,
            original_soft: 1024,
        };
        let line = short.describe(24_840);
        assert!(line.contains("23816"), "{line}");
        assert!(line.contains("ulimit -n 24840"), "{line}");
        assert!(line.contains("LimitNOFILE=24840"), "{line}");
    }

    #[test]
    fn raise_never_lowers_and_lands_on_the_hard_ceiling() {
        let before = nofile_limit().expect("reading RLIMIT_NOFILE");
        // Above any realistic hard limit: the soft limit must stop at `hard`.
        let raised = raise_nofile_limit(u64::MAX / 2).expect("raising RLIMIT_NOFILE");
        assert_eq!(
            raised.original_soft, before.soft,
            "original reading is kept"
        );
        assert_eq!(raised.soft, raised.hard, "capped by the hard limit");
        assert!(
            raised.soft >= before.soft,
            "the soft limit never moves down"
        );
        assert_eq!(raised.shortfall(raised.hard + 1), 1);

        // A smaller `want` from here must not shrink what is already granted.
        let again = raise_nofile_limit(1).expect("re-reading RLIMIT_NOFILE");
        assert_eq!(again.soft, raised.soft, "raise is monotonic");
        assert_eq!(again.original_soft, raised.soft);
        assert_eq!(again.shortfall(again.soft), 0);
    }
}
