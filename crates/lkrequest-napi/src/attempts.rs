//! Attempt limits and summaries: caps on the extra HTTP submissions and the connections one
//! request may start, at client, session or request scope, and what each request did.

use lkrequest::{AttemptLimits, AttemptSummary, EffectiveAttemptLimits};
use napi_derive::napi;

use crate::error::invalid_arg;
use crate::types::usize_from;

/// Caps on one request; an unset field inherits the scope above.
#[napi(object, object_to_js = false)]
pub struct NativeAttemptLimits {
    /// HTTP submissions beyond the first and the redirects: retries and recoveries.
    pub extra_http_attempts: Option<f64>,
    /// TCP and QUIC connections the request may start.
    pub connect_attempts: Option<f64>,
}

/// The limits in effect, each with the scope (`client`, `session`, `request`) that set it.
#[napi(object, object_from_js = false)]
pub struct NativeEffectiveAttemptLimits {
    /// Cap on extra HTTP submissions, absent when there is none.
    pub extra_http_attempts: Option<f64>,
    /// Scope that set `extra_http_attempts`.
    pub extra_http_scope: Option<String>,
    /// Cap on connection starts, absent when there is none.
    pub connect_attempts: Option<f64>,
    /// Scope that set `connect_attempts`.
    pub connect_scope: Option<String>,
}

/// What one request did, as upstream counted it.
#[napi(object, object_from_js = false)]
pub struct NativeAttemptSummary {
    /// Whether the request began executing.
    pub started: bool,
    /// HTTP submissions: the first, redirects, retries and recoveries.
    pub http_submissions: f64,
    /// Submissions charged against the extra HTTP cap.
    pub extra_http_submissions: f64,
    /// Redirects followed.
    pub redirects: f64,
    /// Recoveries decided, including any cancelled before they went out.
    pub recoveries: f64,
    /// TCP and QUIC connections started, failed ones and race losers included.
    pub connect_initiations: f64,
    /// Whether the connection cap held back an optional background probe.
    pub probe_suppressed_by_connect_limit: bool,
    /// `pending`, `active`, `succeeded`, `failed` or `cancelled`.
    pub outcome: String,
    /// Why a submission or recovery the request could have made was refused.
    pub denial_reason: Option<String>,
    /// The limits in effect, once the request started.
    pub effective_limits: Option<NativeEffectiveAttemptLimits>,
}

/// Turns the facade's caps into upstream's; `name` labels the option in errors.
pub(crate) fn limits(spec: &NativeAttemptLimits, name: &str) -> napi::Result<AttemptLimits> {
    let mut limits = AttemptLimits::default();
    if let Some(value) = spec.extra_http_attempts {
        limits = limits.with_extra_http_attempts(count(value, name, "extraHttpAttempts")?);
    }
    if let Some(value) = spec.connect_attempts {
        limits = limits.with_connect_attempts(count(value, name, "connectAttempts")?);
    }
    Ok(limits)
}

/// A cap from JavaScript, a non-negative integer.
fn count(value: f64, name: &str, field: &str) -> napi::Result<u64> {
    usize_from(value, &format!("{name}.{field}")).map(|count| count as u64)
}

/// The limits upstream resolved, or the error it refused a cap above an inherited one with.
pub(crate) fn effective(
    resolved: lkrequest::error::Result<EffectiveAttemptLimits>,
) -> napi::Result<NativeEffectiveAttemptLimits> {
    resolved
        .map(NativeEffectiveAttemptLimits::from)
        .map_err(|err| match err {
            lkrequest::error::Error::InvalidConfig(message) => invalid_arg(message),
            other => invalid_arg(other.to_string()),
        })
}

impl From<EffectiveAttemptLimits> for NativeEffectiveAttemptLimits {
    /// Copies the limits and names their scopes.
    fn from(limits: EffectiveAttemptLimits) -> Self {
        Self {
            extra_http_attempts: limits.extra_http_attempts().map(|limit| limit as f64),
            extra_http_scope: limits
                .extra_http_scope()
                .map(|scope| scope.as_str().to_owned()),
            connect_attempts: limits.connect_attempts().map(|limit| limit as f64),
            connect_scope: limits
                .connect_scope()
                .map(|scope| scope.as_str().to_owned()),
        }
    }
}

impl From<AttemptSummary> for NativeAttemptSummary {
    /// Copies the counts as JavaScript numbers.
    fn from(summary: AttemptSummary) -> Self {
        Self {
            started: summary.started(),
            http_submissions: summary.http_submissions() as f64,
            extra_http_submissions: summary.extra_http_submissions() as f64,
            redirects: summary.redirects() as f64,
            recoveries: summary.recoveries() as f64,
            connect_initiations: summary.connect_initiations() as f64,
            probe_suppressed_by_connect_limit: summary.probe_suppressed_by_connect_limit(),
            outcome: summary.outcome().as_str().to_owned(),
            denial_reason: summary
                .denial_reason()
                .map(|reason| reason.as_str().to_owned()),
            effective_limits: summary
                .effective_limits()
                .map(NativeEffectiveAttemptLimits::from),
        }
    }
}
