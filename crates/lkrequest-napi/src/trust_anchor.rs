//! Trust Anchor Identifiers (draft-ietf-tls-trust-anchor-ids-06): the client options, the
//! identity that names a root, and the negotiation record that diagnostics and errors carry.
//!
//! Upstream validates the combination of options in `ClientBuilder::try_build`; this module only
//! parses them.

use lkrequest::client::ClientBuilder;
use lkrequest::lktls::error::TlsError;
use lkrequest::lktls::trust_anchor::anchor_identity;
use lkrequest::lktls::verify::certchain::parse_trust_anchor_from_der;
use lkrequest::{
    TrustAnchorAdvertisement, TrustAnchorBinding, TrustAnchorId, TrustAnchorInfo,
    TrustAnchorPolicy, TrustAnchorRecovery,
};
use napi_derive::napi;

use crate::bridge::buffer::JsBytes;
use crate::error::invalid_arg;

/// An ID assigned to a root the client trusts.
#[napi(object, object_to_js = false)]
pub struct NativeTrustAnchorBinding {
    /// The ID as hex: the contents of a DER RELATIVE-OID, 1 to 32 bytes.
    pub id: String,
    /// The root's identity, as `trustAnchorIdentity()` computes it.
    pub anchor_identity: String,
}

/// The TAI negotiation of one connection attempt. IDs are hex.
#[napi(object, object_from_js = false)]
pub struct NativeTrustAnchorAttempt {
    /// IDs the ClientHello advertised, in wire order.
    pub requested_ids: Vec<String>,
    /// IDs the server listed, in its order of preference; unverified unless `authenticated`.
    pub available_ids: Vec<String>,
    /// Whether the server said its certificate matches an advertised ID.
    pub matched_request: bool,
    /// Identity of the root the certificate chain was verified against.
    pub verified_anchor: Option<String>,
    /// Whether the certificate chain and the handshake were verified.
    pub authenticated: bool,
    /// Whether the server rejected Encrypted Client Hello.
    pub ech_rejected: bool,
    /// Whether this is a recovery connection that succeeded.
    pub recovered: bool,
    /// Why the attempt failed.
    pub failure: Option<String>,
    /// Whether the failure allows a recovery connection.
    pub recovery_eligible: bool,
}

/// The identity a binding names a root by, and that `verifiedAnchor` reports: a SHA-256 over the
/// certificate's subject, public key and name constraints, as lowercase hex.
#[napi(catch_unwind)]
pub fn trust_anchor_identity(
    #[napi(ts_arg_type = "Uint8Array")] der: JsBytes,
) -> napi::Result<String> {
    let anchor = parse_trust_anchor_from_der(&der.0)
        .map_err(|err| invalid_arg(format!("cannot read the certificate: {err}")))?;
    Ok(anchor_identity(&anchor))
}

/// Applies the TAI options: which IDs the ClientHello advertises, whether one recovery
/// connection is allowed, and IDs for roots the bundled metadata does not cover.
pub(crate) fn configure(
    mut builder: ClientBuilder,
    advertisement: Option<&str>,
    recovery: Option<&str>,
    bindings: Option<&[NativeTrustAnchorBinding]>,
) -> napi::Result<ClientBuilder> {
    let advertisement = match advertisement.unwrap_or("profile") {
        "profile" => TrustAnchorAdvertisement::Profile,
        "trusted" => TrustAnchorAdvertisement::Trusted,
        other => {
            return Err(invalid_arg(format!(
                "unknown tls.trustAnchorIds.advertisement {other:?}; expected profile or trusted"
            )));
        }
    };
    let recovery = match recovery.unwrap_or("disabled") {
        "disabled" => TrustAnchorRecovery::Disabled,
        "once" => TrustAnchorRecovery::Once,
        other => {
            return Err(invalid_arg(format!(
                "unknown tls.trustAnchorIds.recovery {other:?}; expected disabled or once"
            )));
        }
    };
    builder = builder.trust_anchor_policy(TrustAnchorPolicy {
        advertisement,
        recovery,
    });
    for binding in bindings.into_iter().flatten() {
        let id = TrustAnchorId::from_hex(&binding.id).map_err(|err| {
            invalid_arg(format!(
                "invalid trust anchor ID {:?}: {}",
                binding.id,
                reason(&err)
            ))
        })?;
        builder = builder.trust_anchor_binding(TrustAnchorBinding {
            anchor_identity: binding.anchor_identity.clone(),
            id,
        });
    }
    Ok(builder)
}

/// Upstream's negotiation record as a list of attempts, the latest first. A recovery connection
/// keeps the attempt it replaced as its `previous_attempt`.
pub(crate) fn attempts(
    info: Option<Box<TrustAnchorInfo>>,
) -> Option<Vec<NativeTrustAnchorAttempt>> {
    let mut attempts = Vec::new();
    let mut next = info;
    while let Some(info) = next {
        let TrustAnchorInfo {
            requested_ids,
            available_ids,
            matched_request,
            verified_anchor,
            authenticated,
            ech_rejected,
            recovered,
            failure,
            recovery_eligible,
            previous_attempt,
        } = *info;
        attempts.push(NativeTrustAnchorAttempt {
            requested_ids: hex(&requested_ids),
            available_ids: hex(&available_ids),
            matched_request,
            verified_anchor,
            authenticated,
            ech_rejected,
            recovered,
            failure,
            recovery_eligible,
        });
        next = previous_attempt;
    }
    (!attempts.is_empty()).then_some(attempts)
}

/// IDs as hex strings.
fn hex(ids: &[TrustAnchorId]) -> Vec<String> {
    ids.iter().map(TrustAnchorId::to_hex).collect()
}

/// Why upstream rejected an ID, without the TLS alert it reports it as.
fn reason(err: &TlsError) -> String {
    match err {
        TlsError::LocalAlert { message, .. } => message.clone(),
        other => other.to_string(),
    }
}
