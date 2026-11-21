import { X509Certificate } from "node:crypto";
import { native } from "./internal/native.js";
import { callNative, invalidConfig } from "./internal/native-error.js";

/**
 * The identity that names a root in a `TrustAnchorBinding` and in
 * `TrustAnchorInfo#verifiedAnchor`: 64 hex digits that hash the certificate's subject, public
 * key and name constraints. It is not a trust anchor ID; IDs are assigned by the CA.
 *
 * @param certificate - The root certificate, PEM or DER, as `X509Certificate` accepts it.
 * @throws TypeError (`ERR_LK_INVALID_CONFIG`) when it is not a certificate.
 */
export function trustAnchorIdentity(certificate: string | Uint8Array): string {
  let der: Uint8Array;
  try {
    der = new X509Certificate(certificate).raw;
  } catch (error) {
    throw invalidConfig("trustAnchorIdentity() needs a PEM or DER certificate", error);
  }
  return callNative(() => native.trustAnchorIdentity(der));
}
