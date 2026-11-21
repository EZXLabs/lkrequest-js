import type { NativeTrustAnchorAttempt } from "../../native/index.cjs";
import type { TrustAnchorInfo } from "../types.js";

/** Nests the native attempts, the latest first, into the public shape without absent fields. */
export function toTrustAnchorInfo(
  attempts: readonly NativeTrustAnchorAttempt[],
): TrustAnchorInfo | undefined {
  const [latest, ...earlier] = attempts;
  if (latest === undefined) return undefined;
  const { verifiedAnchor, failure, ...rest } = latest;
  const previous = toTrustAnchorInfo(earlier);
  return {
    ...rest,
    ...(verifiedAnchor != null && { verifiedAnchor }),
    ...(failure != null && { failure }),
    ...(previous !== undefined && { previousAttempt: previous }),
  };
}
