import type { NativeAttemptSummary, NativeEffectiveAttemptLimits } from "../../native/index.cjs";
import type {
  AttemptDenialReason,
  AttemptLimitScope,
  AttemptOutcome,
  AttemptSummary,
  EffectiveAttemptLimits,
} from "../types.js";

/** Converts the native caps in effect, leaving out the unset ones. */
export function toEffectiveAttemptLimits(
  native: NativeEffectiveAttemptLimits,
): EffectiveAttemptLimits {
  const { extraHttpAttempts, extraHttpScope, connectAttempts, connectScope } = native;
  return {
    ...(extraHttpAttempts != null && { extraHttpAttempts }),
    ...(extraHttpScope != null && { extraHttpScope: extraHttpScope as AttemptLimitScope }),
    ...(connectAttempts != null && { connectAttempts }),
    ...(connectScope != null && { connectScope: connectScope as AttemptLimitScope }),
  };
}

/** Converts a native attempt summary, leaving out what is unset. */
export function toAttemptSummary(native: NativeAttemptSummary): AttemptSummary {
  const { outcome, denialReason, effectiveLimits, ...counts } = native;
  return {
    ...counts,
    outcome: outcome as AttemptOutcome,
    ...(denialReason != null && { denialReason: denialReason as AttemptDenialReason }),
    ...(effectiveLimits != null && {
      effectiveLimits: toEffectiveAttemptLimits(effectiveLimits),
    }),
  };
}
