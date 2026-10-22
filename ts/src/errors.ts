/**
 * Error codes. The first group is defined by the format spec
 * (spec/FORMAT.md section 10) and shared by every implementation; the rest
 * are raised by this library's runtime pieces.
 */
export type KeysealErrorCode =
  | "invalid_format"
  | "unsupported_format"
  | "env_mismatch"
  | "provider_mismatch"
  | "key_unavailable"
  | "mac_mismatch"
  | "decrypt_failed"
  | "rollback"
  | "not_found"
  | "bundle_changed"
  | "source_unavailable"
  | "invalid_argument";

export class KeysealError extends Error {
  readonly code: KeysealErrorCode;

  constructor(
    code: KeysealErrorCode,
    message: string,
    options?: { cause?: unknown }
  ) {
    super(message, options);
    this.name = "KeysealError";
    this.code = code;
  }
}

export function isKeysealError(
  err: unknown,
  code?: KeysealErrorCode
): err is KeysealError {
  return (
    err instanceof KeysealError && (code === undefined || err.code === code)
  );
}
