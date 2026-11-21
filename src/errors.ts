export type AnalysisErrorKind =
  | "not-found"
  | "unreadable"
  | "empty"
  | "not-pe"
  | "malformed"
  | "unsupported"
  | "invalid-argument"
  | "internal";

export class AnalysisError extends Error {
  readonly kind: AnalysisErrorKind;
  readonly detail: string;

  constructor(kind: AnalysisErrorKind, message: string, detail = "") {
    super(message);
    this.name = "AnalysisError";
    this.kind = kind;
    this.detail = detail;
  }
}

export const asAnalysisError = (error: unknown): AnalysisError =>
  error instanceof AnalysisError
    ? error
    : new AnalysisError("internal", error instanceof Error ? error.message : String(error));
