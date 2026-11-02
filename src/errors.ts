export class IsIPsafeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

export class APIError extends IsIPsafeError {
  readonly status: number;
  readonly body: unknown;

  constructor(message: string, status: number, body?: unknown) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

/** 401: the API key is missing or wrong. */
export class AuthenticationError extends APIError {}

/** 422: invalid input, or an allowlisted / private address was reported. */
export class ValidationError extends APIError {}

/** 429: too many requests. `retryAfter` is in seconds when the API sent it. */
export class RateLimitError extends APIError {
  readonly retryAfter: number | undefined;

  constructor(message: string, status: number, body?: unknown, retryAfter?: number) {
    super(message, status, body);
    this.retryAfter = retryAfter;
  }
}

/** The API could not be reached or did not answer in time. */
export class NetworkError extends IsIPsafeError {
  constructor(message: string, cause?: unknown) {
    super(message);
    if (cause !== undefined) Object.defineProperty(this, 'cause', { value: cause, configurable: true, writable: true });
  }
}
