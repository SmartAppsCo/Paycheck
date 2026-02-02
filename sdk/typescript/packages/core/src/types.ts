/**
 * Device type for license activation
 */
export type DeviceType = 'uuid' | 'machine';

/**
 * Storage adapter interface for custom storage implementations
 */
export interface StorageAdapter {
  get(key: string): string | null | Promise<string | null>;
  set(key: string, value: string): void | Promise<void>;
  remove(key: string): void | Promise<void>;
}

/**
 * Client configuration options
 */
export interface ClientConfig {
  /** Project UUID from Paycheck dashboard */
  projectId: string;
  /** Paycheck server URL (default: "https://api.paycheck.dev") */
  baseUrl?: string;
  /** Custom storage adapter (default: localStorage) */
  storage?: StorageAdapter;
  /** Auto-refresh expired tokens (default: true) */
  autoRefresh?: boolean;
  /** Override device ID (default: auto-generated) */
  deviceId?: string;
  /** Device type (default: "uuid") */
  deviceType?: DeviceType;
}

/**
 * Parameters for starting a checkout session.
 *
 * Note: Price and variant info are configured in the product settings on Paycheck,
 * so you don't need to send them here - just the product ID.
 * Redirect URL is configured per-project in the Paycheck dashboard, not per-request.
 */
export interface CheckoutParams {
  /** Product UUID - Paycheck looks up pricing from product config */
  productId: string;
  /** Payment provider (auto-detected if not specified) */
  provider?: 'stripe' | 'lemonsqueezy';
  /** Your customer identifier (flows through to license) */
  customerId?: string;
}

/**
 * Result from starting a checkout session
 */
export interface CheckoutResult {
  /** URL to redirect user to */
  checkoutUrl: string;
  /** Payment session ID */
  sessionId: string;
}

/**
 * Result from parsing callback URL.
 *
 * Note: No JWT is returned from callback - the user must call activateWithCode()
 * with their device info to get a JWT. This separates purchase from activation.
 */
export interface CallbackResult {
  /** Payment status */
  status: 'success' | 'pending';
  /** Short-lived activation code (PREFIX-XXXX-XXXX format, 30 min TTL) */
  code?: string;
}

/**
 * Optional device info for activation
 */
export interface DeviceInfo {
  /** Human-readable device name */
  deviceName?: string;
}

/**
 * Result from license activation
 */
export interface ActivationResult {
  /** JWT for this device */
  token: string;
  /** When license expires (null = perpetual) */
  licenseExp: number | null;
  /** When version access expires (null = all versions) */
  updatesExp: number | null;
  /** Product tier */
  tier: string;
  /** Enabled features */
  features: string[];
  /** Short-lived activation code for future activations (PREFIX-XXXX-XXXX format) */
  activationCode: string;
  /** When activation code expires (30 minutes from creation) */
  activationCodeExpiresAt: number;
}

/**
 * Decoded JWT claims.
 *
 * **Important: Three Expiration-Related Claims**
 *
 * - `exp`: JWT expiration (~1 hour). Controls token freshness and revocation propagation.
 *   Expired JWTs can still be refreshed via `/refresh` if the license is valid.
 *   The SDK uses this internally for auto-refresh. NOT for license validity checks.
 *
 * - `license_exp`: License expiration (business logic). Controls when the user's access ends.
 *   Can be `null` for perpetual licenses. This is what you check for "is user licensed?"
 *
 * - `updates_exp`: Version access expiration. Controls which versions the user can use.
 *   Compare against your app's build timestamp. Can be `null` for lifetime updates.
 *
 * @see https://github.com/anthropics/paycheck/blob/main/sdk/CORE.md for full documentation
 */
export interface LicenseClaims {
  // Standard JWT claims
  /** Issuer ("paycheck") */
  iss: string;
  /** Subject (license_id) */
  sub: string;
  /** Audience (project name, for debugging - not verified) */
  aud: string;
  /** JWT ID (unique per device activation) */
  jti: string;
  /** Issued at (Unix timestamp) */
  iat: number;
  /**
   * JWT expiration (Unix timestamp, ~1 hour from issuance).
   *
   * This is NOT the license expiration - see `license_exp` for that.
   * Used for token freshness and revocation propagation.
   * Expired JWTs can still be refreshed if the underlying license is valid.
   */
  exp: number;

  // Paycheck claims
  /**
   * When license ACCESS ends (Unix timestamp, or null = perpetual/never expires).
   *
   * This is the business logic expiration - check this for "is user licensed?"
   * Different from `exp` which is just JWT validity (~1 hour).
   */
  license_exp: number | null;
  /**
   * When VERSION ACCESS ends (Unix timestamp, or null = all versions covered).
   *
   * Compare against your app's build/release timestamp to determine if the user
   * can access this version. Use `coversVersion(timestamp)` helper.
   */
  updates_exp: number | null;
  /** Product tier (e.g., "free", "pro", "enterprise") */
  tier: string;
  /** Enabled feature flags for hasFeature() checks */
  features: string[];
  /** Device identifier (verified against current device to prevent token theft) */
  device_id: string;
  /** Device type */
  device_type: DeviceType;
  /** Product UUID */
  product_id: string;
}

/**
 * Result from online validation
 */
export interface ValidateResult {
  /** Whether the license is valid */
  valid: boolean;
  /** When license expires (if valid) */
  licenseExp?: number | null;
  /** When version access expires (if valid) */
  updatesExp?: number | null;
}

/**
 * Device info from license info endpoint
 */
export interface LicenseDeviceInfo {
  deviceId: string;
  deviceType: DeviceType;
  name: string | null;
  activatedAt: number;
  lastSeenAt: number;
}

/**
 * Full license information
 */
export interface LicenseInfo {
  /** License status */
  status: 'active' | 'expired' | 'revoked';
  /** When license was created */
  createdAt: number;
  /** When license expires (null = perpetual) */
  expiresAt: number | null;
  /** When version access expires */
  updatesExpiresAt: number | null;
  /** Number of times license has been activated */
  activationCount: number;
  /** Maximum activations allowed (null = unlimited) */
  activationLimit: number | null;
  /** Current number of active devices */
  deviceCount: number;
  /** Maximum devices allowed (null = unlimited) */
  deviceLimit: number | null;
  /** Active devices */
  devices: LicenseDeviceInfo[];
}

/**
 * Result from device deactivation
 */
export interface DeactivateResult {
  /** Whether deactivation was successful */
  deactivated: boolean;
  /** Number of remaining active devices */
  remainingDevices: number;
}

/**
 * Result from requesting an activation code
 */
export interface RequestCodeResult {
  /** Success message from the server */
  message: string;
}

/**
 * Error codes for Paycheck errors
 */
export type PaycheckErrorCode =
  | 'NO_TOKEN'
  | 'TOKEN_EXPIRED'
  | 'LICENSE_EXPIRED'
  | 'LICENSE_REVOKED'
  | 'DEVICE_LIMIT_REACHED'
  | 'ACTIVATION_LIMIT_REACHED'
  | 'INVALID_LICENSE_KEY'
  | 'INVALID_CODE'
  | 'NETWORK_ERROR'
  | 'VALIDATION_ERROR'
  | 'DUPLICATE_REQUEST';

/**
 * Paycheck SDK error
 */
export class PaycheckError extends Error {
  constructor(
    public code: PaycheckErrorCode,
    message: string,
    public statusCode?: number
  ) {
    super(message);
    this.name = 'PaycheckError';
  }
}

// ==================== Feedback Types ====================

/**
 * Feedback type classification
 */
export type FeedbackType = 'bug' | 'feature' | 'question' | 'other';

/**
 * Priority level for feedback
 */
export type Priority = 'low' | 'medium' | 'high';

/**
 * Options for submitting feedback
 */
export interface FeedbackOptions {
  /** The feedback message (required) */
  message: string;
  /** User's email for follow-up */
  email?: string;
  /** Feedback type classification */
  type?: FeedbackType;
  /** Priority level */
  priority?: Priority;
  /** App version */
  appVersion?: string;
  /** Operating system info */
  os?: string;
  /** Arbitrary metadata */
  metadata?: Record<string, unknown>;
}

// ==================== Crash Reporting Types ====================

/**
 * Stack frame in a crash report
 */
export interface StackFrame {
  /** Source file path */
  file?: string;
  /** Function name */
  function?: string;
  /** Line number */
  line?: number;
  /** Column number */
  column?: number;
}

/**
 * Breadcrumb for crash context
 */
export interface Breadcrumb {
  /** When this event occurred (Unix timestamp in ms) */
  timestamp: number;
  /** Category of event (ui, http, console, navigation) */
  category?: string;
  /** Event description */
  message: string;
}

/**
 * Options for reporting a crash
 */
export interface CrashOptions {
  /** Error type/class (required) */
  errorType: string;
  /** Error message (required) */
  errorMessage: string;
  /** Parsed stack trace */
  stackTrace?: StackFrame[];
  /** Deduplication fingerprint (auto-generated if not provided) */
  fingerprint?: string;
  /** User's email for follow-up */
  userEmail?: string;
  /** App version */
  appVersion?: string;
  /** Operating system info */
  os?: string;
  /** Arbitrary metadata */
  metadata?: Record<string, unknown>;
  /** Event breadcrumbs leading up to crash */
  breadcrumbs?: Breadcrumb[];
}
