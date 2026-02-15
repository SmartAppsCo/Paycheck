// Main client
export {
  Paycheck,
  createPaycheck,
  formatActivationCode,
  sanitizePath,
  sanitizeStackTrace,
} from './paycheck';
export type {
  PaycheckOptions,
  OfflineValidateResult,
  SyncResult,
  ImportResult,
  CallbackActivationResult,
} from './paycheck';

// Types
export type {
  StorageAdapter,
  DeviceType,
  CheckoutParams,
  CheckoutResult,
  CallbackResult,
  DeviceInfo,
  ActivationResult,
  LicenseClaims,
  LicenseInfo,
  LicenseDeviceInfo,
  DeactivateResult,
  RequestCodeResult,
  PaycheckErrorCode,
  // Feedback & crash types
  FeedbackType,
  Priority,
  FeedbackOptions,
  StackFrame,
  Breadcrumb,
  CrashOptions,
} from './types';
export { PaycheckError } from './types';

// Storage utilities
export {
  createLocalStorageAdapter,
  createMemoryStorage,
  generateUUID,
} from './storage';

// JWT utilities
export {
  decodeToken,
  verifyToken,
  verifyAndDecodeToken,
  isJwtExpired,
  isLicenseExpired,
  coversVersion,
  hasFeature,
  validateIssuer,
  EXPECTED_ISSUER,
} from './jwt';
