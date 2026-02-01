// Main client
export { Paycheck, createPaycheck, formatActivationCode } from './paycheck';
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
  ValidateResult,
  LicenseInfo,
  LicenseDeviceInfo,
  DeactivateResult,
  RequestCodeResult,
  PaycheckErrorCode,
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
} from './jwt';
