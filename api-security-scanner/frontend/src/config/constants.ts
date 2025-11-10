/**
 * ©AngelaMos | 2025
 * All hardcoded values, API endpoints, and configuration constants
 */

/**
 * API Configuration
 */
export const API_BASE_URL =
  import.meta.env.VITE_API_URL || 'http://localhost/api';

export const API_ENDPOINTS = {
  // Auth endpoints
  AUTH: {
    REGISTER: '/auth/register',
    LOGIN: '/auth/login',
  },
  // Scan endpoints
  SCANS: {
    CREATE: '/scans',
    LIST: '/scans',
    GET: (id: number) => `/scans/${id}`,
    DELETE: (id: number) => `/scans/${id}`,
  },
} as const;

/**
 * LocalStorage Keys
 */
export const STORAGE_KEYS = {
  AUTH_TOKEN: 'auth_token',
  USER: 'user',
} as const;

/**
 * Application Constants
 */
export const APP_NAME = 'API Security Scanner';
export const APP_VERSION = '1.0.0';

/**
 * Scan Configuration
 */
export const SCAN_TYPES = {
  RATE_LIMIT: 'rate_limit',
  AUTH: 'auth',
  SQLI: 'sqli',
  IDOR: 'idor',
} as const;

export const SCAN_TYPE_LABELS: Record<string, string> = {
  [SCAN_TYPES.RATE_LIMIT]: 'Rate Limiting',
  [SCAN_TYPES.AUTH]: 'Authentication',
  [SCAN_TYPES.SQLI]: 'SQL Injection',
  [SCAN_TYPES.IDOR]: 'IDOR',
};

/**
 * Severity Levels
 */
export const SEVERITY = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info',
} as const;

export const SEVERITY_COLORS: Record<string, string> = {
  [SEVERITY.CRITICAL]: '#dc2626',
  [SEVERITY.HIGH]: '#ea580c',
  [SEVERITY.MEDIUM]: '#f59e0b',
  [SEVERITY.LOW]: '#3b82f6',
  [SEVERITY.INFO]: '#6b7280',
};

/**
 * Scan Status
 */
export const SCAN_STATUS = {
  PENDING: 'pending',
  RUNNING: 'running',
  COMPLETED: 'completed',
  FAILED: 'failed',
} as const;
