// ===================
// © AngelaMos | 2026
// config.ts
// ===================

export const API_BASE = '/api'

export const API_ENDPOINTS = {
  HEALTH: `${API_BASE}/health`,
  BEACONS: `${API_BASE}/beacons`,
  BEACON: (id: string) => `${API_BASE}/beacons/${id}`,
  BEACON_TASKS: (id: string) => `${API_BASE}/beacons/${id}/tasks`,
} as const

export const WS_ENDPOINTS = {
  OPERATOR: `${API_BASE}/ws/operator`,
} as const

export const ROUTES = {
  DASHBOARD: '/',
  SESSION: (id: string) => `/session/${id}`,
} as const

export const STORAGE_KEYS = {
  UI: 'c2-ui-storage',
} as const
