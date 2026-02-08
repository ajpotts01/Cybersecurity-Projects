// ===================
// ©AngelaMos | 2026
// stream.store.ts
// ===================

import { create } from 'zustand'
import { devtools } from 'zustand/middleware'

const MAX_BUFFER_SIZE = 500

interface StreamEvent {
  id: string
  timestamp: string
  data: Record<string, unknown>
}

interface StreamState {
  logEvents: StreamEvent[]
  alertEvents: StreamEvent[]
  logConnected: boolean
  alertConnected: boolean
  pushLogEvent: (event: StreamEvent) => void
  pushAlertEvent: (event: StreamEvent) => void
  setLogConnected: (connected: boolean) => void
  setAlertConnected: (connected: boolean) => void
  clearLogs: () => void
  clearAlerts: () => void
}

export const useStreamStore = create<StreamState>()(
  devtools(
    (set) => ({
      logEvents: [],
      alertEvents: [],
      logConnected: false,
      alertConnected: false,

      pushLogEvent: (event) =>
        set(
          (state) => ({
            logEvents: [event, ...state.logEvents].slice(0, MAX_BUFFER_SIZE),
          }),
          false,
          'stream/pushLog'
        ),

      pushAlertEvent: (event) =>
        set(
          (state) => ({
            alertEvents: [event, ...state.alertEvents].slice(0, MAX_BUFFER_SIZE),
          }),
          false,
          'stream/pushAlert'
        ),

      setLogConnected: (connected) =>
        set({ logConnected: connected }, false, 'stream/logConnected'),

      setAlertConnected: (connected) =>
        set({ alertConnected: connected }, false, 'stream/alertConnected'),

      clearLogs: () => set({ logEvents: [] }, false, 'stream/clearLogs'),

      clearAlerts: () => set({ alertEvents: [] }, false, 'stream/clearAlerts'),
    }),
    { name: 'StreamStore' }
  )
)
