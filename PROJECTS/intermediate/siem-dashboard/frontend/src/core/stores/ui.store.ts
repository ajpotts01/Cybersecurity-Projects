// ===================
// ©AngelaMos | 2026
// ui.store.ts
// ===================

import { create } from 'zustand'
import { devtools, persist } from 'zustand/middleware'
import { STORAGE_KEYS } from '@/config'

interface UIState {
  sidebarOpen: boolean
  sidebarCollapsed: boolean
  toggleSidebar: () => void
  setSidebarOpen: (open: boolean) => void
  toggleSidebarCollapsed: () => void
}

export const useUIStore = create<UIState>()(
  devtools(
    persist(
      (set) => ({
        sidebarOpen: false,
        sidebarCollapsed: false,

        toggleSidebar: () =>
          set(
            (state) => ({ sidebarOpen: !state.sidebarOpen }),
            false,
            'ui/toggleSidebar'
          ),

        setSidebarOpen: (open) =>
          set({ sidebarOpen: open }, false, 'ui/setSidebarOpen'),

        toggleSidebarCollapsed: () =>
          set(
            (state) => ({
              sidebarCollapsed: !state.sidebarCollapsed,
            }),
            false,
            'ui/toggleSidebarCollapsed'
          ),
      }),
      {
        name: STORAGE_KEYS.UI,
        partialize: (state) => ({
          sidebarCollapsed: state.sidebarCollapsed,
        }),
      }
    ),
    { name: 'UIStore' }
  )
)

export const useSidebarOpen = (): boolean => useUIStore((s) => s.sidebarOpen)
export const useSidebarCollapsed = (): boolean =>
  useUIStore((s) => s.sidebarCollapsed)
