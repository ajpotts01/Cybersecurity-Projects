// ===================
// ©AngelaMos | 2026
// auth.store.ts
// ===================

import { create } from 'zustand'
import { devtools, persist } from 'zustand/middleware'
import { STORAGE_KEYS } from '@/config'

export interface AuthUser {
  id: string
  username: string
  email: string
  role: string
  is_active: boolean
}

interface AuthState {
  user: AuthUser | null
  accessToken: string | null
  isAuthenticated: boolean
}

interface AuthActions {
  login: (user: AuthUser, accessToken: string) => void
  logout: () => void
  setAccessToken: (token: string | null) => void
  updateUser: (updates: Partial<AuthUser>) => void
}

type AuthStore = AuthState & AuthActions

export const useAuthStore = create<AuthStore>()(
  devtools(
    persist(
      (set) => ({
        user: null,
        accessToken: null,
        isAuthenticated: false,

        login: (user, accessToken) =>
          set({ user, accessToken, isAuthenticated: true }, false, 'auth/login'),

        logout: () =>
          set(
            { user: null, accessToken: null, isAuthenticated: false },
            false,
            'auth/logout'
          ),

        setAccessToken: (token) =>
          set({ accessToken: token }, false, 'auth/setAccessToken'),

        updateUser: (updates) =>
          set(
            (state) => ({
              user: state.user !== null ? { ...state.user, ...updates } : null,
            }),
            false,
            'auth/updateUser'
          ),
      }),
      {
        name: STORAGE_KEYS.AUTH,
        partialize: (state) => ({
          user: state.user,
          accessToken: state.accessToken,
          isAuthenticated: state.isAuthenticated,
        }),
      }
    ),
    { name: 'AuthStore' }
  )
)

export const useUser = (): AuthUser | null => useAuthStore((s) => s.user)
export const useIsAuthenticated = (): boolean =>
  useAuthStore((s) => s.isAuthenticated)
export const useAccessToken = (): string | null =>
  useAuthStore((s) => s.accessToken)
