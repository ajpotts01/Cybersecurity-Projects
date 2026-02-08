// ===================
// ©AngelaMos | 2026
// protected-route.tsx
// ===================

import { Navigate, Outlet, useLocation } from 'react-router-dom'
import { ROUTES } from '@/config'
import { useAuthStore } from '@/core/stores'

export function ProtectedRoute(): React.ReactElement {
  const location = useLocation()
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)

  if (!isAuthenticated) {
    return (
      <Navigate
        to={ROUTES.LOGIN}
        state={{ from: location.pathname + location.search }}
        replace
      />
    )
  }

  return <Outlet />
}
