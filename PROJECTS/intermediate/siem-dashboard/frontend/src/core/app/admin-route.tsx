// ===================
// ©AngelaMos | 2026
// admin-route.tsx
// ===================

import { Navigate, Outlet } from 'react-router-dom'
import { ROUTES } from '@/config'
import { useAuthStore } from '@/core/stores'

export function AdminRoute(): React.ReactElement {
  const user = useAuthStore((s) => s.user)

  if (user?.role !== 'admin') {
    return <Navigate to={ROUTES.DASHBOARD} replace />
  }

  return <Outlet />
}
