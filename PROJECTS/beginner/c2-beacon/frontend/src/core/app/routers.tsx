// ===================
// © AngelaMos | 2026
// routers.tsx
// ===================

import { createBrowserRouter, type RouteObject } from 'react-router-dom'
import { ROUTES } from '@/config'
import { Shell } from './shell'

const routes: RouteObject[] = [
  {
    element: <Shell />,
    children: [
      {
        path: ROUTES.DASHBOARD,
        lazy: () => import('@/pages/dashboard'),
      },
      {
        path: '/session/:id',
        lazy: () => import('@/pages/session'),
      },
    ],
  },
]

export const router = createBrowserRouter(routes)
