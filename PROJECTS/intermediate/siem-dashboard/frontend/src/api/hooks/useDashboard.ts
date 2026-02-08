// ===================
// ©AngelaMos | 2026
// useDashboard.ts
// ===================

import type { UseQueryResult } from '@tanstack/react-query'
import { useQuery } from '@tanstack/react-query'
import type {
  DashboardOverview,
  SeverityCount,
  TimelineBucket,
  TopSource,
} from '@/api/types'
import { API_ENDPOINTS, QUERY_KEYS } from '@/config'
import { apiClient, QUERY_STRATEGIES } from '@/core/lib'

export const dashboardQueries = {
  all: () => QUERY_KEYS.DASHBOARD.ALL,
  overview: () => QUERY_KEYS.DASHBOARD.OVERVIEW(),
  timeline: (hours: number, bucket: number) =>
    QUERY_KEYS.DASHBOARD.TIMELINE(hours, bucket),
  severity: () => QUERY_KEYS.DASHBOARD.SEVERITY(),
  topSources: (limit: number) => QUERY_KEYS.DASHBOARD.TOP_SOURCES(limit),
} as const

export const useDashboardOverview = (): UseQueryResult<
  DashboardOverview,
  Error
> => {
  return useQuery({
    queryKey: dashboardQueries.overview(),
    queryFn: async () => {
      const response = await apiClient.get<DashboardOverview>(
        API_ENDPOINTS.DASHBOARD.OVERVIEW
      )
      return response.data
    },
    ...QUERY_STRATEGIES.dashboard,
  })
}

export const useTimeline = (
  hours = 24,
  bucketMinutes = 15
): UseQueryResult<TimelineBucket[], Error> => {
  return useQuery({
    queryKey: dashboardQueries.timeline(hours, bucketMinutes),
    queryFn: async () => {
      const response = await apiClient.get<TimelineBucket[]>(
        API_ENDPOINTS.DASHBOARD.TIMELINE,
        { params: { hours, bucket_minutes: bucketMinutes } }
      )
      return response.data
    },
    ...QUERY_STRATEGIES.dashboard,
  })
}

export const useSeverityBreakdown = (): UseQueryResult<
  SeverityCount[],
  Error
> => {
  return useQuery({
    queryKey: dashboardQueries.severity(),
    queryFn: async () => {
      const response = await apiClient.get<SeverityCount[]>(
        API_ENDPOINTS.DASHBOARD.SEVERITY
      )
      return response.data
    },
    ...QUERY_STRATEGIES.dashboard,
  })
}

export const useTopSources = (limit = 10): UseQueryResult<TopSource[], Error> => {
  return useQuery({
    queryKey: dashboardQueries.topSources(limit),
    queryFn: async () => {
      const response = await apiClient.get<TopSource[]>(
        API_ENDPOINTS.DASHBOARD.TOP_SOURCES,
        { params: { limit } }
      )
      return response.data
    },
    ...QUERY_STRATEGIES.dashboard,
  })
}
