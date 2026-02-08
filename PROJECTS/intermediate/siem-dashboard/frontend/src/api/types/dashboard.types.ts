// ===================
// ©AngelaMos | 2026
// dashboard.types.ts
// ===================

import { z } from 'zod'

export const severityCountSchema = z.object({
  severity: z.string(),
  count: z.number(),
})

export const dashboardOverviewSchema = z.object({
  total_events: z.number(),
  total_alerts: z.number(),
  open_alerts: z.number(),
  alerts_by_status: z.record(z.string(), z.number()),
  severity_breakdown: z.array(severityCountSchema),
})

export const timelineBucketSchema = z.object({
  bucket: z.string(),
  count: z.number(),
})

export const topSourceSchema = z.object({
  source_ip: z.string(),
  count: z.number(),
})

export type SeverityCount = z.infer<typeof severityCountSchema>
export type DashboardOverview = z.infer<typeof dashboardOverviewSchema>
export type TimelineBucket = z.infer<typeof timelineBucketSchema>
export type TopSource = z.infer<typeof topSourceSchema>

export interface TimelineParams {
  hours?: number
  bucket_minutes?: number
}

export interface TopSourcesParams {
  limit?: number
}

export const isValidDashboardOverview = (
  data: unknown
): data is DashboardOverview => {
  return dashboardOverviewSchema.safeParse(data).success
}

export const isValidTimelineBucket = (data: unknown): data is TimelineBucket => {
  return timelineBucketSchema.safeParse(data).success
}

export const isValidTopSource = (data: unknown): data is TopSource => {
  return topSourceSchema.safeParse(data).success
}
