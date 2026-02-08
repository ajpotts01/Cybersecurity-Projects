// ===================
// ©AngelaMos | 2026
// alert.types.ts
// ===================

import { z } from 'zod'
import { logEventSchema } from './log.types'

export const alertSchema = z.object({
  id: z.string(),
  rule_id: z.string(),
  rule_name: z.string(),
  severity: z.string(),
  title: z.string(),
  matched_event_ids: z.array(z.string()),
  matched_event_count: z.number(),
  group_value: z.string().nullable(),
  status: z.string(),
  mitre_tactic: z.string().nullable(),
  mitre_technique: z.string().nullable(),
  acknowledged_by: z.string().nullable(),
  acknowledged_at: z.string().nullable(),
  resolved_at: z.string().nullable(),
  notes: z.string().nullable(),
  created_at: z.string(),
  updated_at: z.string(),
})

export const alertDetailSchema = z.object({
  alert: alertSchema,
  matched_events: z.array(logEventSchema),
})

export const streamAlertEventSchema = z.object({
  id: z.string(),
  rule_name: z.string(),
  severity: z.string(),
  title: z.string(),
  group_value: z.string().nullable(),
  matched_event_count: z.number(),
  status: z.string(),
})

export type Alert = z.infer<typeof alertSchema>
export type AlertDetail = z.infer<typeof alertDetailSchema>
export type StreamAlertEvent = z.infer<typeof streamAlertEventSchema>

export interface AlertStatusUpdateRequest {
  status: string
  notes?: string
}

export interface AlertQueryParams {
  page?: number
  per_page?: number
  status?: string
  severity?: string
}

export const isValidAlert = (data: unknown): data is Alert => {
  return alertSchema.safeParse(data).success
}

export const isValidAlertDetail = (data: unknown): data is AlertDetail => {
  return alertDetailSchema.safeParse(data).success
}

export const isValidStreamAlertEvent = (
  data: unknown
): data is StreamAlertEvent => {
  return streamAlertEventSchema.safeParse(data).success
}
