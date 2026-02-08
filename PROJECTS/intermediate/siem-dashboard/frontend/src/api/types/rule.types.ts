// ===================
// ©AngelaMos | 2026
// rule.types.ts
// ===================

import { z } from 'zod'

export const correlationRuleSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  rule_type: z.string(),
  conditions: z.record(z.string(), z.unknown()),
  severity: z.string(),
  enabled: z.boolean(),
  mitre_tactic: z.string().nullable(),
  mitre_technique: z.string().nullable(),
  created_at: z.string(),
  updated_at: z.string(),
})

export const ruleTestAlertSchema = z.object({
  group_value: z.string(),
  matched_event_count: z.number(),
  matched_event_ids: z.array(z.string()),
})

export const ruleTestResultSchema = z.object({
  rule_id: z.string(),
  rule_name: z.string(),
  events_evaluated: z.number(),
  alerts_would_fire: z.number(),
  alerts: z.array(ruleTestAlertSchema),
})

export type CorrelationRule = z.infer<typeof correlationRuleSchema>
export type RuleTestAlert = z.infer<typeof ruleTestAlertSchema>
export type RuleTestResult = z.infer<typeof ruleTestResultSchema>

export interface RuleCreateRequest {
  name: string
  description?: string
  rule_type: string
  conditions: Record<string, unknown>
  severity: string
  enabled?: boolean
  mitre_tactic?: string
  mitre_technique?: string
}

export interface RuleUpdateRequest {
  name?: string
  description?: string
  conditions?: Record<string, unknown>
  severity?: string
  enabled?: boolean
  mitre_tactic?: string
  mitre_technique?: string
}

export interface RuleTestRequest {
  hours?: number
}

export const isValidCorrelationRule = (
  data: unknown
): data is CorrelationRule => {
  return correlationRuleSchema.safeParse(data).success
}

export const isValidRuleTestResult = (data: unknown): data is RuleTestResult => {
  return ruleTestResultSchema.safeParse(data).success
}
