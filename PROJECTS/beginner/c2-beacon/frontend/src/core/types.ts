// ===================
// © AngelaMos | 2026
// types.ts
// ===================

import { z } from 'zod/v4'

export const CommandType = z.enum([
  'shell',
  'sysinfo',
  'proclist',
  'upload',
  'download',
  'screenshot',
  'keylog_start',
  'keylog_stop',
  'persist',
  'sleep',
])
export type CommandType = z.infer<typeof CommandType>

export const BeaconRecord = z.object({
  id: z.string(),
  hostname: z.string(),
  os: z.string(),
  username: z.string(),
  pid: z.number(),
  internal_ip: z.string(),
  arch: z.string(),
  first_seen: z.string(),
  last_seen: z.string(),
  active: z.boolean(),
})
export type BeaconRecord = z.infer<typeof BeaconRecord>

export const TaskRecord = z.object({
  id: z.string(),
  beacon_id: z.string(),
  command: CommandType,
  args: z.string().nullable().optional(),
  status: z.string(),
  created_at: z.string(),
  completed_at: z.string().nullable().optional(),
})
export type TaskRecord = z.infer<typeof TaskRecord>

export const TaskResult = z.object({
  id: z.string(),
  task_id: z.string(),
  output: z.string().nullable().optional(),
  error: z.string().nullable().optional(),
  created_at: z.string(),
})
export type TaskResult = z.infer<typeof TaskResult>

export const WsBeaconList = z.object({
  type: z.literal('beacon_list'),
  payload: z.array(BeaconRecord),
})

export const WsBeaconConnected = z.object({
  type: z.literal('beacon_connected'),
  payload: BeaconRecord.omit({ active: true, first_seen: true, last_seen: true }),
})

export const WsBeaconDisconnected = z.object({
  type: z.literal('beacon_disconnected'),
  payload: z.object({ id: z.string() }),
})

export const WsHeartbeat = z.object({
  type: z.literal('heartbeat'),
  payload: z.object({ id: z.string() }),
})

export const WsTaskResult = z.object({
  type: z.literal('task_result'),
  payload: TaskResult,
})

export const WsTaskSubmitted = z.object({
  type: z.literal('task_submitted'),
  payload: z.object({ local_id: z.string(), task_id: z.string() }),
})

export const WsServerMessage = z.discriminatedUnion('type', [
  WsBeaconList,
  WsBeaconConnected,
  WsBeaconDisconnected,
  WsHeartbeat,
  WsTaskResult,
  WsTaskSubmitted,
])
export type WsServerMessage = z.infer<typeof WsServerMessage>

export function parseServerMessage(raw: string): WsServerMessage | null {
  const result = WsServerMessage.safeParse(JSON.parse(raw))
  return result.success ? result.data : null
}
