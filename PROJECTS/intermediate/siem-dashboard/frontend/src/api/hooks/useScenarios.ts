// ===================
// ©AngelaMos | 2026
// useScenarios.ts
// ===================

import {
  type UseMutationResult,
  type UseQueryResult,
  useMutation,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query'
import { toast } from 'sonner'
import type {
  PlaybookInfo,
  ScenarioRun,
  ScenarioStartRequest,
  SpeedRequest,
} from '@/api/types'
import { API_ENDPOINTS, QUERY_KEYS } from '@/config'
import { apiClient, QUERY_STRATEGIES } from '@/core/lib'

export const scenarioQueries = {
  all: () => QUERY_KEYS.SCENARIOS.ALL,
  available: () => QUERY_KEYS.SCENARIOS.AVAILABLE(),
  running: () => QUERY_KEYS.SCENARIOS.RUNNING(),
} as const

export const useAvailablePlaybooks = (): UseQueryResult<
  PlaybookInfo[],
  Error
> => {
  return useQuery({
    queryKey: scenarioQueries.available(),
    queryFn: async () => {
      const response = await apiClient.get<PlaybookInfo[]>(
        API_ENDPOINTS.SCENARIOS.AVAILABLE
      )
      return response.data
    },
  })
}

export const useRunningScenarios = (): UseQueryResult<ScenarioRun[], Error> => {
  return useQuery({
    queryKey: scenarioQueries.running(),
    queryFn: async () => {
      const response = await apiClient.get<ScenarioRun[]>(
        API_ENDPOINTS.SCENARIOS.RUNNING
      )
      return response.data
    },
    ...QUERY_STRATEGIES.frequent,
  })
}

export const useStartScenario = (): UseMutationResult<
  ScenarioRun,
  Error,
  ScenarioStartRequest
> => {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async (payload: ScenarioStartRequest) => {
      const response = await apiClient.post<ScenarioRun>(
        API_ENDPOINTS.SCENARIOS.START,
        payload
      )
      return response.data
    },
    onSuccess: (data: ScenarioRun): void => {
      queryClient.invalidateQueries({ queryKey: scenarioQueries.running() })
      toast.success(`Scenario "${data.scenario_name}" started`)
    },
    onError: (error: Error): void => {
      toast.error(error.message)
    },
  })
}

export const useStopScenario = (): UseMutationResult<
  ScenarioRun,
  Error,
  string
> => {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async (runId: string) => {
      const response = await apiClient.post<ScenarioRun>(
        API_ENDPOINTS.SCENARIOS.STOP(runId)
      )
      return response.data
    },
    onSuccess: (): void => {
      queryClient.invalidateQueries({ queryKey: scenarioQueries.running() })
      toast.success('Scenario stopped')
    },
    onError: (error: Error): void => {
      toast.error(error.message)
    },
  })
}

export const usePauseScenario = (): UseMutationResult<
  ScenarioRun,
  Error,
  string
> => {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async (runId: string) => {
      const response = await apiClient.post<ScenarioRun>(
        API_ENDPOINTS.SCENARIOS.PAUSE(runId)
      )
      return response.data
    },
    onSuccess: (): void => {
      queryClient.invalidateQueries({ queryKey: scenarioQueries.running() })
      toast.success('Scenario paused')
    },
    onError: (error: Error): void => {
      toast.error(error.message)
    },
  })
}

export const useResumeScenario = (): UseMutationResult<
  ScenarioRun,
  Error,
  string
> => {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async (runId: string) => {
      const response = await apiClient.post<ScenarioRun>(
        API_ENDPOINTS.SCENARIOS.RESUME(runId)
      )
      return response.data
    },
    onSuccess: (): void => {
      queryClient.invalidateQueries({ queryKey: scenarioQueries.running() })
      toast.success('Scenario resumed')
    },
    onError: (error: Error): void => {
      toast.error(error.message)
    },
  })
}

export const useSetScenarioSpeed = (
  runId: string
): UseMutationResult<ScenarioRun, Error, SpeedRequest> => {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async (payload: SpeedRequest) => {
      const response = await apiClient.put<ScenarioRun>(
        API_ENDPOINTS.SCENARIOS.SPEED(runId),
        payload
      )
      return response.data
    },
    onSuccess: (data: ScenarioRun): void => {
      queryClient.invalidateQueries({ queryKey: scenarioQueries.running() })
      toast.success(`Speed set to ${data.speed}x`)
    },
    onError: (error: Error): void => {
      toast.error(error.message)
    },
  })
}
