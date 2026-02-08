// ===================
// ©AngelaMos | 2026
// useRules.ts
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
  CorrelationRule,
  DeleteResponse,
  RuleCreateRequest,
  RuleTestRequest,
  RuleTestResult,
  RuleUpdateRequest,
} from '@/api/types'
import { API_ENDPOINTS, QUERY_KEYS } from '@/config'
import { apiClient } from '@/core/lib'

export const ruleQueries = {
  all: () => QUERY_KEYS.RULES.ALL,
  list: () => QUERY_KEYS.RULES.LIST(),
  byId: (id: string) => QUERY_KEYS.RULES.BY_ID(id),
} as const

export const useRules = (): UseQueryResult<CorrelationRule[], Error> => {
  return useQuery({
    queryKey: ruleQueries.list(),
    queryFn: async () => {
      const response = await apiClient.get<CorrelationRule[]>(
        API_ENDPOINTS.RULES.LIST
      )
      return response.data
    },
  })
}

export const useRuleDetail = (
  ruleId: string
): UseQueryResult<CorrelationRule, Error> => {
  return useQuery({
    queryKey: ruleQueries.byId(ruleId),
    queryFn: async () => {
      const response = await apiClient.get<CorrelationRule>(
        API_ENDPOINTS.RULES.BY_ID(ruleId)
      )
      return response.data
    },
    enabled: ruleId.length > 0,
  })
}

export const useCreateRule = (): UseMutationResult<
  CorrelationRule,
  Error,
  RuleCreateRequest
> => {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async (payload: RuleCreateRequest) => {
      const response = await apiClient.post<CorrelationRule>(
        API_ENDPOINTS.RULES.CREATE,
        payload
      )
      return response.data
    },
    onSuccess: (): void => {
      queryClient.invalidateQueries({ queryKey: ruleQueries.all() })
      toast.success('Rule created')
    },
    onError: (error: Error): void => {
      toast.error(error.message)
    },
  })
}

export const useUpdateRule = (
  ruleId: string
): UseMutationResult<CorrelationRule, Error, RuleUpdateRequest> => {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async (payload: RuleUpdateRequest) => {
      const response = await apiClient.patch<CorrelationRule>(
        API_ENDPOINTS.RULES.UPDATE(ruleId),
        payload
      )
      return response.data
    },
    onSuccess: (): void => {
      queryClient.invalidateQueries({ queryKey: ruleQueries.all() })
      toast.success('Rule updated')
    },
    onError: (error: Error): void => {
      toast.error(error.message)
    },
  })
}

export const useDeleteRule = (): UseMutationResult<
  DeleteResponse,
  Error,
  string
> => {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async (ruleId: string) => {
      const response = await apiClient.delete<DeleteResponse>(
        API_ENDPOINTS.RULES.DELETE(ruleId)
      )
      return response.data
    },
    onSuccess: (): void => {
      queryClient.invalidateQueries({ queryKey: ruleQueries.all() })
      toast.success('Rule deleted')
    },
    onError: (error: Error): void => {
      toast.error(error.message)
    },
  })
}

export const useTestRule = (
  ruleId: string
): UseMutationResult<RuleTestResult, Error, RuleTestRequest> => {
  return useMutation({
    mutationFn: async (payload: RuleTestRequest) => {
      const response = await apiClient.post<RuleTestResult>(
        API_ENDPOINTS.RULES.TEST(ruleId),
        payload
      )
      return response.data
    },
    onError: (error: Error): void => {
      toast.error(error.message)
    },
  })
}
