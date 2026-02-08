// ===================
// ©AngelaMos | 2026
// useAuth.ts
// ===================

import {
  type UseMutationResult,
  type UseQueryResult,
  useMutation,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query'
import { toast } from 'sonner'
import {
  AUTH_ERROR_MESSAGES,
  AUTH_SUCCESS_MESSAGES,
  AuthResponseError,
  isValidTokenResponse,
  isValidUpdateProfileResponse,
  isValidUserResponse,
  type LoginRequest,
  type RegisterRequest,
  type TokenResponse,
  type UpdateProfileRequest,
  type UpdateProfileResponse,
  type UserResponse,
} from '@/api/types'
import { API_ENDPOINTS, QUERY_KEYS, ROUTES } from '@/config'
import { apiClient, QUERY_STRATEGIES } from '@/core/lib'
import { useAuthStore } from '@/core/stores'

export const authQueries = {
  all: () => QUERY_KEYS.AUTH.ALL,
  me: () => QUERY_KEYS.AUTH.ME(),
} as const

const fetchCurrentUser = async (): Promise<UserResponse> => {
  const response = await apiClient.get<unknown>(API_ENDPOINTS.AUTH.ME)
  const data: unknown = response.data

  if (!isValidUserResponse(data)) {
    throw new AuthResponseError(
      AUTH_ERROR_MESSAGES.INVALID_USER_RESPONSE,
      API_ENDPOINTS.AUTH.ME
    )
  }

  return data
}

export const useCurrentUser = (): UseQueryResult<UserResponse, Error> => {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)

  return useQuery({
    queryKey: authQueries.me(),
    queryFn: fetchCurrentUser,
    enabled: isAuthenticated,
    ...QUERY_STRATEGIES.auth,
  })
}

const performLogin = async (
  credentials: LoginRequest
): Promise<TokenResponse> => {
  const response = await apiClient.post<unknown>(
    API_ENDPOINTS.AUTH.LOGIN,
    credentials
  )
  const data: unknown = response.data

  if (!isValidTokenResponse(data)) {
    throw new AuthResponseError(
      AUTH_ERROR_MESSAGES.INVALID_LOGIN_RESPONSE,
      API_ENDPOINTS.AUTH.LOGIN
    )
  }

  return data
}

export const useLogin = (): UseMutationResult<
  TokenResponse,
  Error,
  LoginRequest
> => {
  const queryClient = useQueryClient()
  const login = useAuthStore((s) => s.login)

  return useMutation({
    mutationFn: performLogin,
    onSuccess: async (data: TokenResponse): Promise<void> => {
      useAuthStore.getState().setAccessToken(data.access_token)

      const userResponse = await apiClient.get<unknown>(API_ENDPOINTS.AUTH.ME)
      const userData: unknown = userResponse.data

      if (!isValidUserResponse(userData)) {
        throw new AuthResponseError(
          AUTH_ERROR_MESSAGES.INVALID_USER_RESPONSE,
          API_ENDPOINTS.AUTH.ME
        )
      }

      login(userData, data.access_token)
      queryClient.setQueryData(authQueries.me(), userData)
      toast.success(AUTH_SUCCESS_MESSAGES.WELCOME_BACK(userData.username))
    },
    onError: (error: Error): void => {
      const message =
        error instanceof AuthResponseError ? error.message : 'Login failed'
      toast.error(message)
    },
  })
}

const performRegister = async (
  payload: RegisterRequest
): Promise<TokenResponse> => {
  const response = await apiClient.post<unknown>(
    API_ENDPOINTS.AUTH.REGISTER,
    payload
  )
  const data: unknown = response.data

  if (!isValidTokenResponse(data)) {
    throw new AuthResponseError(
      AUTH_ERROR_MESSAGES.INVALID_TOKEN_RESPONSE,
      API_ENDPOINTS.AUTH.REGISTER
    )
  }

  return data
}

export const useRegister = (): UseMutationResult<
  TokenResponse,
  Error,
  RegisterRequest
> => {
  const queryClient = useQueryClient()
  const login = useAuthStore((s) => s.login)

  return useMutation({
    mutationFn: performRegister,
    onSuccess: async (data: TokenResponse): Promise<void> => {
      useAuthStore.getState().setAccessToken(data.access_token)

      const userResponse = await apiClient.get<unknown>(API_ENDPOINTS.AUTH.ME)
      const userData: unknown = userResponse.data

      if (!isValidUserResponse(userData)) {
        throw new AuthResponseError(
          AUTH_ERROR_MESSAGES.INVALID_USER_RESPONSE,
          API_ENDPOINTS.AUTH.ME
        )
      }

      login(userData, data.access_token)
      queryClient.setQueryData(authQueries.me(), userData)
      toast.success(AUTH_SUCCESS_MESSAGES.REGISTERED)
    },
    onError: (error: Error): void => {
      const message =
        error instanceof AuthResponseError ? error.message : 'Registration failed'
      toast.error(message)
    },
  })
}

export const useUpdateProfile = (): UseMutationResult<
  UpdateProfileResponse,
  Error,
  UpdateProfileRequest
> => {
  const queryClient = useQueryClient()
  const updateUser = useAuthStore((s) => s.updateUser)

  return useMutation({
    mutationFn: async (
      payload: UpdateProfileRequest
    ): Promise<UpdateProfileResponse> => {
      const response = await apiClient.patch<unknown>(
        API_ENDPOINTS.AUTH.UPDATE_PROFILE,
        payload
      )
      const data: unknown = response.data

      if (!isValidUpdateProfileResponse(data)) {
        throw new AuthResponseError(
          AUTH_ERROR_MESSAGES.INVALID_USER_RESPONSE,
          API_ENDPOINTS.AUTH.UPDATE_PROFILE
        )
      }

      return data
    },
    onSuccess: (data: UpdateProfileResponse): void => {
      updateUser(data.user)

      if (data.access_token !== undefined) {
        useAuthStore.getState().setAccessToken(data.access_token)
      }

      queryClient.setQueryData(authQueries.me(), data.user)
      toast.success(AUTH_SUCCESS_MESSAGES.PROFILE_UPDATED)
    },
    onError: (error: Error): void => {
      toast.error(error.message)
    },
  })
}

export const useLogout = (): UseMutationResult<void, Error, void> => {
  const queryClient = useQueryClient()
  const logout = useAuthStore((s) => s.logout)

  return useMutation({
    mutationFn: async (): Promise<void> => {},
    onSuccess: (): void => {
      logout()
      queryClient.removeQueries({ queryKey: authQueries.all() })
      toast.success(AUTH_SUCCESS_MESSAGES.LOGOUT_SUCCESS)
      window.location.href = ROUTES.LOGIN
    },
  })
}
