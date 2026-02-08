// ===================
// ©AngelaMos | 2026
// api.ts
// ===================

import axios, {
  type AxiosError,
  type AxiosInstance,
  type InternalAxiosRequestConfig,
} from 'axios'
import { HTTP_STATUS } from '@/config'
import { useAuthStore } from '@/core/stores'
import { transformAxiosError } from './errors'

export const getBaseURL = (): string => {
  return import.meta.env.VITE_API_URL ?? '/api'
}

export const apiClient: AxiosInstance = axios.create({
  baseURL: getBaseURL(),
  timeout: 15000,
  headers: { 'Content-Type': 'application/json' },
})

apiClient.interceptors.request.use(
  (config: InternalAxiosRequestConfig): InternalAxiosRequestConfig => {
    const token = useAuthStore.getState().accessToken
    if (token !== null && token.length > 0) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error: unknown): Promise<never> => {
    return Promise.reject(error)
  }
)

apiClient.interceptors.response.use(
  (response) => response,
  (error: AxiosError): Promise<never> => {
    if (error.response?.status === HTTP_STATUS.UNAUTHORIZED) {
      useAuthStore.getState().logout()
      window.location.href = '/login'
    }
    return Promise.reject(transformAxiosError(error))
  }
)
