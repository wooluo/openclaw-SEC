/**
 * API Service
 * Handles all HTTP requests to the backend API
 */

import axios, { AxiosInstance, AxiosRequestConfig } from 'axios'
import { message } from 'antd'

const BASE_URL = import.meta.env.VITE_API_URL || '/api/v1'

class ApiService {
  private client: AxiosInstance

  constructor() {
    this.client = axios.create({
      baseURL: BASE_URL,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
      },
    })

    // Request interceptor
    this.client.interceptors.request.use(
      (config) => {
        const token = localStorage.getItem('token')
        if (token) {
          config.headers.Authorization = `Bearer ${token}`
        }
        return config
      },
      (error) => Promise.reject(error)
    )

    // Response interceptor
    this.client.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response?.status === 401) {
          localStorage.removeItem('token')
          window.location.href = '/login'
        } else if (error.response?.status >= 500) {
          message.error('服务器错误，请稍后重试')
        } else if (error.response?.status === 403) {
          message.error('没有权限执行此操作')
        }
        return Promise.reject(error)
      }
    )
  }

  async get<T = any>(url: string, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.client.get<T>(url, config)
    return response.data
  }

  async post<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.client.post<T>(url, data, config)
    return response.data
  }

  async put<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.client.put<T>(url, data, config)
    return response.data
  }

  async delete<T = any>(url: string, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.client.delete<T>(url, config)
    return response.data
  }
}

export const apiService = new ApiService()

// API endpoints
export const api = {
  // Assets
  getAssets: (params?: any) => apiService.get('/assets', { params }),
  getAssetStats: () => apiService.get('/assets/stats'),
  getAsset: (id: string) => apiService.get(`/assets/${id}`),
  scanAssets: (data: any) => apiService.post('/assets/scan', data),

  // Alerts
  getAlerts: (params?: any) => apiService.get('/alerts', { params }),
  getAlertStats: () => apiService.get('/alerts/stats'),
  getAlert: (id: string) => apiService.get(`/alerts/${id}`),
  updateAlert: (id: string, data: any) => apiService.put(`/alerts/${id}`, data),
  resolveAlert: (id: string, notes?: string) => apiService.post(`/alerts/${id}/resolve`, { notes }),
  deleteAlert: (id: string) => apiService.delete(`/alerts/${id}`),

  // Policies
  getPolicies: (params?: any) => apiService.get('/policies', { params }),
  getPolicy: (id: string) => apiService.get(`/policies/${id}`),
  createPolicy: (data: any) => apiService.post('/policies', data),
  updatePolicy: (id: string, data: any) => apiService.put(`/policies/${id}`, data),
  deletePolicy: (id: string) => apiService.delete(`/policies/${id}`),

  // Monitoring
  getDashboard: () => apiService.get('/monitoring/dashboard'),
  getSystemMetrics: () => apiService.get('/monitoring/system'),
  getSecurityMetrics: () => apiService.get('/monitoring/security'),
  getCPUTimeSeries: (hours: number) => apiService.get(`/monitoring/timeseries/cpu?hours=${hours}`),
  getMemoryTimeSeries: (hours: number) => apiService.get(`/monitoring/timeseries/memory?hours=${hours}`),

  // User
  getCurrentUser: () => apiService.get('/me'),
}

export default apiService
