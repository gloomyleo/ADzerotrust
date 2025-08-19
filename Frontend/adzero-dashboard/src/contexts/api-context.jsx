import { createContext, useContext, useState } from 'react'

const ApiContext = createContext()

// Base API URL - will be updated for production deployment
const API_BASE_URL = process.env.NODE_ENV === 'production' 
  ? '/api' 
  : 'http://localhost:5000/api'

export function ApiProvider({ children }) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  // Generic API call function
  const apiCall = async (endpoint, options = {}) => {
    setLoading(true)
    setError(null)
    
    try {
      const url = `${API_BASE_URL}${endpoint}`
      const config = {
        headers: {
          'Content-Type': 'application/json',
          ...options.headers,
        },
        ...options,
      }

      const response = await fetch(url, config)
      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || `HTTP error! status: ${response.status}`)
      }

      setLoading(false)
      return data
    } catch (err) {
      setError(err.message)
      setLoading(false)
      throw err
    }
  }

  // Assessment API functions
  const assessmentApi = {
    // Get all assessments
    getAll: (params = {}) => {
      const queryString = new URLSearchParams(params).toString()
      return apiCall(`/assessments${queryString ? `?${queryString}` : ''}`)
    },

    // Get specific assessment
    get: (id) => apiCall(`/assessments/${id}`),

    // Create new assessment
    create: (data) => apiCall('/assessments', {
      method: 'POST',
      body: JSON.stringify(data)
    }),

    // Update assessment
    update: (id, data) => apiCall(`/assessments/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data)
    }),

    // Delete assessment
    delete: (id) => apiCall(`/assessments/${id}`, {
      method: 'DELETE'
    }),

    // Get assessment summary
    getSummary: (id) => apiCall(`/assessments/${id}/summary`),

    // Get assessment modules
    getModules: (id) => apiCall(`/assessments/${id}/modules`),

    // Get assessment recommendations
    getRecommendations: (id, params = {}) => {
      const queryString = new URLSearchParams(params).toString()
      return apiCall(`/assessments/${id}/recommendations${queryString ? `?${queryString}` : ''}`)
    },

    // Create recommendation
    createRecommendation: (id, data) => apiCall(`/assessments/${id}/recommendations`, {
      method: 'POST',
      body: JSON.stringify(data)
    })
  }

  // PowerShell API functions
  const powershellApi = {
    // Get available scripts
    getScripts: () => apiCall('/powershell/scripts'),

    // Execute script manually
    executeScript: (data) => apiCall('/powershell/execute', {
      method: 'POST',
      body: JSON.stringify(data)
    }),

    // Run assessment
    runAssessment: (id, data = {}) => apiCall(`/powershell/assessments/${id}/run`, {
      method: 'POST',
      body: JSON.stringify(data)
    }),

    // Run specific module
    runModule: (assessmentId, moduleId, data = {}) => apiCall(`/powershell/assessments/${assessmentId}/modules/${moduleId}/run`, {
      method: 'POST',
      body: JSON.stringify(data)
    }),

    // Get assessment status
    getStatus: (id) => apiCall(`/powershell/assessments/${id}/status`)
  }

  // Dashboard API functions
  const dashboardApi = {
    // Get overview data
    getOverview: () => apiCall('/dashboard/overview'),

    // Get recent assessments
    getRecentAssessments: (limit = 10) => apiCall(`/dashboard/assessments/recent?limit=${limit}`),

    // Get trends data
    getTrends: (days = 30) => apiCall(`/dashboard/trends?days=${days}`),

    // Get top risks
    getTopRisks: (params = {}) => {
      const queryString = new URLSearchParams(params).toString()
      return apiCall(`/dashboard/risks/top${queryString ? `?${queryString}` : ''}`)
    },

    // Get priority recommendations
    getPriorityRecommendations: (params = {}) => {
      const queryString = new URLSearchParams(params).toString()
      return apiCall(`/dashboard/recommendations/priority${queryString ? `?${queryString}` : ''}`)
    },

    // Get compliance overview
    getCompliance: () => apiCall('/dashboard/compliance'),

    // Get identity analytics
    getIdentityAnalytics: () => apiCall('/dashboard/analytics/identity'),

    // Get permission analytics
    getPermissionAnalytics: () => apiCall('/dashboard/analytics/permissions')
  }

  // Roadmap API functions
  const roadmapApi = {
    // Get all roadmaps
    getAll: (params = {}) => {
      const queryString = new URLSearchParams(params).toString()
      return apiCall(`/roadmap${queryString ? `?${queryString}` : ''}`)
    },

    // Get specific roadmap
    get: (id) => apiCall(`/roadmap/${id}`),

    // Get roadmap by assessment
    getByAssessment: (assessmentId) => apiCall(`/roadmap/assessments/${assessmentId}`),

    // Generate roadmap
    generate: (assessmentId, data = {}) => apiCall(`/roadmap/assessments/${assessmentId}/generate`, {
      method: 'POST',
      body: JSON.stringify(data)
    }),

    // Update roadmap
    update: (id, data) => apiCall(`/roadmap/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data)
    }),

    // Delete roadmap
    delete: (id) => apiCall(`/roadmap/${id}`, {
      method: 'DELETE'
    }),

    // Export roadmap
    export: (id, format = 'json') => apiCall(`/roadmap/${id}/export?format=${format}`)
  }

  // Recommendations API functions
  const recommendationApi = {
    // Update recommendation
    update: (id, data) => apiCall(`/recommendations/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data)
    })
  }

  // Health check
  const healthCheck = () => apiCall('/info')

  const value = {
    loading,
    error,
    setError,
    apiCall,
    assessmentApi,
    powershellApi,
    dashboardApi,
    roadmapApi,
    recommendationApi,
    healthCheck
  }

  return (
    <ApiContext.Provider value={value}>
      {children}
    </ApiContext.Provider>
  )
}

export const useApi = () => {
  const context = useContext(ApiContext)
  if (!context) {
    throw new Error('useApi must be used within an ApiProvider')
  }
  return context
}

