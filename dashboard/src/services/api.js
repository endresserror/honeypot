import axios from 'axios';

// Create axios instance with base configuration
const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || '/api',
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor for adding auth tokens (if needed in future)
api.interceptors.request.use(
  (config) => {
    // Add auth token if available
    const token = localStorage.getItem('authToken');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor for error handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('API Error:', error.response?.data || error.message);
    return Promise.reject(error);
  }
);

// Signature API endpoints
export const signatureApi = {
  // Get approved signatures
  getSignatures: (params = {}) => {
    return api.get('/signatures', { params });
  },

  // Get pending signatures for review
  getPendingSignatures: () => {
    return api.get('/signatures/pending');
  },

  // Get signature details
  getSignatureDetail: (signatureId) => {
    return api.get(`/signatures/${signatureId}`);
  },

  // Approve a signature
  approveSignature: (signatureId, adminUsername) => {
    return api.put(`/signatures/${signatureId}/approve`, {
      admin_username: adminUsername
    });
  },

  // Reject a signature
  rejectSignature: (signatureId, adminUsername, reason = '') => {
    return api.put(`/signatures/${signatureId}/reject`, {
      admin_username: adminUsername,
      reason: reason
    });
  },

  // Get signature statistics
  getStatistics: () => {
    return api.get('/signatures/statistics');
  },

  // Trigger signature generation
  generateSignatures: () => {
    return api.post('/signatures/generate');
  }
};

// Logs API endpoints
export const logsApi = {
  // Get attack logs
  getLogs: (params = {}) => {
    return api.get('/logs', { params });
  },

  // Get log details
  getLogDetail: (logId) => {
    return api.get(`/logs/${logId}`);
  },

  // Analyze specific log
  analyzeLog: (logId) => {
    return api.post(`/logs/${logId}/analyze`);
  },

  // Get log statistics
  getStatistics: () => {
    return api.get('/logs/statistics');
  },

  // Submit attack log (for honeypot)
  submitLog: (logData) => {
    return api.post('/logs', logData);
  }
};

// Feedback API endpoints
export const feedbackApi = {
  // Submit feedback
  submitFeedback: (feedbackData) => {
    return api.post('/feedback', feedbackData);
  },

  // Submit batch feedback
  submitBatchFeedback: (feedbackItems) => {
    return api.post('/feedback/batch', { feedback_items: feedbackItems });
  },

  // Get feedback statistics
  getStatistics: () => {
    return api.get('/feedback/statistics');
  },

  // Get execution details
  getExecutionDetail: (executionId) => {
    return api.get(`/feedback/${executionId}`);
  },

  // Mark execution as false positive
  markFalsePositive: (executionId, adminUsername, notes = '') => {
    return api.put(`/feedback/${executionId}/mark-false-positive`, {
      admin_username: adminUsername,
      notes: notes
    });
  }
};

// Health check
export const healthApi = {
  // Basic health check
  healthCheck: () => {
    return api.get('/health');
  },

  // System status
  getStatus: () => {
    return api.get('/status');
  }
};

export default api;