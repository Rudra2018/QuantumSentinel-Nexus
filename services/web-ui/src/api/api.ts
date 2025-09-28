import axios from 'axios';

// API base configuration
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor
api.interceptors.request.use(
  (config) => {
    // Add auth token if available
    const token = localStorage.getItem('authToken');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Handle unauthorized access
      localStorage.removeItem('authToken');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// Types
export interface ScanRequest {
  scan_type: string;
  targets: string[];
  priority?: number;
  timeout_seconds?: number;
  program?: string;
  options?: Record<string, any>;
}

export interface ScanJob {
  job_id: string;
  scan_type: string;
  targets: string[];
  status: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  findings: any[];
  error_message?: string;
}

export interface DashboardStats {
  totalScans: number;
  activeScans: number;
  criticalVulnerabilities: number;
  zeroDayPredictions: number;
  ibbFindings: number;
  mlPredictions: number;
}

// Dashboard API
export const fetchDashboardStats = async (): Promise<DashboardStats> => {
  const response = await api.get('/dashboard/stats');
  return response.data;
};

export const fetchRecentScans = async () => {
  const response = await api.get('/scans?limit=10');
  return response.data.scans;
};

export const fetchVulnerabilityTrends = async () => {
  const response = await api.get('/dashboard/vulnerability-trends');
  return response.data;
};

// Scan Management API
export const createScan = async (scanRequest: ScanRequest) => {
  const response = await api.post('/scans', scanRequest);
  return response.data;
};

export const fetchScans = async (limit = 50, offset = 0) => {
  const response = await api.get(`/scans?limit=${limit}&offset=${offset}`);
  return response.data;
};

export const fetchScanDetails = async (scanId: string): Promise<ScanJob> => {
  const response = await api.get(`/scans/${scanId}`);
  return response.data;
};

export const deleteScan = async (scanId: string) => {
  const response = await api.delete(`/scans/${scanId}`);
  return response.data;
};

// IBB Research API
export const fetchIBBFindings = async (limit = 50) => {
  const response = await api.get(`/ibb-research/findings?limit=${limit}`);
  return response.data;
};

export const fetchIBBStatistics = async () => {
  const response = await api.get('/ibb-research/statistics');
  return response.data;
};

export const triggerIBBResearch = async (targets: string[]) => {
  const response = await api.post('/ibb-research/scan', { targets });
  return response.data;
};

// ML Intelligence API
export const fetchMLPredictions = async (limit = 50) => {
  const response = await api.get(`/ml-intelligence/predictions?limit=${limit}`);
  return response.data;
};

export const fetchMLStatistics = async () => {
  const response = await api.get('/ml-intelligence/statistics');
  return response.data;
};

export const analyzeTarget = async (targetData: Record<string, any>) => {
  const response = await api.post('/ml-intelligence/analyze', targetData);
  return response.data;
};

// Vulnerability Database API
export const fetchVulnerabilities = async (filters?: Record<string, any>) => {
  const params = new URLSearchParams(filters);
  const response = await api.get(`/vulnerabilities?${params}`);
  return response.data;
};

export const fetchVulnerabilityDetails = async (vulnId: string) => {
  const response = await api.get(`/vulnerabilities/${vulnId}`);
  return response.data;
};

// Reports API
export const fetchReports = async () => {
  const response = await api.get('/reports');
  return response.data;
};

export const generateReport = async (reportConfig: Record<string, any>) => {
  const response = await api.post('/reports/generate', reportConfig);
  return response.data;
};

export const downloadReport = async (reportId: string) => {
  const response = await api.get(`/reports/${reportId}/download`, {
    responseType: 'blob',
  });
  return response.data;
};

// Settings API
export const fetchSettings = async () => {
  const response = await api.get('/settings');
  return response.data;
};

export const updateSettings = async (settings: Record<string, any>) => {
  const response = await api.put('/settings', settings);
  return response.data;
};

// Health Check API
export const fetchSystemHealth = async () => {
  const response = await api.get('/health');
  return response.data;
};

// Service-specific health checks
export const fetchServiceHealth = async (service: string) => {
  const serviceEndpoints = {
    orchestration: '/health',
    'ibb-research': '/ibb-research/health',
    'ml-intelligence': '/ml-intelligence/health',
    'sast-dast': '/sast-dast/health',
    fuzzing: '/fuzzing/health',
    'reverse-engineering': '/reverse-engineering/health',
    reporting: '/reporting/health',
  };

  const endpoint = serviceEndpoints[service as keyof typeof serviceEndpoints];
  if (!endpoint) {
    throw new Error(`Unknown service: ${service}`);
  }

  const response = await api.get(endpoint);
  return response.data;
};

// Batch operations
export const batchDeleteScans = async (scanIds: string[]) => {
  const response = await api.post('/scans/batch-delete', { scan_ids: scanIds });
  return response.data;
};

export const batchCreateScans = async (scanRequests: ScanRequest[]) => {
  const response = await api.post('/scans/batch-create', { scans: scanRequests });
  return response.data;
};

// Real-time data
export const subscribeToUpdates = (onMessage: (data: any) => void) => {
  const wsUrl = process.env.REACT_APP_WEBSOCKET_URL || 'ws://localhost:8000/ws';
  const ws = new WebSocket(wsUrl);

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      onMessage(data);
    } catch (error) {
      console.error('Failed to parse WebSocket message:', error);
    }
  };

  ws.onerror = (error) => {
    console.error('WebSocket error:', error);
  };

  return () => {
    ws.close();
  };
};

// Export default API instance
export default api;