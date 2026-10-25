import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000',
});

// Request interceptor to attach JWT token
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor to auto-logout on 401 Unauthorized
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      localStorage.removeItem('token');
      localStorage.removeItem('username');
      localStorage.removeItem('role');
      // Dispatch custom event to notify React app without hard reload
      window.dispatchEvent(new Event('auth:logout'));
    }
    return Promise.reject(error);
  }
);

export const login = async (username, password) => {
  const formData = new URLSearchParams();
  formData.append('username', username);
  formData.append('password', password);
  
  const response = await api.post('/token', formData, {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    }
  });
  
  if (response.data?.access_token) {
    localStorage.setItem('token', response.data.access_token);
    localStorage.setItem('username', response.data.username || username);
    localStorage.setItem('role', response.data.role || 'user');
  }
  return response.data;
};

export const logout = () => {
  localStorage.removeItem('token');
  localStorage.removeItem('username');
  localStorage.removeItem('role');
  window.dispatchEvent(new Event('auth:logout'));
};

export const getFindings = async (params = {}) => {
  // Clean empty params
  const cleanParams = {};
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') {
      cleanParams[k] = v;
    }
  }
  const response = await api.get('/findings/', { params: cleanParams });
  return response.data;
};

export const getFindingDetails = async (id) => {
  const response = await api.get(`/findings/${id}`);
  return response.data;
};

export const getFacilities = async () => {
  const response = await api.get('/facilities/');
  return response.data;
};

export const getAuditLogs = async () => {
  const response = await api.get('/audit/');
  return response.data;
};

export default api;
