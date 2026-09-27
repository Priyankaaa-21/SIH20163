import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:8000',
});

// Add a request interceptor to attach the JWT token
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export const login = async (username, password) => {
  const formData = new URLSearchParams();
  formData.append('username', username);
  formData.append('password', password);
  
  const response = await api.post('/token', formData, {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    }
  });
  return response.data;
};

export const getFindings = async () => {
  const response = await api.get('/findings/');
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
