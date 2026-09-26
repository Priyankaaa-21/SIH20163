import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:8000',
});

export const getFindings = async () => {
  const response = await api.get('/findings/');
  return response.data;
};

export const getFindingDetails = async (id) => {
  const response = await api.get(`/findings/${id}`);
  return response.data;
};
