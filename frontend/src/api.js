import axios from 'axios';

const BASE_URL = 'http://46.101.193.155:8000';

const api = axios.create({ baseURL: BASE_URL });

api.interceptors.request.use(config => {
  const token = localStorage.getItem('token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

export const WS_BASE = 'ws://46.101.193.155:8000';
export default api;
