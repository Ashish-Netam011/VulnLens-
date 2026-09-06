import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
});

// Attach JWT to every request. Token is stored in localStorage (a common
// SPA pattern); server-side it is verified on every protected route.
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('vulnlens_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response && err.response.status === 401) {
      localStorage.removeItem('vulnlens_token');
      localStorage.removeItem('vulnlens_user');
      if (!window.location.pathname.startsWith('/login')) {
        window.location.href = '/login';
      }
    }
    return Promise.reject(err);
  }
);

export default api;