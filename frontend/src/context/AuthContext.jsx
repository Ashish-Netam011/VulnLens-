import { createContext, useContext, useEffect, useState } from 'react';
import api from '../api/client.js';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem('vulnlens_user') || 'null');
    } catch {
      return null;
    }
  });
  const [token, setToken] = useState(() => localStorage.getItem('vulnlens_token') || null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function bootstrap() {
      if (!token) {
        setLoading(false);
        return;
      }
      try {
        const { data } = await api.get('/auth/me');
        setUser(data.user);
      } catch {
        setUser(null);
        setToken(null);
        localStorage.removeItem('vulnlens_token');
      } finally {
        setLoading(false);
      }
    }
    bootstrap();
  }, []);

  function login(authData) {
    localStorage.setItem('vulnlens_token', authData.token);
    localStorage.setItem('vulnlens_user', JSON.stringify(authData.user));
    setToken(authData.token);
    setUser(authData.user);
  }

  function logout() {
    localStorage.removeItem('vulnlens_token');
    localStorage.removeItem('vulnlens_user');
    setToken(null);
    setUser(null);
  }

  return (
    <AuthContext.Provider value={{ user, token, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}