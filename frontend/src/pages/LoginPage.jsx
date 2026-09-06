import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import api from '../api/client.js';
import { useAuth } from '../context/AuthContext.jsx';
import { Button } from '../components/ui/Button.jsx';
import { Alert } from '../components/ui/Alert.jsx';
import { errorMessage } from '../utils/helpers.js';
import { ShieldAlert } from 'lucide-react';

export default function LoginPage() {
  const [form, setForm] = useState({ email: '', password: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  async function onSubmit(e) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const { data } = await api.post('/auth/login', form);
      login(data);
      navigate('/');
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-base-950 px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center gap-3">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-sky-600/15 text-sky-400">
            <ShieldAlert size={24} />
          </div>
          <h1 className="text-xl font-bold text-slate-50">Sign in to VulnLens<span className="text-sky-400"> AI</span></h1>
          <p className="text-center text-sm text-slate-400">Secure code analysis for developers</p>
        </div>

        <div className="card card-pad">
          {error && <Alert variant="error" title="Sign-in failed">{error}</Alert>}
          <form onSubmit={onSubmit} className="mt-3 flex flex-col gap-4">
            <div>
              <label htmlFor="email" className="label">Email</label>
              <input id="email" type="email" required value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} className="input" placeholder="you@example.com" autoFocus />
            </div>
            <div>
              <label htmlFor="password" className="label">Password</label>
              <input id="password" type="password" required value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} className="input" placeholder="••••••••" />
            </div>
            <Button type="submit" className="w-full" disabled={loading}>
              {loading ? 'Signing in...' : 'Sign In'}
            </Button>
          </form>
          <p className="mt-4 text-center text-xs text-slate-500">
            No account?{' '}
            <Link to="/register" className="text-sky-400 hover:text-sky-300">Create one</Link>
          </p>
        </div>
      </div>
    </div>
  );
}