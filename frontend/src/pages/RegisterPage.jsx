import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import api from '../api/client.js';
import { useAuth } from '../context/AuthContext.jsx';
import { Button } from '../components/ui/Button.jsx';
import { Alert } from '../components/ui/Alert.jsx';
import { errorMessage } from '../utils/helpers.js';
import { ShieldAlert } from 'lucide-react';

export default function RegisterPage() {
  const [form, setForm] = useState({ name: '', email: '', password: '', confirm: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  async function onSubmit(e) {
    e.preventDefault();
    setError('');
    if (form.password.length < 8) {
      setError('Password must be at least 8 characters.');
      return;
    }
    if (form.password !== form.confirm) {
      setError('Passwords do not match.');
      return;
    }
    setLoading(true);
    try {
      const { data } = await api.post('/auth/register', {
        name: form.name,
        email: form.email,
        password: form.password,
      });
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
          <h1 className="text-xl font-bold text-slate-50">Create your account</h1>
          <p className="text-center text-sm text-slate-400">Join VulnLens AI</p>
        </div>

        <div className="card card-pad">
          {error && <Alert variant="error" title="Registration failed">{error}</Alert>}
          <form onSubmit={onSubmit} className="mt-3 flex flex-col gap-4">
            <div>
              <label htmlFor="name" className="label">Name (optional)</label>
              <input id="name" type="text" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} className="input" placeholder="Jane Developer" />
            </div>
            <div>
              <label htmlFor="email" className="label">Email</label>
              <input id="email" type="email" required value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} className="input" placeholder="you@example.com" autoFocus />
            </div>
            <div>
              <label htmlFor="password" className="label">Password</label>
              <input id="password" type="password" required value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} className="input" placeholder="At least 8 characters" />
            </div>
            <div>
              <label htmlFor="confirm" className="label">Confirm Password</label>
              <input id="confirm" type="password" required value={form.confirm} onChange={(e) => setForm({ ...form, confirm: e.target.value })} className="input" placeholder="••••••••" />
            </div>
            <Button type="submit" className="w-full" disabled={loading}>
              {loading ? 'Creating account...' : 'Create Account'}
            </Button>
          </form>
          <p className="mt-4 text-center text-xs text-slate-500">
            Already have an account?{' '}
            <Link to="/login" className="text-sky-400 hover:text-sky-300">Sign in</Link>
          </p>
        </div>
      </div>
    </div>
  );
}