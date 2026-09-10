import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../api/client.js';
import { useAuth } from '../context/AuthContext.jsx';
import { Button } from '../components/ui/Button.jsx';
import { Alert } from '../components/ui/Alert.jsx';
import { AuthShell } from '../components/layout/AuthShell.jsx';
import { errorMessage } from '../utils/helpers.js';

export default function LoginPage() {
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  async function onStart() {
    setError('');
    setLoading(true);
    try {
      const { data } = await api.post('/auth/demo');
      login(data);
      navigate('/');
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <AuthShell
      title="VulnLens AI"
      subtitle="Detect the risk · trace the attack path · understand the impact · fix the vulnerability."
    >
      {error && <Alert variant="error" title="Something went wrong" className="mb-4">{error}</Alert>}
      <Button onClick={onStart} className="w-full" size="lg" disabled={loading}>
        {loading ? 'Starting…' : 'Start Demo'}
      </Button>
      <p className="mt-4 text-center text-[11px] text-slate-600">
        No account needed — jumps right in.
      </p>
    </AuthShell>
  );
}
