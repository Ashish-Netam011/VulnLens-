import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../api/client.js';
import { Layout } from '../components/layout/Layout.jsx';
import { PageHeader } from '../components/layout/PageHeader.jsx';
import { Card } from '../components/ui/Card.jsx';
import { Button } from '../components/ui/Button.jsx';
import { ErrorState } from '../components/ui/ErrorState.jsx';
import { useAuth } from '../context/AuthContext.jsx';
import { User, ShieldCheck, KeyRound } from 'lucide-react';

export default function SettingsPage() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState('');
  const [me, setMe] = useState(null);

  useEffect(() => {
    api
      .get('/auth/me')
      .then(({ data }) => setMe(data.user))
      .catch((err) => setError(err?.response?.data?.error || 'Could not load account details'));
  }, []);

  function signOut() {
    logout();
    navigate('/login');
  }

  return (
    <Layout>
      <PageHeader
        eyebrow="Output"
        title="Settings"
        description="Your session and account. Scanner, AI-provider and CI configuration live server-side and are deliberately not exposed in this interface."
      />

      {error && <div className="mb-4"><ErrorState title="Could not load account" message={error} /></div>}

      <div className="grid gap-5 lg:grid-cols-2">
        <Card className="card-pad">
          <div className="flex items-center gap-3">
            <span className="flex h-10 w-10 items-center justify-center rounded-full border border-edge bg-base-850 text-accent-300">
              <User size={17} aria-hidden="true" />
            </span>
            <div className="min-w-0">
              <p className="text-sm font-semibold text-slate-100">{me?.name || user?.name || 'VulnLens user'}</p>
              <p className="truncate font-mono text-xs text-slate-500">{me?.email || user?.email}</p>
            </div>
          </div>
          <div className="mt-4 border-t border-edge pt-4">
            <Button variant="danger" onClick={signOut}>Sign out of this session</Button>
          </div>
        </Card>

        <Card className="card-pad">
          <div className="flex items-center gap-3">
            <span className="flex h-10 w-10 items-center justify-center rounded-lg border border-edge bg-base-850 text-accent-300">
              <ShieldCheck size={17} aria-hidden="true" />
            </span>
            <div>
              <p className="text-sm font-semibold text-slate-100">Security model</p>
              <p className="text-xs text-slate-500">How VulnLens keeps you in control</p>
            </div>
          </div>
          <ul className="mt-4 space-y-2.5 text-[13px] leading-relaxed text-slate-400">
            <li className="flex gap-2"><KeyRound size={14} className="mt-0.5 shrink-0 text-slate-600" /> API keys for AI providers stay server-side and are never sent to the model prompt.</li>
            <li className="flex gap-2"><ShieldCheck size={14} className="mt-0.5 shrink-0 text-slate-600" /> The deterministic scanner decides severity, confidence and the CI gate — AI only explains.</li>
            <li className="flex gap-2"><KeyRound size={14} className="mt-0.5 shrink-0 text-slate-600" /> All scans, projects and reports are ownership-isolated to your account.</li>
          </ul>
        </Card>
      </div>
    </Layout>
  );
}
