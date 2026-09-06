import { useAuth } from '../../context/AuthContext.jsx';
import { useNavigate } from 'react-router-dom';
import { LogOut, User } from 'lucide-react';

export function Topbar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  function handleLogout() {
    logout();
    navigate('/login');
  }

  return (
    <header className="flex h-14 shrink-0 items-center justify-between border-b border-borderline bg-base-900 px-4">
      <div className="flex items-center gap-2.5 lg:hidden">
        <div className="flex h-6 w-6 items-center justify-center rounded bg-sky-600/20 text-sky-400">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s-8-4.5-8-11.8A8 8 0 0 1 12 2a8 8 0 0 1 8 8.2c0 7.3-8 11.8-8 11.8Z"/>
            <circle cx="12" cy="10" r="3"/>
          </svg>
        </div>
        <span className="text-sm font-bold text-slate-100">VulnLens<span className="text-sky-400"> AI</span></span>
      </div>

      <div />
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2 text-sm text-slate-400">
          <div className="flex h-6 w-6 items-center justify-center rounded-full bg-base-700 text-slate-300">
            <User size={13} />
          </div>
          <span className="hidden text-[13px] sm:inline">{user?.name || user?.email}</span>
        </div>
        <button onClick={handleLogout} className="btn-ghost p-1.5 text-slate-500 hover:text-slate-200" title="Sign out">
          <LogOut size={15} />
        </button>
      </div>
    </header>
  );
}
