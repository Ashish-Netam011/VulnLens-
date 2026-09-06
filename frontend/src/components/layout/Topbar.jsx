import { useAuth } from '../../context/AuthContext.jsx';
import { Link, useNavigate } from 'react-router-dom';
import { LogOut, Menu, Plus } from 'lucide-react';
import { cx } from '../../utils/helpers.js';

export function Topbar({ onMenu }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  function handleLogout() {
    logout();
    navigate('/login');
  }

  const initials = (user?.name || user?.email || 'U')
    .split(/[\s@]+/)
    .map((s) => s[0])
    .filter(Boolean)
    .slice(0, 2)
    .join('')
    .toUpperCase();

  return (
    <header className="flex h-16 shrink-0 items-center justify-between gap-3 border-b border-edge bg-base-925/60 px-4 backdrop-blur sm:px-6">
      <div className="flex items-center gap-2">
        <button onClick={onMenu} className="btn-ghost p-2 lg:hidden" aria-label="Open navigation">
          <Menu size={18} />
        </button>
        {/* Breadcrumb context is provided by each page header. */}
      </div>

      <div className="flex items-center gap-2.5">
        <Link to="/scans/new" className="btn-primary hidden sm:inline-flex" aria-label="Start a new scan">
          <Plus size={15} /> New Scan
        </Link>
        <div className="mx-1 hidden h-6 w-px bg-edge sm:block" aria-hidden="true" />
        <div className="flex items-center gap-2">
          <div className="flex h-7 w-7 items-center justify-center rounded-full bg-base-800 text-[11px] font-bold text-accent-300 ring-1 ring-inset ring-edge-strong" aria-hidden="true">
            {initials || 'U'}
          </div>
          <span className={cx('hidden max-w-[140px] truncate text-[13px] text-slate-300', 'md:inline')}>
            {user?.name || user?.email}
          </span>
        </div>
        <button onClick={handleLogout} className="btn-ghost p-2 text-slate-500 hover:text-slate-200" title="Sign out" aria-label="Sign out">
          <LogOut size={15} />
        </button>
      </div>
    </header>
  );
}
