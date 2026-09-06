import { NavLink } from 'react-router-dom';
import { LayoutDashboard, FolderKanban, ShieldAlert, UploadCloud } from 'lucide-react';

const NAV = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/projects', icon: FolderKanban, label: 'Projects' },
  { to: '/scans', icon: ShieldAlert, label: 'Scans' },
  { to: '/new-scan', icon: UploadCloud, label: 'New Scan' },
];

export function Sidebar() {
  return (
    <aside className="hidden w-56 shrink-0 border-r border-borderline bg-base-900 lg:flex lg:flex-col">
      <div className="flex h-14 items-center gap-2.5 border-b border-borderline px-4">
        <div className="flex h-7 w-7 items-center justify-center rounded-md bg-sky-600/20 text-sky-400">
          <ShieldAlert size={16} strokeWidth={2.4} />
        </div>
        <span className="text-sm font-bold tracking-tight text-slate-100">VulnLens<span className="text-sky-400"> AI</span></span>
      </div>

      <nav className="flex-1 space-y-0.5 px-2.5 py-3">
        {NAV.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-2.5 rounded-md px-3 py-2 text-[13px] font-medium transition-colors ${
                isActive
                  ? 'bg-sky-600/15 text-sky-300'
                  : 'text-slate-400 hover:bg-base-800 hover:text-slate-200'
              }`
            }
          >
            <Icon size={16} />
            {label}
          </NavLink>
        ))}
      </nav>

      <div className="border-t border-borderline px-4 py-3">
        <p className="text-[10px] text-slate-600">VulnLens AI v1.0</p>
      </div>
    </aside>
  );
}
