import { useEffect, useRef } from 'react';
import { NavLink } from 'react-router-dom';
import { Activity, FolderKanban, Gauge, History, Radar, ScanSearch, Settings, ShieldCheck, Sparkles, UploadCloud, X } from 'lucide-react';
import { cx } from '../../utils/helpers.js';

const GROUPS = [
  {
    label: 'Overview',
    items: [
      { to: '/', label: 'Overview', icon: Gauge, end: true },
      { to: '/projects', label: 'Projects', icon: FolderKanban, end: false },
    ],
  },
  {
    label: 'Scans',
    items: [
      { to: '/scans/new', label: 'New Scan', icon: UploadCloud, end: true },
      { to: '/scans', label: 'Scan History', icon: History, end: false },
    ],
  },
  {
    label: 'Investigate',
    items: [
      { to: '/findings', label: 'Findings', icon: ScanSearch, end: true },
      { to: '/security-analysis', label: 'Data Flow', icon: Radar, end: true },
      { to: '/ai-copilot', label: 'AI Copilot', icon: Sparkles, end: true },
    ],
  },
  {
    label: 'Output',
    items: [
      { to: '/reports', label: 'Reports', icon: Activity, end: true },
      { to: '/settings', label: 'Settings', icon: Settings, end: true },
    ],
  },
];

function Brand() {
  return (
    <div className="flex h-16 items-center gap-2.5 border-b border-edge px-5">
      <div className="flex h-8 w-8 items-center justify-center rounded-md border border-accent-500/30 bg-accent-500/15 text-accent-300">
        <ShieldCheck size={17} strokeWidth={2.2} aria-hidden="true" />
      </div>
      <div className="leading-tight">
        <p className="text-[13px] font-bold tracking-tight text-slate-100">VulnLens</p>
        <p className="text-[9px] font-medium uppercase tracking-widest2 text-accent-400/80">AI Security</p>
      </div>
    </div>
  );
}

function NavList({ onNavigate }) {
  return (
    <nav className="flex-1 space-y-5 overflow-y-auto px-3 py-4" aria-label="Primary">
      {GROUPS.map((group) => (
        <div key={group.label}>
          <p className="px-2.5 pb-1.5 text-2xs font-semibold uppercase tracking-widest2 text-slate-600">{group.label}</p>
          <ul className="space-y-0.5">
            {group.items.map(({ to, label, icon: Icon, end }) => (
              <li key={to}>
                <NavLink
                  to={to}
                  end={end}
                  onClick={onNavigate}
                  className={({ isActive }) =>
                    cx(
                      'group flex items-center gap-2.5 rounded-md px-2.5 py-[7px] text-[13px] font-medium transition-colors',
                      isActive ? 'bg-base-800 text-slate-100 ring-1 ring-inset ring-edge-strong' : 'text-slate-400 hover:bg-base-850/70 hover:text-slate-200'
                    )
                  }
                >
                  {({ isActive }) => (
                    <>
                      <Icon size={16} className={isActive ? 'text-accent-400' : 'text-slate-500 group-hover:text-slate-400'} aria-hidden="true" />
                      <span className="truncate">{label}</span>
                      {isActive ? <span className="ml-auto h-1.5 w-1.5 rounded-full bg-accent-400" aria-hidden="true" /> : null}
                    </>
                  )}
                </NavLink>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </nav>
  );
}

export function Sidebar({ onNavigate }) {
  return (
    <aside className="hidden w-60 shrink-0 flex-col border-r border-edge bg-base-925/80 lg:flex">
      <Brand />
      <NavList onNavigate={onNavigate} />
      <div className="border-t border-edge px-5 py-3">
        <p className="text-2xs text-slate-600">Deterministic scanner · AI explanation layer</p>
      </div>
    </aside>
  );
}

export function MobileSidebar({ open, onClose }) {
  const closeRef = useRef(null);

  // Escape closes the drawer; focus lands on the close button while open and
  // returns to the trigger when it closes.
  useEffect(() => {
    if (!open) return undefined;
    const prev = document.activeElement;
    const t = window.setTimeout(() => closeRef.current?.focus(), 0);
    function onKey(e) {
      if (e.key === 'Escape') onClose();
    }
    document.addEventListener('keydown', onKey);
    return () => {
      window.clearTimeout(t);
      document.removeEventListener('keydown', onKey);
      if (prev && typeof prev.focus === 'function') prev.focus();
    };
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-40 lg:hidden" role="dialog" aria-modal="true" aria-label="Navigation">
      <div className="absolute inset-0 bg-base-950/80" onClick={onClose} aria-hidden="true" />
      <aside className="absolute inset-y-0 left-0 flex w-64 flex-col border-r border-edge bg-base-925 shadow-lift">
        <div className="flex items-center pr-2">
          <Brand />
          <button ref={closeRef} onClick={onClose} className="btn-ghost ml-auto mr-1 p-2 text-slate-400" aria-label="Close navigation">
            <X size={16} />
          </button>
        </div>
        <NavList onNavigate={onClose} />
      </aside>
    </div>
  );
}
