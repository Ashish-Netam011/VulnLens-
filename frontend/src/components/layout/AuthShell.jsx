import { ShieldCheck } from 'lucide-react';

export function AuthShell({ title, subtitle, children, footer }) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-base-950 px-4 py-10">
      <div
        className="pointer-events-none fixed inset-0 opacity-[0.35]"
        aria-hidden="true"
        style={{
          background:
            'radial-gradient(700px 300px at 20% -5%, rgba(99,102,241,0.14), transparent), radial-gradient(700px 340px at 90% 110%, rgba(34,211,238,0.07), transparent)',
        }}
      />
      <div className="relative w-full max-w-[380px]">
        <div className="mb-8 flex flex-col items-center gap-3 text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-accent-500/30 bg-accent-500/10 text-accent-300">
            <ShieldCheck size={24} aria-hidden="true" />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight text-slate-50">{title}</h1>
            <p className="mt-1 text-[13px] leading-relaxed text-slate-500">{subtitle}</p>
          </div>
        </div>
        <div className="card p-6 shadow-lift">{children}</div>
        {footer ? <p className="mt-5 text-center text-xs text-slate-500">{footer}</p> : null}
      </div>
    </div>
  );
}
