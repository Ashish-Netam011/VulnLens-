import { Link } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';

export function PageHeader({ eyebrow, title, description, actions, backTo, backLabel }) {
  return (
    <div className="mb-6 flex flex-wrap items-start justify-between gap-x-6 gap-y-3">
      <div className="min-w-0">
        {backTo ? (
          <Link to={backTo} className="mb-2 inline-flex items-center gap-1 text-xs text-slate-500 transition-colors hover:text-slate-300">
            <ArrowLeft size={13} /> {backLabel || 'Back'}
          </Link>
        ) : null}
        {eyebrow ? <p className="eyebrow">{eyebrow}</p> : null}
        <h1 className="mt-1 text-xl font-bold tracking-tight text-slate-50">{title}</h1>
        {description ? <p className="mt-1 max-w-2xl text-sm leading-relaxed text-slate-400">{description}</p> : null}
      </div>
      {actions ? <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}
