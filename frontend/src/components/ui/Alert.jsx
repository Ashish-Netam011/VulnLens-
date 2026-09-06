export function Alert({ variant = 'info', title, children, className = '' }) {
  const styles = {
    error: 'border-critical/30 bg-critical/10 text-red-200',
    warning: 'border-amber-500/30 bg-amber-500/10 text-amber-200',
    success: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200',
    info: 'border-sky-500/30 bg-sky-500/10 text-sky-200',
  };
  return (
    <div className={`rounded-md border px-4 py-3 text-sm ${styles[variant]} ${className}`.trim()} role={variant === 'error' ? 'alert' : 'status'}>
      {title ? <p className="font-semibold">{title}</p> : null}
      {children}
    </div>
  );
}
