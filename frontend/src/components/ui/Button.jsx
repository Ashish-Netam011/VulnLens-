export function Button({ variant = 'primary', size = 'md', className = '', type = 'button', children, ...props }) {
  const base = {
    primary: 'btn-primary',
    secondary: 'btn-secondary',
    ghost: 'btn-ghost',
    danger: 'btn-danger',
  }[variant];
  const s = size === 'sm' ? 'px-2.5 py-1.5 text-xs' : size === 'lg' ? 'px-4 py-2.5 text-sm' : '';
  return (
    <button type={type} className={`${base} ${s} ${className}`.trim()} {...props}>
      {children}
    </button>
  );
}
