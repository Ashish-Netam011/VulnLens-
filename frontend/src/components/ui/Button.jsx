export function Button({ variant = 'primary', className = '', type = 'button', children, ...props }) {
  const base = {
    primary: 'btn-primary',
    secondary: 'btn-secondary',
    danger: 'btn-danger',
    ghost: 'btn-ghost',
  }[variant];
  return (
    <button type={type} className={`${base} ${className}`.trim()} {...props}>
      {children}
    </button>
  );
}