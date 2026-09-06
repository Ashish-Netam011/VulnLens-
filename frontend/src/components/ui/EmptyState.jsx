export function EmptyState({ icon: Icon, title, message, action }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed border-borderline px-6 py-14 text-center">
      {Icon ? (
        <div className="flex h-12 w-12 items-center justify-center rounded-full bg-base-800 text-slate-500">
          <Icon size={22} />
        </div>
      ) : null}
      <div>
        <p className="text-sm font-semibold text-slate-200">{title}</p>
        {message ? <p className="mx-auto mt-1 max-w-md text-[13px] text-slate-500">{message}</p> : null}
      </div>
      {action}
    </div>
  );
}