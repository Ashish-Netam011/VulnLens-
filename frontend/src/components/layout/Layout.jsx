import { Sidebar } from './Sidebar.jsx';
import { Topbar } from './Topbar.jsx';

export function Layout({ children }) {
  return (
    <div className="flex h-screen overflow-hidden bg-base-950">
      <Sidebar />
      <div className="flex flex-1 flex-col overflow-hidden">
        <Topbar />
        <main className="flex-1 overflow-y-auto px-4 py-6 sm:px-6 lg:px-8">{children}</main>
      </div>
    </div>
  );
}