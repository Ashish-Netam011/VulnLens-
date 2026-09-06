import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuth } from './context/AuthContext.jsx';
import { PageLoader } from './components/ui/Spinner.jsx';
import LoginPage from './pages/LoginPage.jsx';
import RegisterPage from './pages/RegisterPage.jsx';
import OverviewPage from './pages/OverviewPage.jsx';
import ProjectsPage from './pages/ProjectsPage.jsx';
import ProjectDetailPage from './pages/ProjectDetailPage.jsx';
import NewScanPage from './pages/NewScanPage.jsx';
import ScansPage from './pages/ScansPage.jsx';
import ScanDetailPage from './pages/ScanDetailPage.jsx';
import FindingsPage from './pages/FindingsPage.jsx';
import FindingDetailPage from './pages/FindingDetailPage.jsx';
import SecurityAnalysisPage from './pages/SecurityAnalysisPage.jsx';
import AiCopilotPage from './pages/AiCopilotPage.jsx';
import ReportsPage from './pages/ReportsPage.jsx';
import SettingsPage from './pages/SettingsPage.jsx';

function Protected({ children }) {
  const { user, loading } = useAuth();
  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-base-950">
        <PageLoader label="Checking session…" />
      </div>
    );
  }
  if (!user) return <Navigate to="/login" replace />;
  return children;
}

function AuthGate({ children }) {
  const { user, loading } = useAuth();
  if (loading) return null;
  if (user) return <Navigate to="/" replace />;
  return children;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<AuthGate><LoginPage /></AuthGate>} />
      <Route path="/register" element={<AuthGate><RegisterPage /></AuthGate>} />

      <Route path="/" element={<Protected><OverviewPage /></Protected>} />
      <Route path="/projects" element={<Protected><ProjectsPage /></Protected>} />
      <Route path="/projects/:id" element={<Protected><ProjectDetailPage /></Protected>} />

      <Route path="/scans" element={<Protected><ScansPage /></Protected>} />
      <Route path="/scans/new" element={<Protected><NewScanPage /></Protected>} />
      <Route path="/scans/:id" element={<Protected><ScanDetailPage /></Protected>} />

      <Route path="/findings" element={<Protected><FindingsPage /></Protected>} />
      <Route path="/findings/:scanId/:key" element={<Protected><FindingDetailPage /></Protected>} />

      <Route path="/security-analysis" element={<Protected><SecurityAnalysisPage /></Protected>} />
      <Route path="/ai-copilot" element={<Protected><AiCopilotPage /></Protected>} />
      <Route path="/reports" element={<Protected><ReportsPage /></Protected>} />
      <Route path="/settings" element={<Protected><SettingsPage /></Protected>} />

      {/* Compatibility: old deep links */}
      <Route path="/new-scan" element={<Navigate to="/scans/new" replace />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
