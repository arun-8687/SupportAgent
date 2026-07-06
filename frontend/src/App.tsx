import { useQuery } from '@tanstack/react-query';
import { NavLink, Navigate, Route, Routes } from 'react-router-dom';

import { api } from './api/client';
import { Dashboard } from './pages/Dashboard';
import { IncidentDetailPage } from './pages/IncidentDetail';
import { Approvals } from './pages/Approvals';

export default function App() {
  const me = useQuery({ queryKey: ['me'], queryFn: api.me });

  return (
    <>
      <header className="app-header">
        <h1>SRE Agent Console</h1>
        <nav>
          <NavLink to="/" end>
            Dashboard
          </NavLink>
          <NavLink to="/approvals">Approvals</NavLink>
        </nav>
        <div className="header-spacer" />
        <div className="identity">
          {me.data ? (
            <>
              <span>{me.data.identity}</span>
              <span className={`badge ${me.data.can_approve ? 'ok' : 'muted'}`}>
                {me.data.can_approve ? 'Approver' : 'Viewer'}
              </span>
            </>
          ) : (
            <span>…</span>
          )}
        </div>
      </header>

      <main className="container">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/approvals" element={<Approvals />} />
          <Route path="/incidents/:id" element={<IncidentDetailPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </>
  );
}
