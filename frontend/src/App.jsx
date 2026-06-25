import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import Home from './pages/Home';
import Login from './pages/Login';
import Register from './pages/Register';
import NewRun from './pages/NewRun';
import RunStatus from './pages/RunStatus';
import Report from './pages/Report';
import Reports from './pages/Reports';
import Profile from './pages/Profile';
import Guides from './pages/Guides';

function RequireAuth({ children }) {
  return localStorage.getItem('token') ? children : <Navigate to="/login" replace />;
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login"    element={<Login />} />
        <Route path="/register" element={<Register />} />

        {/* Public introductory landing — restrictions & requirements live here. */}
        <Route path="/" element={<Home />} />

        <Route path="/dashboard" element={<RequireAuth><NewRun /></RequireAuth>} />
        <Route path="/reports" element={<RequireAuth><Reports /></RequireAuth>} />
        <Route path="/guides"  element={<RequireAuth><Guides /></RequireAuth>} />
        <Route path="/profile" element={<RequireAuth><Profile /></RequireAuth>} />

        <Route path="/runs/:runId/status" element={<RequireAuth><RunStatus /></RequireAuth>} />
        <Route path="/runs/:runId/report" element={<RequireAuth><Report /></RequireAuth>} />

        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
