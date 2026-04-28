import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import Login from "./pages/Login";
import Register from "./pages/Register";
import NewRun from "./pages/NewRun";
import RunStatus from "./pages/RunStatus";
import Report from "./pages/Report";

function RequireAuth({ children }) {
  return localStorage.getItem("token") ? children : <Navigate to="/login" replace />;
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/" element={<RequireAuth><NewRun /></RequireAuth>} />
        <Route path="/runs/:runId/status" element={<RequireAuth><RunStatus /></RequireAuth>} />
        <Route path="/runs/:runId/report" element={<RequireAuth><Report /></RequireAuth>} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
