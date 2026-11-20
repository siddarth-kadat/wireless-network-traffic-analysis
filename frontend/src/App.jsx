import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import ProtectedRoute from './components/ProtectedRoute';
import SOCLayout from './layouts/SOCLayout';

// Pages
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import UploadPCAP from './pages/UploadPCAP';
import TrafficLogs from './pages/TrafficLogs';
import Alerts from './pages/Alerts';
import DetectionResults from './pages/DetectionResults';
import DetectionRules from './pages/DetectionRules';
import ProcessingBatches from './pages/ProcessingBatches';
import Users from './pages/Users';
import Reports from './pages/Reports';
import Settings from './pages/Settings';
import EngineStatus from './pages/EngineStatus';
import NotFound from './pages/NotFound';

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          {/* Public Authentication Route */}
          <Route path="/login" element={<Login />} />

          {/* Protected SOC Console Application */}
          <Route
            element={
              <ProtectedRoute>
                <SOCLayout />
              </ProtectedRoute>
            }
          >
            <Route path="/" element={<Dashboard />} />
            <Route path="/upload" element={<UploadPCAP />} />
            <Route path="/traffic-logs" element={<TrafficLogs />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/detections" element={<DetectionResults />} />
            <Route path="/rules" element={<DetectionRules />} />
            <Route path="/batches" element={<ProcessingBatches />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/system-logs" element={<Reports />} />
            <Route path="/engine-status" element={<EngineStatus />} />
            <Route
              path="/users"
              element={
                <ProtectedRoute requiredRole="Network Administrator">
                  <Users />
                </ProtectedRoute>
              }
            />
            <Route path="/settings" element={<Settings />} />
            <Route path="*" element={<NotFound />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
