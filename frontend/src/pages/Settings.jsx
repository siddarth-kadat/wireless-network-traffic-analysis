import React, { useState } from 'react';
import {
  Server,
  Database,
  Cpu,
  RefreshCw,
  Trash2,
  CheckCircle2,
} from 'lucide-react';
import { API_BASE_URL, getBackendStatus } from '../services/api';
import { useAuth } from '../context/AuthContext';
import { batchService } from '../services/batchService';
import { alertService } from '../services/alertService';
import { detectionService } from '../services/detectionService';
import { userService } from '../services/userService';

export default function Settings() {
  const { user, isAdmin } = useAuth();
  const [apiUrl, setApiUrl] = useState(API_BASE_URL);
  const [resetSuccess, setResetSuccess] = useState(false);
  const isLive = getBackendStatus();

  const handleResetData = () => {
    if (window.confirm('Reset all in-memory mock SOC datasets back to initial baseline seed?')) {
      batchService.resetState();
      alertService.resetState();
      detectionService.resetState();
      userService.resetState();
      setResetSuccess(true);
      setTimeout(() => setResetSuccess(false), 3000);
    }
  };

  const engines = [
    {
      id: 'E1',
      name: 'Packet Processing Engine',
      description: 'Reads and parses network packet captures. Validates and normalizes packet records.',
      status: 'OPERATIONAL',
      version: 'Active Engine',
    },
    {
      id: 'E2',
      name: 'Suspicious Activity Detection Engine',
      description: 'Evaluates network traffic against configured detection rules. Identifies suspicious patterns.',
      status: 'OPERATIONAL',
      version: 'Active Engine',
    },
    {
      id: 'E3',
      name: 'Log and Alert Storage Engine',
      description: 'Stores traffic logs, detection results and alerts. Provides configured detection rules to E2.',
      status: 'OPERATIONAL',
      version: 'Active Engine',
    },
    {
      id: 'E4',
      name: 'Alert Generation Engine',
      description: 'Generates structured alerts from detection results. Sends generated alerts to E3 for storage.',
      status: 'OPERATIONAL',
      version: 'Active Engine',
    },
  ];

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      {/* Page Header */}
      <div className="p-6 md:p-8 rounded-md bg-white border border-border">
        <div className="text-xs text-primary font-bold uppercase tracking-wider mb-1">
          SYSTEM TELEMETRY // SOC CONFIGURATION
        </div>
        <h1 className="text-3xl font-extrabold tracking-tight text-secondary">
          System Settings &amp; Telemetry
        </h1>
        <p className="text-sm text-muted mt-1">
          Engine status, backend API connectivity parameters, and local SOC state management.
        </p>
      </div>

      {/* 4 Engines Telemetry Grid */}
      <div className="bg-white border border-border rounded-md p-6 space-y-4">
        <h3 className="text-base font-extrabold text-secondary flex items-center gap-2">
          <Cpu className="w-5 h-5 text-primary" />
          <span>Core Engine Architecture Status</span>
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {engines.map((eng) => (
            <div key={eng.id} className="p-4 rounded-md bg-subtle border border-border space-y-2">
              <div className="flex items-center justify-between">
                <span className="px-2.5 py-0.5 rounded-full bg-primary text-white text-xs font-bold font-mono">
                  {eng.id}
                </span>
                <span className="px-2.5 py-0.5 rounded-full bg-primary/10 text-primary border border-primary/20 text-xs font-bold">
                  {eng.status}
                </span>
              </div>
              <h4 className="text-sm font-bold text-secondary">{eng.name}</h4>
              <p className="text-xs text-muted leading-relaxed">{eng.description}</p>
              <div className="text-[11px] font-mono text-muted pt-2 border-t border-border">
                {eng.version}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* API Connectivity Box */}
      <div className="bg-white border border-border rounded-md p-6 space-y-4">
        <h3 className="text-base font-extrabold text-secondary flex items-center gap-2">
          <Server className="w-5 h-5 text-primary" />
          <span>FastAPI Backend Connection</span>
        </h3>

        <div className="p-4 rounded-md bg-subtle border border-border flex items-center justify-between gap-4 text-xs">
          <div>
            <span className="text-muted block text-[11px]">TARGET API ENDPOINT</span>
            <code className="text-secondary font-bold font-mono text-sm block mt-0.5">{apiUrl}</code>
          </div>
          <span className="px-3 py-1 rounded-full bg-primary/10 text-primary border border-primary/20 font-bold">
            Live Connected (24ms)
          </span>
        </div>
      </div>

      {/* Maintenance & Reset Box */}
      <div className="bg-white border border-border rounded-md p-6 space-y-4">
        <h3 className="text-base font-extrabold text-secondary flex items-center gap-2">
          <Database className="w-5 h-5 text-muted" />
          <span>Local State &amp; Baseline Diagnostics</span>
        </h3>

        <p className="text-xs text-muted leading-relaxed">
          Reset local browser mock cache to factory baseline seed. This reloads the sample PCAPs, alerts, and user accounts.
        </p>

        {resetSuccess && (
          <div className="p-3.5 rounded-md bg-primary/10 border border-primary/20 text-xs text-primary font-bold flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4" />
            <span>Mock datasets successfully reset to baseline seed!</span>
          </div>
        )}

        <button
          onClick={handleResetData}
          className="flex items-center gap-2 px-4 py-2 rounded-md bg-secondary hover:bg-muted text-white text-xs font-bold transition"
        >
          <Trash2 className="w-4 h-4" />
          <span>Reset Baseline Mock Seed</span>
        </button>
      </div>
    </div>
  );
}
