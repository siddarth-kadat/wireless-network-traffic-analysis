import React, { useState } from 'react';
import {
  Settings as SettingsIcon,
  Server,
  Database,
  Cpu,
  ShieldCheck,
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
      name: 'Log Processing Engine',
      description: 'PCAP & PCAPNG ingest, layer decoders, concurrent queue',
      status: 'OPERATIONAL',
      version: 'v1.0.0 (Scapy/dpkt)',
    },
    {
      id: 'E2',
      name: 'Suspicious Pattern Detection Engine',
      description: 'Applies predefined deterministic rules, identifies anomalies',
      status: 'OPERATIONAL',
      version: 'v1.0.0 (Deterministic)',
    },
    {
      id: 'E3',
      name: 'Log and Alert Storage Engine',
      description: '7-Entity SQLite relational persistence via SQLAlchemy ORM',
      status: 'OPERATIONAL',
      version: 'v1.0.0 (SQLite 3)',
    },
    {
      id: 'E4',
      name: 'Alert Generation Engine',
      description: 'Generates structured security alerts from E2 results',
      status: 'OPERATIONAL',
      version: 'v1.0.0 (Contract Compliant)',
    },
  ];

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      {/* Page Header */}
      <div>
        <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
          <span>System Settings & Architecture Diagnostics</span>
          <span className="text-xs px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-400 font-mono">
            CONFIGURATION
          </span>
        </h1>
        <p className="text-xs text-slate-400">
          Engine status, backend API connectivity parameters, and local SOC state management.
        </p>
      </div>

      {/* Backend API Configuration */}
      <div className="soc-card p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2 text-white font-bold text-sm">
            <Server className="w-4 h-4 text-cyan-400" />
            <span>FastAPI Backend Service Endpoint</span>
          </div>
          <div
            className={`px-2.5 py-1 rounded-full text-[11px] font-mono border ${
              isLive
                ? 'bg-emerald-950/40 text-emerald-400 border-emerald-800'
                : 'bg-amber-950/40 text-amber-400 border-amber-800'
            }`}
          >
            {isLive ? 'CONNECTED (HTTP 200)' : 'STANDALONE SEED DEMO'}
          </div>
        </div>

        <div className="space-y-2">
          <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
            API Gateway Base URL
          </label>
          <div className="flex gap-3">
            <input
              type="text"
              value={apiUrl}
              onChange={(e) => setApiUrl(e.target.value)}
              className="flex-1 px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white font-mono focus:outline-none focus:border-cyan-500"
            />
            <button
              onClick={() => window.location.reload()}
              className="py-2 px-4 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200 transition"
            >
              Test Ping
            </button>
          </div>
          <p className="text-[11px] text-slate-500">
            When the FastAPI backend is running on <code className="text-cyan-400 font-mono">http://localhost:8000</code>, live endpoints are seamlessly utilized.
          </p>
        </div>
      </div>

      {/* Four Engines Architecture Grid */}
      <div className="soc-card p-6 space-y-4">
        <h3 className="text-sm font-bold text-white flex items-center gap-2">
          <Cpu className="w-4 h-4 text-cyan-400" />
          <span>Modular Four-Engine Operational Health</span>
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {engines.map((eng) => (
            <div
              key={eng.id}
              className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1.5"
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-cyan-400 font-mono">
                  {eng.id}: {eng.name}
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/40 text-emerald-400 border border-emerald-800">
                  {eng.status}
                </span>
              </div>
              <p className="text-xs text-slate-400">{eng.description}</p>
              <div className="text-[10px] text-slate-500 font-mono">{eng.version}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Database Schema Entities Card */}
      <div className="soc-card p-6 space-y-3">
        <h3 className="text-sm font-bold text-white flex items-center gap-2">
          <Database className="w-4 h-4 text-indigo-400" />
          <span>Approved 7-Entity Database Design Compliance</span>
        </h3>
        <p className="text-xs text-slate-400">
          The database consists of exactly seven entities as specified in the approved architecture:
        </p>
        <div className="flex flex-wrap gap-2 pt-1 font-mono text-xs">
          {['User', 'Log_Batch', 'Traffic_Log', 'Detection_Rule', 'Detection_Result', 'Alert', 'Processing_Error'].map((tbl) => (
            <span key={tbl} className="px-2.5 py-1 rounded bg-slate-900 border border-slate-700 text-slate-200">
              {tbl}
            </span>
          ))}
        </div>
      </div>

      {/* Reset State Action */}
      <div className="soc-card p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-l-4 border-l-rose-500">
        <div className="space-y-1">
          <h4 className="text-sm font-bold text-white">Reset Demonstration State</h4>
          <p className="text-xs text-slate-400">
            Re-seeds all in-memory alerts, uploaded batches, and detection results to baseline values.
          </p>
        </div>
        <button
          onClick={handleResetData}
          className="py-2 px-4 rounded bg-rose-950/60 hover:bg-rose-900 border border-rose-800 text-rose-300 font-mono text-xs flex items-center gap-2 transition"
        >
          <Trash2 className="w-4 h-4" />
          <span>Reset Demo Data</span>
        </button>
      </div>

      {resetSuccess && (
        <div className="p-3 rounded-lg bg-emerald-950/60 border border-emerald-800 text-xs text-emerald-300 flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4" />
          <span>Demo state successfully restored to initial seed.</span>
        </div>
      )}
    </div>
  );
}

