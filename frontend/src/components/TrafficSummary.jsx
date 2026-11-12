import React from 'react';
import { Activity, ShieldCheck, Database, HardDrive } from 'lucide-react';

export default function TrafficSummary({ totalPackets = 0, totalBytes = 0, protocols = [], activeAlerts = 0 }) {
  const formattedBytes = (bytes) => {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
  };

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      <div className="soc-card p-4 space-y-1">
        <div className="flex items-center gap-2 text-slate-400 text-xs">
          <Activity className="w-4 h-4 text-cyan-400" />
          <span>Analyzed Packets</span>
        </div>
        <p className="text-xl font-bold font-mono text-white">{totalPackets.toLocaleString()}</p>
      </div>

      <div className="soc-card p-4 space-y-1">
        <div className="flex items-center gap-2 text-slate-400 text-xs">
          <HardDrive className="w-4 h-4 text-emerald-400" />
          <span>Data Ingested</span>
        </div>
        <p className="text-xl font-bold font-mono text-white">{formattedBytes(totalBytes)}</p>
      </div>

      <div className="soc-card p-4 space-y-1">
        <div className="flex items-center gap-2 text-slate-400 text-xs">
          <Database className="w-4 h-4 text-indigo-400" />
          <span>Protocols Detected</span>
        </div>
        <p className="text-xl font-bold font-mono text-white">{protocols.length || '3'}</p>
      </div>

      <div className="soc-card p-4 space-y-1">
        <div className="flex items-center gap-2 text-slate-400 text-xs">
          <ShieldCheck className="w-4 h-4 text-amber-400" />
          <span>Active Alerts</span>
        </div>
        <p className="text-xl font-bold font-mono text-white">{activeAlerts}</p>
      </div>
    </div>
  );
}
