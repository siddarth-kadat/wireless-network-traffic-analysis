import React, { useState, useEffect } from 'react';
import {
  AlertTriangle,
  Search,
  CheckCircle2,
  Clock,
  Eye,
  RefreshCw,
  Check,
  CheckSquare,
  ShieldAlert,
} from 'lucide-react';
import DataTable from '../components/DataTable';
import DetailModal from '../components/DetailModal';
import StatusBadge from '../components/StatusBadge';
import { alertService } from '../services/alertService';

export default function Alerts() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');

  const fetchAlerts = async () => {
    setLoading(true);
    try {
      const data = await alertService.getAlerts();
      setAlerts(data);
    } catch (err) {
      console.error('Failed to load alerts:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, []);

  const handleAcknowledge = async (alertId) => {
    await alertService.acknowledgeAlert(alertId);
    setAlerts((prev) =>
      prev.map((a) => (a.alert_id === alertId ? { ...a, status: 'ACKNOWLEDGED' } : a))
    );
    if (selectedAlert && selectedAlert.alert_id === alertId) {
      setSelectedAlert((prev) => ({ ...prev, status: 'ACKNOWLEDGED' }));
    }
  };

  const handleResolve = async (alertId) => {
    await alertService.resolveAlert(alertId);
    setAlerts((prev) =>
      prev.map((a) => (a.alert_id === alertId ? { ...a, status: 'RESOLVED' } : a))
    );
    if (selectedAlert && selectedAlert.alert_id === alertId) {
      setSelectedAlert((prev) => ({ ...prev, status: 'RESOLVED' }));
    }
  };

  const filteredAlerts = alerts.filter((alert) => {
    if (severityFilter !== 'ALL' && alert.severity !== severityFilter) return false;
    if (statusFilter !== 'ALL' && alert.status !== statusFilter) return false;
    return true;
  });

  const columns = [
    {
      key: 'alert_id',
      label: 'Alert ID',
      render: (row) => <span className="text-cyan-400 font-bold">{row.alert_id}</span>,
    },
    {
      key: 'severity',
      label: 'Severity',
      render: (row) => <StatusBadge value={row.severity} type="severity" size="small" />,
    },
    {
      key: 'status',
      label: 'Status',
      render: (row) => <StatusBadge value={row.status} type="status" size="small" />,
    },
    {
      key: 'alert_type',
      label: 'Threat Classification',
      render: (row) => <span className="text-white font-semibold font-sans">{row.alert_type}</span>,
    },
    {
      key: 'message',
      label: 'Incident Narrative',
      render: (row) => <span className="text-slate-300 text-xs font-sans truncate max-w-sm block">{row.message}</span>,
    },
    {
      key: 'generated_at',
      label: 'Generated Timestamp',
      render: (row) => (
        <span className="text-slate-400 text-[11px]">
          {new Date(row.generated_at).toLocaleTimeString()}
        </span>
      ),
    },
    {
      key: 'actions',
      label: 'Triage Actions',
      sortable: false,
      render: (row) => (
        <div className="flex items-center gap-2">
          {row.status === 'NEW' && (
            <button
              onClick={(e) => {
                e.stopPropagation();
                handleAcknowledge(row.alert_id);
              }}
              className="py-1 px-2 rounded bg-cyan-950/60 hover:bg-cyan-900 border border-cyan-800 text-cyan-400 text-[11px] font-sans"
              title="Acknowledge incident"
            >
              Ack
            </button>
          )}
          {row.status !== 'RESOLVED' && (
            <button
              onClick={(e) => {
                e.stopPropagation();
                handleResolve(row.alert_id);
              }}
              className="py-1 px-2 rounded bg-emerald-950/60 hover:bg-emerald-900 border border-emerald-800 text-emerald-400 text-[11px] font-sans"
              title="Resolve incident"
            >
              Resolve
            </button>
          )}
          <button
            onClick={() => setSelectedAlert(row)}
            className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
            title="Inspect Alert Contract"
          >
            <Eye className="w-4 h-4" />
          </button>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            <span>Security Alerts Triage</span>
            <span className="text-xs px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-400 font-mono">
              E4 ALERT ENGINE
            </span>
          </h1>
          <p className="text-xs text-slate-400">
            Real-time security incident alerts generated by E4 Alert Generation Engine for Security Analyst triage.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchAlerts}
            className="p-2 rounded-lg bg-slate-900 border border-slate-700/80 text-slate-300 hover:text-cyan-400 transition"
            title="Refresh Alerts"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="flex flex-wrap items-center gap-4 text-xs">
        {/* Severity Filters */}
        <div className="flex items-center gap-1.5">
          <span className="text-slate-500 font-semibold uppercase tracking-wider mr-1">Severity:</span>
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-2.5 py-1 rounded font-mono transition ${
                severityFilter === sev
                  ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40 font-bold'
                  : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>

        {/* Status Filters */}
        <div className="flex items-center gap-1.5">
          <span className="text-slate-500 font-semibold uppercase tracking-wider mr-1">Status:</span>
          {['ALL', 'NEW', 'ACKNOWLEDGED', 'RESOLVED'].map((st) => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={`px-2.5 py-1 rounded font-mono transition ${
                statusFilter === st
                  ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40 font-bold'
                  : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
              }`}
            >
              {st}
            </button>
          ))}
        </div>
      </div>

      {/* Main DataTable */}
      <DataTable
        columns={columns}
        data={filteredAlerts}
        loading={loading}
        pageSize={10}
        searchPlaceholder="Search alert ID, threat type, or narrative..."
        searchKeys={['alert_id', 'alert_type', 'message', 'result_id']}
        onRowClick={(row) => setSelectedAlert(row)}
      />

      {/* Alert Inspection Modal */}
      {selectedAlert && (
        <DetailModal
          isOpen={!!selectedAlert}
          onClose={() => setSelectedAlert(null)}
          title={selectedAlert.alert_type}
          subtitle={`Alert ID: ${selectedAlert.alert_id} • Detection Result: ${selectedAlert.result_id}`}
          badge={<StatusBadge value={selectedAlert.severity} type="severity" />}
          rawJson={selectedAlert}
          actions={
            <div className="flex items-center gap-3">
              {selectedAlert.status === 'NEW' && (
                <button
                  onClick={() => handleAcknowledge(selectedAlert.alert_id)}
                  className="py-1.5 px-3 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs"
                >
                  Acknowledge Incident
                </button>
              )}
              {selectedAlert.status !== 'RESOLVED' && (
                <button
                  onClick={() => handleResolve(selectedAlert.alert_id)}
                  className="py-1.5 px-3 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs"
                >
                  Resolve Incident
                </button>
              )}
              <button
                onClick={() => setSelectedAlert(null)}
                className="py-1.5 px-3 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs"
              >
                Close
              </button>
            </div>
          }
        >
          <div className="space-y-4">
            <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">
                Security Incident Narrative
              </h4>
              <p className="text-sm text-slate-100">{selectedAlert.message}</p>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-xs font-mono">
              <div className="p-3 rounded bg-slate-900 border border-slate-800">
                <span className="text-slate-500 block">Severity</span>
                <StatusBadge value={selectedAlert.severity} type="severity" size="small" />
              </div>
              <div className="p-3 rounded bg-slate-900 border border-slate-800">
                <span className="text-slate-500 block">Triage Status</span>
                <StatusBadge value={selectedAlert.status} type="status" size="small" />
              </div>
              <div className="p-3 rounded bg-slate-900 border border-slate-800">
                <span className="text-slate-500 block">Timestamp</span>
                <span className="text-white">{new Date(selectedAlert.generated_at).toLocaleString()}</span>
              </div>
            </div>
          </div>
        </DetailModal>
      )}
    </div>
  );
}
