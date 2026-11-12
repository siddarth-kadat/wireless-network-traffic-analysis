import React, { useState, useEffect } from 'react';
import {
  Sliders,
  CheckCircle2,
  AlertCircle,
  Eye,
  RefreshCw,
  Power,
  ShieldCheck,
  Cpu,
} from 'lucide-react';
import DataTable from '../components/DataTable';
import DetailModal from '../components/DetailModal';
import StatusBadge from '../components/StatusBadge';
import { detectionService } from '../services/detectionService';
import { useAuth } from '../context/AuthContext';

export default function DetectionRules() {
  const { isAdmin } = useAuth();
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedRule, setSelectedRule] = useState(null);

  const fetchRules = async () => {
    setLoading(true);
    try {
      const data = await detectionService.getRules();
      setRules(data);
    } catch (err) {
      console.error('Failed to load detection rules:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const handleToggleRule = async (ruleId) => {
    try {
      const updated = await detectionService.toggleRule(ruleId);
      setRules((prev) =>
        prev.map((r) => (r.rule_id === ruleId ? updated : r))
      );
      if (selectedRule && selectedRule.rule_id === ruleId) {
        setSelectedRule(updated);
      }
    } catch (err) {
      console.error('Failed to toggle rule state:', err);
    }
  };

  const columns = [
    {
      key: 'rule_id',
      label: 'Rule Identifier',
      render: (row) => <span className="text-cyan-400 font-bold">{row.rule_id}</span>,
    },
    {
      key: 'rule_name',
      label: 'Rule Name',
      render: (row) => <span className="text-white font-semibold font-sans">{row.rule_name}</span>,
    },
    {
      key: 'severity',
      label: 'Severity Level',
      render: (row) => <StatusBadge value={row.severity} type="severity" size="small" />,
    },
    {
      key: 'is_active',
      label: 'Engine State',
      render: (row) => <StatusBadge value={row.is_active} type="boolean" size="small" />,
    },
    {
      key: 'description',
      label: 'Deterministic Detection Logic',
      render: (row) => <span className="text-slate-300 text-xs font-sans truncate max-w-sm block">{row.description}</span>,
    },
    {
      key: 'actions',
      label: 'Controls',
      sortable: false,
      render: (row) => (
        <div className="flex items-center gap-2">
          <button
            onClick={() => handleToggleRule(row.rule_id)}
            className={`p-1.5 rounded transition ${row.is_active
                ? 'text-emerald-400 hover:bg-emerald-950/60'
                : 'text-slate-500 hover:bg-slate-800'
              }`}
            title={row.is_active ? 'Disable Rule in E2 Engine' : 'Enable Rule in E2 Engine'}
          >
            <Power className="w-4 h-4" />
          </button>
          <button
            onClick={() => setSelectedRule(row)}
            className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
            title="Inspect Mathematical Condition"
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
            <span>Deterministic Detection Rules</span>
            <span className="text-xs px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-400 font-mono">
              DETECTION_RULE ENTITY
            </span>
          </h1>
          <p className="text-xs text-slate-400">
            Predefined deterministic rules retrieved from E3 and applied by E2 Suspicious Pattern Detection Engine.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchRules}
            className="p-2 rounded-lg bg-slate-900 border border-slate-700/80 text-slate-300 hover:text-cyan-400 transition"
            title="Refresh Rules"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Deterministic Assurance Card */}
      <div className="soc-card p-4 bg-slate-900/60 border-l-4 border-l-cyan-500 flex items-start gap-3">
        <Cpu className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
        <div className="text-xs space-y-1">
          <p className="font-bold text-white uppercase tracking-wider">
            Deterministic Threat Modeling Guarantee
          </p>
          <p className="text-slate-300">
            All detection criteria utilize mathematical thresholds, temporal sliding windows, and discrete protocol field matching.
            The system strictly avoids opaque machine learning models to ensure zero hallucinations and 100% reproducible SOC audit trails.
          </p>
        </div>
      </div>

      {/* Main DataTable */}
      <DataTable
        columns={columns}
        data={rules}
        loading={loading}
        pageSize={10}
        searchPlaceholder="Search rule name, ID, or description..."
        searchKeys={['rule_id', 'rule_name', 'description', 'severity']}
        onRowClick={(row) => setSelectedRule(row)}
      />

      {/* Rule Inspection Modal */}
      {selectedRule && (
        <DetailModal
          isOpen={!!selectedRule}
          onClose={() => setSelectedRule(null)}
          title={selectedRule.rule_name}
          subtitle={`Rule ID: ${selectedRule.rule_id} • Status: ${selectedRule.is_active ? 'ACTIVE' : 'DISABLED'}`}
          badge={<StatusBadge value={selectedRule.severity} type="severity" />}
          rawJson={selectedRule}
          actions={
            <div className="flex items-center gap-3">
              <button
                onClick={() => handleToggleRule(selectedRule.rule_id)}
                className={`py-1.5 px-3 rounded text-xs font-bold ${selectedRule.is_active
                    ? 'bg-rose-950/80 border border-rose-800 text-rose-300 hover:bg-rose-900'
                    : 'bg-emerald-600 hover:bg-emerald-500 text-white'
                  }`}
              >
                {selectedRule.is_active ? 'Disable in Engine' : 'Activate in Engine'}
              </button>
              <button
                onClick={() => setSelectedRule(null)}
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
                Rule Description & Threat Vector
              </h4>
              <p className="text-sm text-slate-200">{selectedRule.description}</p>
            </div>

            <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
              <h4 className="text-xs font-bold uppercase tracking-wider text-cyan-400 flex items-center gap-2">
                <Sliders className="w-4 h-4" />
                <span>Deterministic Parameters (rule_condition)</span>
              </h4>
              <pre className="text-xs font-mono text-cyan-300 p-3 bg-slate-950 rounded border border-slate-800 overflow-x-auto">
                {JSON.stringify(selectedRule.rule_condition, null, 2)}
              </pre>
            </div>
          </div>
        </DetailModal>
      )}
    </div>
  );
}
