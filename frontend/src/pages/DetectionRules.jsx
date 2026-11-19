import React, { useState, useEffect } from 'react';
import {
  Sliders,
  Eye,
  RefreshCw,
  Power,
  ShieldCheck,
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
      label: 'RULE ID',
      render: (row) => <span className="text-primary font-bold font-mono">{row.rule_id}</span>,
    },
    {
      key: 'rule_name',
      label: 'RULE NAME',
      render: (row) => <span className="text-secondary font-bold font-sans">{row.rule_name}</span>,
    },
    {
      key: 'severity',
      label: 'SEVERITY',
      render: (row) => <StatusBadge value={row.severity} type="severity" size="small" />,
    },
    {
      key: 'is_active',
      label: 'STATE',
      render: (row) => <StatusBadge value={row.is_active} type="boolean" size="small" />,
    },
    {
      key: 'description',
      label: 'DETERMINISTIC LOGIC',
      render: (row) => <span className="text-muted text-xs truncate max-w-sm block">{row.description}</span>,
    },
    {
      key: 'actions',
      label: 'CONTROLS',
      sortable: false,
      render: (row) => (
        <div className="flex items-center gap-2">
          <button
            onClick={() => handleToggleRule(row.rule_id)}
            className={`p-1.5 rounded-md transition ${
              row.is_active
                ? 'text-primary hover:bg-primary/10'
                : 'text-muted hover:bg-subtle'
            }`}
            title={row.is_active ? 'Disable rule' : 'Enable rule'}
          >
            <Power className="w-4 h-4" />
          </button>
          <button
            onClick={() => setSelectedRule(row)}
            className="flex items-center gap-1.5 px-3 py-1 rounded-md bg-white hover:bg-subtle border border-border text-secondary font-bold text-xs transition"
          >
            <Eye className="w-3.5 h-3.5 text-muted" />
            <span>Logic</span>
          </button>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="p-6 md:p-8 rounded-md bg-white border border-border flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="text-xs text-primary font-bold uppercase tracking-wider mb-1">
            RULES ENGINE // E2 DETECTION POLICIES
          </div>
          <h1 className="text-3xl font-extrabold tracking-tight text-secondary">
            Deterministic Detection Rules
          </h1>
          <p className="text-sm text-muted mt-1">
            Signatures and behavioral threshold policies applied by E2 against incoming wireless frames.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchRules}
            className="flex items-center gap-2 px-4 py-2 rounded-md bg-white hover:bg-subtle border border-border text-secondary font-bold text-xs transition"
          >
            <RefreshCw className={`w-4 h-4 text-muted ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Main Table */}
      <DataTable
        columns={columns}
        data={rules}
        loading={loading}
        pageSize={10}
        onRowClick={(row) => setSelectedRule(row)}
        searchPlaceholder="Filter rules by Name, ID, or Severity..."
      />

      {/* Logic Detail Modal */}
      <DetailModal
        isOpen={!!selectedRule}
        onClose={() => setSelectedRule(null)}
        title={`Rule Logic: ${selectedRule?.rule_name}`}
        subtitle={`Rule Identifier: ${selectedRule?.rule_id}`}
        data={selectedRule}
      >
        {selectedRule && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="p-3.5 rounded-md bg-subtle border border-border">
                <span className="text-muted block text-[11px]">ACTIVE STATUS</span>
                <div className="mt-1">
                  <StatusBadge value={selectedRule.is_active} type="boolean" />
                </div>
              </div>
              <div className="p-3.5 rounded-md bg-subtle border border-border">
                <span className="text-muted block text-[11px]">EMITTED SEVERITY</span>
                <div className="mt-1">
                  <StatusBadge value={selectedRule.severity} type="severity" />
                </div>
              </div>
            </div>

            <div className="p-4 rounded-md border border-border bg-white space-y-2">
              <span className="text-xs font-bold text-secondary uppercase tracking-wider block">
                Rule Definition Description
              </span>
              <p className="text-xs text-secondary leading-relaxed">{selectedRule.description}</p>
            </div>
          </div>
        )}
      </DetailModal>
    </div>
  );
}
