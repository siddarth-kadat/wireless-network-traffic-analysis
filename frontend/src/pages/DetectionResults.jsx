import React, { useState, useEffect } from 'react';
import {
  Search,
  Filter,
  Eye,
  RefreshCw,
  ShieldAlert,
  Sliders,
  CheckCircle,
  FileText,
} from 'lucide-react';
import DataTable from '../components/DataTable';
import DetailModal from '../components/DetailModal';
import StatusBadge from '../components/StatusBadge';
import { detectionService } from '../services/detectionService';

export default function DetectionResults() {
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedResult, setSelectedResult] = useState(null);
  const [suspiciousFilter, setSuspiciousFilter] = useState('ALL'); // 'ALL' | 'TRUE' | 'FALSE'

  const fetchResults = async () => {
    setLoading(true);
    try {
      const data = await detectionService.getDetectionResults();
      setResults(data);
    } catch (err) {
      console.error('Failed to load detection results:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchResults();
  }, []);

  const filteredResults = results.filter((r) => {
    if (suspiciousFilter === 'TRUE') return r.is_suspicious === true;
    if (suspiciousFilter === 'FALSE') return r.is_suspicious === false;
    return true;
  });

  const columns = [
    {
      key: 'result_id',
      label: 'Result ID',
      render: (row) => <span className="text-cyan-400 font-bold">{row.result_id}</span>,
    },
    {
      key: 'detection_timestamp',
      label: 'Timestamp',
      render: (row) => (
        <span className="text-slate-400 text-[11px]">
          {new Date(row.detection_timestamp).toLocaleTimeString()}
        </span>
      ),
    },
    {
      key: 'rule_id',
      label: 'Triggered Rule',
      render: (row) => (
        <span className="px-2 py-0.5 rounded text-[11px] bg-slate-900 border border-slate-700 text-amber-300 font-bold">
          {row.rule_id}
        </span>
      ),
    },
    {
      key: 'log_id',
      label: 'Associated Log ID',
      render: (row) => <span className="text-slate-300 text-[11px]">{row.log_id}</span>,
    },
    {
      key: 'is_suspicious',
      label: 'Suspicious Verdict',
      render: (row) => (
        <StatusBadge
          value={row.is_suspicious ? 'CRITICAL' : 'RESOLVED'}
          type="severity"
          size="small"
        />
      ),
    },
    {
      key: 'evidence_summary',
      label: 'Evidence Summary',
      render: (row) => {
        const ev = row.evidence_data || {};
        return (
          <span className="text-slate-400 text-xs truncate max-w-xs block">
            {ev.reason || (ev.detected_rate ? `Rate: ${ev.detected_rate}/s (thresh ${ev.threshold})` : 'Threshold evaluated')}
          </span>
        );
      },
    },
    {
      key: 'actions',
      label: 'Inspect',
      sortable: false,
      render: (row) => (
        <button
          onClick={() => setSelectedResult(row)}
          className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-cyan-400 transition"
          title="Inspect Evidence Contract"
        >
          <Eye className="w-4 h-4" />
        </button>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            <span>Detection Results</span>
            <span className="text-xs px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-400 font-mono">
              DETECTION_RESULT ENTITY
            </span>
          </h1>
          <p className="text-xs text-slate-400">
            Outcomes from E2 Suspicious Pattern Detection Engine forwarded to E4 for Alert Generation.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchResults}
            className="p-2 rounded-lg bg-slate-900 border border-slate-700/80 text-slate-300 hover:text-cyan-400 transition"
            title="Refresh Detection Results"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex items-center gap-2 text-xs">
        <span className="text-slate-500 font-semibold uppercase tracking-wider mr-2">
          Verdict Filter:
        </span>
        {[
          { id: 'ALL', label: 'All Results' },
          { id: 'TRUE', label: 'Suspicious Threats' },
          { id: 'FALSE', label: 'Benign Traffic' },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setSuspiciousFilter(tab.id)}
            className={`px-3 py-1.5 rounded-lg font-mono transition ${
              suspiciousFilter === tab.id
                ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40 font-bold'
                : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Main DataTable */}
      <DataTable
        columns={columns}
        data={filteredResults}
        loading={loading}
        pageSize={10}
        searchPlaceholder="Search result ID, rule ID, or log ID..."
        searchKeys={['result_id', 'rule_id', 'log_id']}
        onRowClick={(row) => setSelectedResult(row)}
      />

      {/* Inspection Modal */}
      {selectedResult && (
        <DetailModal
          isOpen={!!selectedResult}
          onClose={() => setSelectedResult(null)}
          title={`Detection Result: ${selectedResult.result_id}`}
          subtitle={`Evaluated At: ${new Date(selectedResult.detection_timestamp).toLocaleString()}`}
          badge={
            <StatusBadge
              value={selectedResult.is_suspicious ? 'CRITICAL' : 'RESOLVED'}
              type="severity"
            />
          }
          rawJson={selectedResult}
          actions={
            <button
              onClick={() => setSelectedResult(null)}
              className="py-1.5 px-4 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs"
            >
              Done
            </button>
          }
        >
          <div className="space-y-4">
            <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
              <h4 className="text-xs font-bold uppercase tracking-wider text-amber-400 flex items-center gap-2">
                <Sliders className="w-4 h-4" />
                <span>Deterministic Rule Evaluation</span>
              </h4>
              <div className="grid grid-cols-2 gap-3 text-xs font-mono">
                <div>
                  <span className="text-slate-500 block">Matched Rule ID:</span>
                  <span className="text-white font-bold">{selectedResult.rule_id}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Associated Traffic Log:</span>
                  <span className="text-cyan-400 font-bold">{selectedResult.log_id}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Threat Classification:</span>
                  <span className={selectedResult.is_suspicious ? 'text-rose-400 font-bold' : 'text-emerald-400 font-bold'}>
                    {selectedResult.is_suspicious ? 'CONFIRMED SUSPICIOUS PATTERN' : 'BENIGN EVALUATION'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block">Engine Pipeline:</span>
                  <span className="text-slate-300">E2 Pattern Engine &rarr; E4 Alert Engine</span>
                </div>
              </div>
            </div>

            <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
              <h4 className="text-xs font-bold uppercase tracking-wider text-cyan-400 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4" />
                <span>Extracted Forensic Evidence</span>
              </h4>
              <pre className="text-xs font-mono text-cyan-300 whitespace-pre-wrap">
                {JSON.stringify(selectedResult.evidence_data, null, 2)}
              </pre>
            </div>
          </div>
        </DetailModal>
      )}
    </div>
  );
}

