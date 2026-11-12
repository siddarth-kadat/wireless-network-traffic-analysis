import React, { useState, useEffect } from 'react';
import {
  Layers,
  AlertTriangle,
  CheckCircle2,
  Eye,
  RefreshCw,
  FileCode,
  AlertCircle,
  Clock,
} from 'lucide-react';
import DataTable from '../components/DataTable';
import DetailModal from '../components/DetailModal';
import StatusBadge from '../components/StatusBadge';
import { batchService } from '../services/batchService';

export default function ProcessingBatches() {
  const [batches, setBatches] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedBatch, setSelectedBatch] = useState(null);
  const [batchErrors, setBatchErrors] = useState([]);
  const [loadingErrors, setLoadingErrors] = useState(false);

  const fetchBatches = async () => {
    setLoading(true);
    try {
      const data = await batchService.getBatches();
      setBatches(data);
    } catch (err) {
      console.error('Failed to load batches:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchBatches();
  }, []);

  const handleInspectBatch = async (batch) => {
    setSelectedBatch(batch);
    setLoadingErrors(true);
    try {
      const errors = await batchService.getBatchErrors(batch.batch_id);
      setBatchErrors(errors);
    } catch (err) {
      console.error('Failed to load batch errors:', err);
      setBatchErrors([]);
    } finally {
      setLoadingErrors(false);
    }
  };

  const columns = [
    {
      key: 'batch_id',
      label: 'Batch ID',
      render: (row) => <span className="text-cyan-400 font-bold">{row.batch_id}</span>,
    },
    {
      key: 'file_name',
      label: 'PCAP Capture File',
      render: (row) => (
        <div className="space-y-0.5">
          <div className="text-white font-medium truncate max-w-xs">{row.file_name}</div>
          <div className="text-[10px] text-slate-500 font-mono uppercase">{row.file_format}</div>
        </div>
      ),
    },
    {
      key: 'processing_status',
      label: 'Processing Status',
      render: (row) => <StatusBadge value={row.processing_status} size="small" />,
    },
    {
      key: 'total_records',
      label: 'Total Packets',
      render: (row) => <span className="text-slate-300 font-bold">{row.total_records?.toLocaleString()}</span>,
    },
    {
      key: 'processed_records',
      label: 'Success / Failed',
      render: (row) => (
        <div className="flex items-center gap-1.5 font-mono text-xs">
          <span className="text-emerald-400">{row.processed_records}</span>
          <span className="text-slate-600">/</span>
          <span className={row.failed_records > 0 ? 'text-rose-400 font-bold' : 'text-slate-500'}>
            {row.failed_records}
          </span>
        </div>
      ),
    },
    {
      key: 'submitted_at',
      label: 'Submitted Timestamp',
      render: (row) => (
        <span className="text-slate-400 text-[11px]">
          {new Date(row.submitted_at).toLocaleString()}
        </span>
      ),
    },
    {
      key: 'actions',
      label: 'Diagnostics',
      sortable: false,
      render: (row) => (
        <button
          onClick={() => handleInspectBatch(row)}
          className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-cyan-400 transition"
          title="Inspect Batch Diagnostics & Errors"
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
            <span>Processing Batches & Diagnostics</span>
            <span className="text-xs px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-400 font-mono">
              LOG_BATCH & PROCESSING_ERROR
            </span>
          </h1>
          <p className="text-xs text-slate-400">
            Audit history of ingested PCAP captures and packet parsing failure telemetry.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchBatches}
            className="p-2 rounded-lg bg-slate-900 border border-slate-700/80 text-slate-300 hover:text-cyan-400 transition"
            title="Refresh Batches"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Main DataTable */}
      <DataTable
        columns={columns}
        data={batches}
        loading={loading}
        pageSize={10}
        searchPlaceholder="Search by batch ID or capture filename..."
        searchKeys={['batch_id', 'file_name', 'file_format', 'user_id']}
        onRowClick={(row) => handleInspectBatch(row)}
      />

      {/* Batch Diagnostics Modal */}
      {selectedBatch && (
        <DetailModal
          isOpen={!!selectedBatch}
          onClose={() => setSelectedBatch(null)}
          title={`Batch Diagnostics: ${selectedBatch.file_name}`}
          subtitle={`Batch ID: ${selectedBatch.batch_id} • Ingested by User: ${selectedBatch.user_id}`}
          badge={<StatusBadge value={selectedBatch.processing_status} />}
          rawJson={selectedBatch}
          actions={
            <button
              onClick={() => setSelectedBatch(null)}
              className="py-1.5 px-4 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs"
            >
              Done
            </button>
          }
        >
          <div className="space-y-4">
            {/* Batch Metrics Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
              <div className="p-3 rounded bg-slate-900 border border-slate-800">
                <span className="text-slate-500 block">Total Records</span>
                <span className="text-white font-bold">{selectedBatch.total_records}</span>
              </div>
              <div className="p-3 rounded bg-slate-900 border border-slate-800">
                <span className="text-slate-500 block">Successfully Parsed</span>
                <span className="text-emerald-400 font-bold">{selectedBatch.processed_records}</span>
              </div>
              <div className="p-3 rounded bg-slate-900 border border-slate-800">
                <span className="text-slate-500 block">Corrupt / Failed</span>
                <span className={selectedBatch.failed_records > 0 ? 'text-rose-400 font-bold' : 'text-slate-400'}>
                  {selectedBatch.failed_records}
                </span>
              </div>
              <div className="p-3 rounded bg-slate-900 border border-slate-800">
                <span className="text-slate-500 block">Format</span>
                <span className="text-cyan-400 uppercase">{selectedBatch.file_format}</span>
              </div>
            </div>

            {/* Associated Processing Errors (Processing_Error entity) */}
            <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-bold uppercase tracking-wider text-rose-400 flex items-center gap-2">
                  <AlertCircle className="w-4 h-4" />
                  <span>Processing Error Telemetry (Processing_Error Entity)</span>
                </h4>
                <span className="text-xs font-mono text-slate-400">
                  {batchErrors.length} recorded errors
                </span>
              </div>

              {loadingErrors ? (
                <div className="py-4 text-center text-xs text-slate-500">Loading error telemetry...</div>
              ) : batchErrors.length === 0 ? (
                <div className="p-3 rounded bg-emerald-950/20 border border-emerald-900/60 text-xs text-emerald-400 flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Zero parsing anomalies or frame corruption detected in this capture batch.</span>
                </div>
              ) : (
                <div className="space-y-2">
                  {batchErrors.map((err) => (
                    <div
                      key={err.error_id}
                      className="p-3 rounded bg-slate-950 border border-rose-900/40 text-xs font-mono space-y-1"
                    >
                      <div className="flex items-center justify-between text-[11px]">
                        <span className="text-rose-400 font-bold">{err.error_type}</span>
                        <span className="text-slate-500">Packet Index: {err.packet_index}</span>
                      </div>
                      <p className="text-slate-300 font-sans">{err.error_message}</p>
                      <div className="text-[10px] text-slate-500">
                        Error ID: {err.error_id} • Occurred: {new Date(err.occurred_at).toLocaleTimeString()}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </DetailModal>
      )}
    </div>
  );
}
