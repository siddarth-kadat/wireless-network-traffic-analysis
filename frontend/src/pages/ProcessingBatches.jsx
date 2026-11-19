import React, { useState, useEffect } from 'react';
import {
  Layers,
  AlertTriangle,
  Eye,
  RefreshCw,
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
      label: 'BATCH ID',
      render: (row) => <span className="text-primary font-bold font-mono">{row.batch_id}</span>,
    },
    {
      key: 'file_name',
      label: 'CAPTURE FILE',
      render: (row) => (
        <div className="space-y-0.5">
          <div className="text-secondary font-bold font-mono truncate max-w-xs">{row.file_name}</div>
          <div className="text-[11px] text-muted font-mono uppercase">{row.file_format}</div>
        </div>
      ),
    },
    {
      key: 'processing_status',
      label: 'STATUS',
      render: (row) => <StatusBadge value={row.processing_status} size="small" />,
    },
    {
      key: 'total_records',
      label: 'TOTAL PACKETS',
      render: (row) => <span className="text-secondary font-extrabold">{row.total_records?.toLocaleString()}</span>,
    },
    {
      key: 'processed_records',
      label: 'PROCESSED / FAILED',
      render: (row) => (
        <div className="flex items-center gap-1.5 font-mono text-xs">
          <span className="text-primary font-bold">{row.processed_records}</span>
          <span className="text-border">/</span>
          <span className={row.failed_records > 0 ? 'text-error font-bold' : 'text-muted'}>
            {row.failed_records}
          </span>
        </div>
      ),
    },
    {
      key: 'created_at',
      label: 'INGESTION TIME',
      render: (row) => (
        <span className="text-muted text-xs">
          {new Date(row.created_at).toLocaleString()}
        </span>
      ),
    },
    {
      key: 'actions',
      label: 'ACTIONS',
      sortable: false,
      render: (row) => (
        <button
          onClick={(e) => {
            e.stopPropagation();
            handleInspectBatch(row);
          }}
          className="flex items-center gap-1.5 px-3 py-1 rounded-md bg-white hover:bg-subtle border border-border text-secondary font-bold text-xs transition"
        >
          <Eye className="w-3.5 h-3.5 text-muted" />
          <span>Audit</span>
        </button>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="p-6 md:p-8 rounded-md bg-white border border-border flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="text-xs text-primary font-bold uppercase tracking-wider mb-1">
            INGESTION PIPELINE // E1 &amp; E3 ENGINE
          </div>
          <h1 className="text-3xl font-extrabold tracking-tight text-secondary">
            Capture Processing Batches
          </h1>
          <p className="text-sm text-muted mt-1">
            Historical audit log of all ingested PCAP/PCAPNG datasets, extraction metrics, and error rates.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchBatches}
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
        data={batches}
        loading={loading}
        pageSize={10}
        onRowClick={(row) => handleInspectBatch(row)}
        searchPlaceholder="Search by Batch ID, File Name, Format..."
      />

      {/* Audit Detail Modal */}
      <DetailModal
        isOpen={!!selectedBatch}
        onClose={() => setSelectedBatch(null)}
        title={`Batch Audit: ${selectedBatch?.batch_id}`}
        subtitle={`Capture File: ${selectedBatch?.file_name} (${selectedBatch?.file_format})`}
        data={selectedBatch}
      >
        {selectedBatch && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
              <div className="p-3 rounded-md bg-subtle border border-border">
                <span className="text-muted block text-[11px]">STATUS</span>
                <div className="mt-1">
                  <StatusBadge value={selectedBatch.processing_status} />
                </div>
              </div>
              <div className="p-3 rounded-md bg-subtle border border-border">
                <span className="text-muted block text-[11px]">TOTAL RECORDS</span>
                <span className="text-secondary font-bold text-sm block mt-1">{selectedBatch.total_records}</span>
              </div>
              <div className="p-3 rounded-md bg-subtle border border-border">
                <span className="text-muted block text-[11px]">SUCCESSFULLY PARSED</span>
                <span className="text-primary font-bold text-sm block mt-1">{selectedBatch.processed_records}</span>
              </div>
              <div className="p-3 rounded-md bg-subtle border border-border">
                <span className="text-muted block text-[11px]">CORRUPT / DROPPED</span>
                <span className={`font-bold text-sm block mt-1 ${selectedBatch.failed_records > 0 ? 'text-error' : 'text-muted'}`}>
                  {selectedBatch.failed_records}
                </span>
              </div>
            </div>

            {/* Batch Errors Section */}
            <div className="border border-border rounded-md p-4 bg-white space-y-3">
              <h4 className="text-xs font-bold text-secondary uppercase tracking-wider flex items-center gap-2">
                <AlertCircle className="w-4 h-4 text-error" />
                <span>Ingestion Faults &amp; Validation Errors</span>
              </h4>

              {loadingErrors ? (
                <p className="text-xs text-muted">Querying fault logs...</p>
              ) : batchErrors.length === 0 ? (
                <p className="text-xs text-primary font-medium">
                  Zero frame corruption or validation anomalies logged for this batch.
                </p>
              ) : (
                <div className="divide-y divide-border text-xs">
                  {batchErrors.map((err, idx) => (
                    <div key={idx} className="py-2 space-y-0.5">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-error">{err.error_type}</span>
                        <span className="text-muted text-[11px]">{err.timestamp}</span>
                      </div>
                      <p className="text-muted">{err.error_message}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </DetailModal>
    </div>
  );
}
