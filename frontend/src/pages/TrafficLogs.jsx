import React, { useState, useEffect } from 'react';
import {
  FileText,
  Search,
  Download,
  Filter,
  Eye,
  RefreshCw,
  Layers,
  Radio,
} from 'lucide-react';
import DataTable from '../components/DataTable';
import DetailModal from '../components/DetailModal';
import { logService } from '../services/logService';

export default function TrafficLogs() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedLog, setSelectedLog] = useState(null);
  const [selectedProtocol, setSelectedProtocol] = useState('ALL');

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const data = await logService.getTrafficLogs();
      setLogs(data);
    } catch (err) {
      console.error('Failed to load traffic logs:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  const protocols = ['ALL', '802.11_MGMT', '802.11_DATA', 'TCP', 'UDP', 'ARP'];

  const filteredLogs = logs.filter((log) => {
    if (selectedProtocol === 'ALL') return true;
    return log.protocol === selectedProtocol;
  });

  const columns = [
    {
      key: 'log_id',
      label: 'LOG ID',
      render: (row) => <span className="text-primary font-bold font-mono">{row.log_id}</span>,
    },
    {
      key: 'timestamp',
      label: 'TIMESTAMP',
      render: (row) => (
        <span className="text-muted font-mono text-xs">
          {new Date(row.timestamp).toLocaleTimeString()}
        </span>
      ),
    },
    {
      key: 'protocol',
      label: 'PROTOCOL',
      render: (row) => (
        <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-subtle text-secondary border border-border">
          {row.protocol}
        </span>
      ),
    },
    {
      key: 'source_address',
      label: 'SOURCE ADDR / MAC',
      render: (row) => (
        <div className="space-y-0.5">
          <div className="text-secondary font-bold">{row.source_address || '—'}</div>
          <div className="text-muted text-[11px] font-mono">{row.source_mac || '—'}</div>
        </div>
      ),
    },
    {
      key: 'destination_address',
      label: 'DESTINATION ADDR / MAC',
      render: (row) => (
        <div className="space-y-0.5">
          <div className="text-secondary font-bold">{row.destination_address || '—'}</div>
          <div className="text-muted text-[11px] font-mono">{row.destination_mac || '—'}</div>
        </div>
      ),
    },
    {
      key: 'packet_length',
      label: 'LENGTH',
      render: (row) => <span className="font-mono text-secondary font-medium">{row.packet_length} B</span>,
    },
    {
      key: 'ssid',
      label: 'WIRELESS SSID',
      render: (row) => (
        <span className="font-medium text-secondary">
          {row.ssid || <span className="text-muted italic">Non-Wireless</span>}
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
            setSelectedLog(row);
          }}
          className="flex items-center gap-1.5 px-3 py-1 rounded-md bg-white hover:bg-subtle border border-border text-secondary font-bold text-xs transition"
        >
          <Eye className="w-3.5 h-3.5 text-muted" />
          <span>Inspect</span>
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
            NETWORK MONITORING // TRAFFIC EXPLORER
          </div>
          <h1 className="text-3xl font-extrabold tracking-tight text-secondary">
            Extracted Traffic Records
          </h1>
          <p className="text-sm text-muted mt-1">
            Normalized frame features dissected by E1 Log Processing Engine and stored in SQLite E3.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchLogs}
            className="flex items-center gap-2 px-4 py-2 rounded-md bg-white hover:bg-subtle border border-border text-secondary font-bold text-xs transition"
          >
            <RefreshCw className={`w-4 h-4 text-muted ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Protocol Filter Tabs */}
      <div className="flex flex-wrap items-center gap-2">
        {protocols.map((proto) => (
          <button
            key={proto}
            onClick={() => setSelectedProtocol(proto)}
            className={`px-4 py-1.5 rounded-full text-xs font-bold transition ${
              selectedProtocol === proto
                ? 'bg-primary text-white'
                : 'bg-white hover:bg-subtle border border-border text-secondary'
            }`}
          >
            {proto}
          </button>
        ))}
      </div>

      {/* Main Table */}
      <DataTable
        columns={columns}
        data={filteredLogs}
        loading={loading}
        pageSize={12}
        onRowClick={(row) => setSelectedLog(row)}
        searchPlaceholder="Search IP, MAC, SSID, Protocol, or Log ID..."
      />

      {/* Inspect Detail Modal */}
      <DetailModal
        isOpen={!!selectedLog}
        onClose={() => setSelectedLog(null)}
        title={`Packet Log Dissection: ${selectedLog?.log_id}`}
        subtitle={`Captured at ${selectedLog?.timestamp} by E1 Log Processing Engine`}
        data={selectedLog}
      >
        {selectedLog && (
          <div className="grid grid-cols-2 gap-4 text-xs">
            <div className="p-3.5 rounded-md bg-subtle border border-border">
              <span className="text-muted block text-[11px]">SOURCE HARDWARE / IP</span>
              <p className="text-secondary font-bold font-mono text-sm mt-0.5">{selectedLog.source_address || 'None'}</p>
              <p className="text-muted text-[11px] font-mono">{selectedLog.source_mac}</p>
            </div>
            <div className="p-3.5 rounded-md bg-subtle border border-border">
              <span className="text-muted block text-[11px]">DESTINATION HARDWARE / IP</span>
              <p className="text-secondary font-bold font-mono text-sm mt-0.5">{selectedLog.destination_address || 'None'}</p>
              <p className="text-muted text-[11px] font-mono">{selectedLog.destination_mac}</p>
            </div>
            <div className="p-3.5 rounded-md bg-subtle border border-border">
              <span className="text-muted block text-[11px]">WIRELESS SSID &amp; BSSID</span>
              <p className="text-secondary font-bold text-sm mt-0.5">{selectedLog.ssid || 'N/A'}</p>
              <p className="text-muted text-[11px] font-mono">{selectedLog.bssid || 'N/A'}</p>
            </div>
            <div className="p-3.5 rounded-md bg-subtle border border-border">
              <span className="text-muted block text-[11px]">CHANNEL &amp; SIGNAL</span>
              <p className="text-secondary font-bold text-sm mt-0.5">Channel {selectedLog.channel || 'Auto'}</p>
              <p className="text-muted text-[11px]">{selectedLog.signal_strength ? `${selectedLog.signal_strength} dBm` : 'N/A'}</p>
            </div>
          </div>
        )}
      </DetailModal>
    </div>
  );
}
