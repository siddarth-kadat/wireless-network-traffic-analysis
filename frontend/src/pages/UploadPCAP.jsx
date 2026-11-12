import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  UploadCloud,
  FileCheck,
  AlertCircle,
  HardDrive,
  Cpu,
  CheckCircle2,
  ArrowRight,
  ShieldAlert,
} from 'lucide-react';
import { batchService } from '../services/batchService';
import { useAuth } from '../context/AuthContext';
import StatusBadge from '../components/StatusBadge';

export default function UploadPCAP() {
  const { user } = useAuth();
  const navigate = useNavigate();

  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [isProcessing, setIsProcessing] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const [resultBatch, setResultBatch] = useState(null);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const validateAndSetFile = (file) => {
    setErrorMessage('');
    setResultBatch(null);
    setUploadProgress(0);

    if (!file) return;

    const validExtensions = ['.pcap', '.pcapng', '.cap'];
    const hasValidExt = validExtensions.some((ext) => file.name.toLowerCase().endsWith(ext));

    if (!hasValidExt) {
      setErrorMessage(
        `Invalid file extension "${file.name}". Supported network capture formats: ${validExtensions.join(', ')}`
      );
      setSelectedFile(null);
      return;
    }

    setSelectedFile(file);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndSetFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileInput = (e) => {
    if (e.target.files && e.target.files[0]) {
      validateAndSetFile(e.target.files[0]);
    }
  };

  const handleStartProcessing = async () => {
    if (!selectedFile) return;

    setIsProcessing(true);
    setErrorMessage('');

    try {
      const batch = await batchService.uploadBatch(
        selectedFile,
        user?.user_id,
        (progress) => setUploadProgress(progress)
      );
      setResultBatch(batch);
    } catch (err) {
      setErrorMessage(err.message || 'PCAP processing encountered an error.');
    } finally {
      setIsProcessing(false);
    }
  };

  const formatFileSize = (bytes) => {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
  };

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      {/* Page Title */}
      <div>
        <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
          <span>PCAP Log Ingestion Station</span>
          <span className="text-xs px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-400 font-mono">
            E1 ENGINE
          </span>
        </h1>
        <p className="text-xs text-slate-400">
          Upload raw packet captures (.pcap, .pcapng) for concurrent ingestion, deterministic validation, and layer parsing.
        </p>
      </div>

      {/* Upload Box */}
      <div className="soc-card p-6 md:p-8 space-y-6">
        {errorMessage && (
          <div className="p-4 rounded-lg bg-rose-950/50 border border-rose-800 text-xs text-rose-300 flex items-center gap-3">
            <AlertCircle className="w-5 h-5 flex-shrink-0 text-rose-400" />
            <span>{errorMessage}</span>
          </div>
        )}

        <div
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
          className={`border-2 border-dashed rounded-xl p-8 md:p-12 text-center transition flex flex-col items-center justify-center gap-4 ${
            dragActive
              ? 'border-cyan-400 bg-cyan-950/20'
              : 'border-slate-700/80 hover:border-slate-500 bg-slate-900/30'
          }`}
        >
          <div className="w-16 h-16 rounded-full bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <UploadCloud className="w-8 h-8" />
          </div>

          <div className="space-y-1">
            <p className="text-sm font-semibold text-white">
              Drag & Drop PCAP Capture Here or{' '}
              <label className="text-cyan-400 hover:text-cyan-300 cursor-pointer underline">
                Browse Files
                <input
                  type="file"
                  accept=".pcap,.pcapng,.cap"
                  onChange={handleFileInput}
                  className="hidden"
                />
              </label>
            </p>
            <p className="text-xs text-slate-400">
              Accepted formats: <span className="font-mono text-cyan-400">.pcap</span>,{' '}
              <span className="font-mono text-cyan-400">.pcapng</span> (IEEE 802.11 Wireless Frames & IP Packets)
            </p>
          </div>

          {selectedFile && (
            <div className="mt-2 p-3 rounded-lg bg-slate-900 border border-slate-700 flex items-center gap-3 text-xs font-mono text-slate-200">
              <FileCheck className="w-4 h-4 text-emerald-400" />
              <span className="font-bold">{selectedFile.name}</span>
              <span className="text-slate-500">({formatFileSize(selectedFile.size)})</span>
            </div>
          )}
        </div>

        {/* Progress Bar */}
        {isProcessing && (
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs font-mono text-slate-400">
              <span className="flex items-center gap-2">
                <span className="w-3 h-3 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
                <span>E1 Parser: Extracting layers and validating batch...</span>
              </span>
              <span>{uploadProgress}%</span>
            </div>
            <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-cyan-400 transition-all duration-300 ease-out"
                style={{ width: `${uploadProgress}%` }}
              />
            </div>
          </div>
        )}

        {/* Action Button */}
        {!resultBatch && (
          <button
            onClick={handleStartProcessing}
            disabled={!selectedFile || isProcessing}
            className="w-full py-3 px-4 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-40 disabled:cursor-not-allowed text-slate-950 font-bold rounded-lg text-sm flex items-center justify-center gap-2 transition"
          >
            <Cpu className="w-4 h-4" />
            <span>Process Capture with E1 Log Engine</span>
          </button>
        )}

        {/* Success Output Card */}
        {resultBatch && (
          <div className="p-5 rounded-xl bg-emerald-950/20 border border-emerald-800/80 space-y-4 animate-fadeIn">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
                <CheckCircle2 className="w-5 h-5" />
                <span>PCAP Batch Successfully Processed</span>
              </div>
              <StatusBadge value={resultBatch.processing_status} />
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
              <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                <span className="text-slate-500 block">Batch ID</span>
                <span className="text-white truncate block">{resultBatch.batch_id}</span>
              </div>
              <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                <span className="text-slate-500 block">Capture Format</span>
                <span className="text-white uppercase">{resultBatch.file_format}</span>
              </div>
              <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                <span className="text-slate-500 block">Total Records</span>
                <span className="text-emerald-400 font-bold">{resultBatch.total_records}</span>
              </div>
              <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                <span className="text-slate-500 block">Processed Records</span>
                <span className="text-cyan-400 font-bold">{resultBatch.processed_records}</span>
              </div>
            </div>

            <div className="pt-2 flex flex-col sm:flex-row items-center justify-end gap-3">
              <button
                onClick={() => {
                  setSelectedFile(null);
                  setResultBatch(null);
                }}
                className="w-full sm:w-auto py-2 px-4 rounded bg-slate-900 hover:bg-slate-800 text-xs text-slate-300 font-mono border border-slate-700"
              >
                Upload Another Capture
              </button>
              <button
                onClick={() => navigate('/traffic-logs')}
                className="w-full sm:w-auto py-2 px-4 rounded bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center justify-center gap-1.5"
              >
                <span>Inspect Extracted Logs</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Engine Architecture Context Box */}
      <div className="soc-card p-5 space-y-3 border-l-4 border-l-cyan-500 text-xs">
        <h3 className="text-sm font-bold text-white flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-cyan-400" />
          <span>E1 Log Processing Engine Architecture</span>
        </h3>
        <p className="text-slate-300">
          The E1 engine validates capture formats, performs layer decoding (Ethernet, RadioTap, IEEE 802.11 Management/Control/Data, IPv4/IPv6, TCP/UDP), extracts standardized network features, and populates the <code className="text-cyan-300 font-mono">Traffic_Log</code> entity in compliance with the approved 7-entity relational schema.
        </p>
      </div>
    </div>
  );
}

