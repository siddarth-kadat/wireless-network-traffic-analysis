import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  UploadCloud,
  FileCheck,
  AlertCircle,
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
        `Invalid file extension "${file.name}". Supported capture formats: ${validExtensions.join(', ')}`
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
      {/* Page Header */}
      <div className="p-6 md:p-8 rounded-md bg-white border border-border">
        <div className="text-xs text-primary font-bold uppercase tracking-wider mb-1">
          NETWORK MONITORING // PCAP FILE PROCESSING
        </div>
        <h1 className="text-3xl font-extrabold tracking-tight text-secondary">
          PCAP File Processing
        </h1>
        <p className="text-sm text-muted mt-1">
          Upload raw packet captures (.pcap, .pcapng) for packet parsing, layer extraction, and automated suspicious activity detection.
        </p>
      </div>

      {/* Upload Box */}
      <div className="bg-white border border-border rounded-md p-6 md:p-8 space-y-6">
        {errorMessage && (
          <div className="p-4 rounded-md bg-error/10 border border-error/20 text-xs text-error flex items-center gap-3">
            <AlertCircle className="w-5 h-5 flex-shrink-0" />
            <span className="font-medium">{errorMessage}</span>
          </div>
        )}

        <div
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
          className={`border-2 border-dashed rounded-md p-10 md:p-14 text-center transition flex flex-col items-center justify-center gap-4 ${
            dragActive
              ? 'border-primary bg-primary/5'
              : 'border-border hover:border-primary/50 bg-subtle/30'
          }`}
        >
          <div className="w-16 h-16 rounded-full bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
            <UploadCloud className="w-8 h-8" />
          </div>

          <div className="space-y-1.5">
            <p className="text-base font-bold text-secondary">
              Drag &amp; Drop PCAP Capture Here or{' '}
              <label className="text-primary hover:text-primary-hover cursor-pointer underline font-bold">
                Browse Files
                <input
                  type="file"
                  accept=".pcap,.pcapng,.cap"
                  onChange={handleFileInput}
                  className="hidden"
                />
              </label>
            </p>
            <p className="text-xs text-muted">
              Accepted formats: <span className="font-mono font-bold text-secondary">.pcap</span>,{' '}
              <span className="font-mono font-bold text-secondary">.pcapng</span> (IEEE 802.11 Wireless Frames &amp; IP Packets)
            </p>
          </div>

          {selectedFile && (
            <div className="mt-2 p-3 rounded-md bg-white border border-border flex items-center gap-3 text-xs text-secondary">
              <FileCheck className="w-5 h-5 text-primary" />
              <span className="font-bold">{selectedFile.name}</span>
              <span className="text-muted">({formatFileSize(selectedFile.size)})</span>
            </div>
          )}
        </div>

        {/* Progress Bar */}
        {isProcessing && (
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs text-muted">
              <span className="flex items-center gap-2">
                <span className="w-3.5 h-3.5 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                <span>Packet Processing Engine: Extracting layers and validating records...</span>
              </span>
              <span className="font-bold text-secondary">{uploadProgress}%</span>
            </div>
            <div className="w-full h-2 bg-subtle rounded-full overflow-hidden">
              <div
                className="h-full bg-primary transition-all duration-300 ease-out"
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
            className="w-full py-3 px-4 bg-primary hover:bg-primary-hover active:bg-primary disabled:opacity-40 disabled:cursor-not-allowed text-white font-bold rounded-md text-sm flex items-center justify-center gap-2 transition shadow-2xs"
          >
            <Cpu className="w-4 h-4" />
            <span>Process Capture with Packet Processing Engine</span>
          </button>
        )}

        {/* Success Output Card */}
        {resultBatch && (
          <div className="p-6 rounded-md bg-primary/5 border border-primary/20 space-y-4 animate-fadeIn">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-primary font-bold text-base">
                <CheckCircle2 className="w-5 h-5 text-primary" />
                <span>PCAP Capture File Successfully Processed</span>
              </div>
              <StatusBadge value={resultBatch.processing_status} />
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
              <div className="p-3 rounded-md bg-white border border-border">
                <span className="text-muted block text-[11px]">BATCH ID</span>
                <span className="text-secondary font-bold font-mono truncate block mt-0.5">{resultBatch.batch_id}</span>
              </div>
              <div className="p-3 rounded-md bg-white border border-border">
                <span className="text-muted block text-[11px]">CAPTURE FORMAT</span>
                <span className="text-secondary font-bold uppercase mt-0.5 block">{resultBatch.file_format}</span>
              </div>
              <div className="p-3 rounded-md bg-white border border-border">
                <span className="text-muted block text-[11px]">TOTAL RECORDS</span>
                <span className="text-primary font-extrabold mt-0.5 block">{resultBatch.total_records}</span>
              </div>
              <div className="p-3 rounded-md bg-white border border-border">
                <span className="text-muted block text-[11px]">PROCESSED RECORDS</span>
                <span className="text-secondary font-extrabold mt-0.5 block">{resultBatch.processed_records}</span>
              </div>
            </div>

            <div className="pt-3 flex flex-col sm:flex-row items-center justify-end gap-3">
              <button
                onClick={() => {
                  setSelectedFile(null);
                  setResultBatch(null);
                }}
                className="w-full sm:w-auto py-2 px-4 rounded-md bg-white hover:bg-subtle text-xs text-secondary border border-border font-bold transition"
              >
                Upload Another Capture
              </button>
              <button
                onClick={() => navigate('/traffic-logs')}
                className="w-full sm:w-auto py-2 px-4 rounded-md bg-primary hover:bg-primary-hover text-white font-bold text-xs flex items-center justify-center gap-2 transition"
              >
                <span>Inspect Extracted Logs</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Engine Architecture Context Box */}
      <div className="bg-white border border-border border-l-4 border-l-primary rounded-md p-5 space-y-2 text-xs">
        <h3 className="text-xs font-bold text-secondary flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-primary" />
          <span>E1 Log Processing Engine Architecture</span>
        </h3>
        <p className="text-muted leading-relaxed">
          The E1 engine validates capture formats, performs layer decoding (Ethernet, RadioTap, IEEE 802.11 Management/Control/Data, IPv4/IPv6, TCP/UDP), extracts standardized network features, and populates the <code className="text-primary font-mono bg-subtle px-1.5 py-0.5 rounded font-bold">Traffic_Log</code> entity in compliance with the approved 7-entity relational schema.
        </p>
      </div>
    </div>
  );
}
