/**
 * Batch Service
 * 
 * Handles PCAP/PCAPNG file uploads and processing batch queries.
 * Interacts with backend /api/batches endpoints, falling back to local SOC seed state.
 */
import { apiRequest, SEED_BATCHES, SEED_PROCESSING_ERRORS } from './api';

// In-memory mutable batch store initialized with seed batches
let localBatches = [...SEED_BATCHES];
let localErrors = [...SEED_PROCESSING_ERRORS];

export const batchService = {
  /**
   * Retrieve all log batches with optional status filter
   */
  async getBatches(statusFilter = 'ALL') {
    const live = await apiRequest('/api/batches');
    const source = live && Array.isArray(live) ? live : localBatches;
    
    if (statusFilter && statusFilter !== 'ALL') {
      return source.filter((b) => b.processing_status === statusFilter);
    }
    return [...source];
  },

  /**
   * Retrieve single batch details by batch_id
   */
  async getBatchById(batchId) {
    const live = await apiRequest(`/api/batches/${batchId}`);
    if (live) return live;
    return localBatches.find((b) => b.batch_id === batchId) || null;
  },

  /**
   * Upload a PCAP/PCAPNG capture file
   */
  async uploadBatch(file, userId, onProgress) {
    // Basic validation
    if (!file) throw new Error('No capture file selected.');
    const validExts = ['.pcap', '.pcapng', '.cap'];
    const hasValidExt = validExts.some((ext) => file.name.toLowerCase().endsWith(ext));
    if (!hasValidExt) {
      throw new Error(`Invalid file format. Supported formats: ${validExts.join(', ')}`);
    }

    // Try live upload endpoint first
    const formData = new FormData();
    formData.append('file', file);
    formData.append('user_id', userId || 'usr-admin-01');

    try {
      const live = await apiRequest('/api/batches/upload', {
        method: 'POST',
        body: formData,
      });
      if (live && live.batch_id) {
        localBatches.unshift(live);
        return live;
      }
    } catch (err) {
      console.warn('[batchService] Backend upload failed or unmapped, simulating batch execution.', err);
    }

    // Simulate progress if callback provided
    if (onProgress) {
      for (let p = 15; p <= 90; p += 25) {
        onProgress(p);
        await new Promise((r) => setTimeout(r, 60));
      }
      onProgress(100);
    }

    // High fidelity simulated batch matching Log_Batch entity
    const fileExt = file.name.toLowerCase().endsWith('.pcapng') ? 'pcapng' : 'pcap';
    const estimatedPackets = Math.max(120, Math.floor(file.size / 128));
    const newBatch = {
      batch_id: `batch-${Math.random().toString(16).substring(2, 6)}-${Date.now().toString(16).substring(8)}`,
      user_id: userId || 'usr-admin-01',
      file_name: file.name,
      file_format: fileExt,
      submitted_at: new Date().toISOString(),
      processing_status: 'SUCCESS',
      total_records: estimatedPackets,
      processed_records: estimatedPackets,
      failed_records: 0,
    };

    localBatches.unshift(newBatch);
    return newBatch;
  },

  /**
   * Retrieve processing errors associated with a batch
   */
  async getBatchErrors(batchId) {
    const live = await apiRequest(`/api/batches/${batchId}/errors`);
    if (live && Array.isArray(live)) return live;
    return localErrors.filter((e) => !batchId || e.batch_id === batchId);
  },

  /**
   * Reset local state to seed data (useful for test resets)
   */
  resetState() {
    localBatches = [...SEED_BATCHES];
    localErrors = [...SEED_PROCESSING_ERRORS];
  },
};
