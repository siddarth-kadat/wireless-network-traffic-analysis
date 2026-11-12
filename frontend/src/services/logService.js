import { apiRequest, SEED_TRAFFIC_LOGS } from './api';

/**
 * Traffic Logs API Service.
 */
export const logService = {
  /**
   * Fetches paginated, filtered traffic logs.
   */
  async getLogs(params = {}) {
    const query = new URLSearchParams(params).toString();
    const liveData = await apiRequest(`/api/logs${query ? `?${query}` : ''}`);

    if (liveData && Array.isArray(liveData.items)) {
      return liveData;
    }

    // High-fidelity fallback dataset
    let filtered = [...SEED_TRAFFIC_LOGS];

    if (params.protocol) {
      filtered = filtered.filter((l) => l.protocol.toLowerCase().includes(params.protocol.toLowerCase()));
    }
    if (params.search) {
      const q = params.search.toLowerCase();
      filtered = filtered.filter(
        (l) =>
          (l.source_address && l.source_address.toLowerCase().includes(q)) ||
          (l.destination_address && l.destination_address.toLowerCase().includes(q)) ||
          (l.source_mac && l.source_mac.toLowerCase().includes(q)) ||
          (l.destination_mac && l.destination_mac.toLowerCase().includes(q)) ||
          l.log_id.toLowerCase().includes(q)
      );
    }

    return {
      total: filtered.length,
      page: parseInt(params.page || 1, 10),
      limit: parseInt(params.limit || 10, 10),
      items: filtered,
    };
  },

  /**
   * Fetches a single traffic log by ID.
   */
  async getLogById(logId) {
    const live = await apiRequest(`/api/logs/${logId}`);
    if (live) return live;
    return SEED_TRAFFIC_LOGS.find((l) => l.log_id === logId) || null;
  },

  /**
   * Aggregated traffic stats for Plotly charts.
   */
  async getTrafficStats() {
    const live = await apiRequest('/api/logs/stats/summary');
    if (live) return live;

    return {
      total_packets: 4500,
      protocol_breakdown: {
        '802.11_MGMT': 1420,
        TCP: 1850,
        UDP: 980,
        ARP: 250,
      },
      time_series: [
        { time: '10:00', packets_per_sec: 120, bytes_per_sec: 14200 },
        { time: '10:15', packets_per_sec: 280, bytes_per_sec: 38500 },
        { time: '10:30', packets_per_sec: 190, bytes_per_sec: 24100 },
        { time: '10:45', packets_per_sec: 150, bytes_per_sec: 18400 },
        { time: '11:00', packets_per_sec: 340, bytes_per_sec: 49200 },
        { time: '11:15', packets_per_sec: 210, bytes_per_sec: 29800 },
        { time: '11:30', packets_per_sec: 480, bytes_per_sec: 64500 },
        { time: '11:45', packets_per_sec: 780, bytes_per_sec: 104200 },
        { time: '12:00', packets_per_sec: 310, bytes_per_sec: 41200 },
      ],
    };
  },
};
