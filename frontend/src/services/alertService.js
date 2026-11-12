import { apiRequest, SEED_ALERTS } from './api';

// In-memory alert state for interactive UI triage
let memoryAlerts = SEED_ALERTS.map(normalizeAlert);

function normalizeAlert(a) {
  return {
    ...a,
    status: a.status || a.alert_status || 'NEW',
    alert_status: a.status || a.alert_status || 'NEW',
    generated_at: a.generated_at || a.alert_timestamp || new Date().toISOString(),
    alert_timestamp: a.generated_at || a.alert_timestamp || new Date().toISOString(),
    alert_type: a.alert_type || a.alert_details?.suspicious_activity || 'Wireless Threat',
    message: a.message || a.alert_details?.summary_description || 'Suspicious network pattern identified.',
  };
}

/**
 * Security Alerts Service.
 */
export const alertService = {
  /**
   * Fetches alerts with optional filtering by severity and status.
   */
  async getAlerts(params = {}) {
    const query = new URLSearchParams(params).toString();
    const live = await apiRequest(`/api/alerts${query ? `?${query}` : ''}`);
    if (live && Array.isArray(live)) {
      return live.map(normalizeAlert);
    }
    if (live && Array.isArray(live.items)) {
      return live.items.map(normalizeAlert);
    }

    let items = [...memoryAlerts];
    if (params.severity && params.severity !== 'ALL') {
      items = items.filter((a) => a.severity === params.severity);
    }
    if (params.status && params.status !== 'ALL') {
      items = items.filter((a) => a.status === params.status);
    }
    if (params.search) {
      const q = params.search.toLowerCase();
      items = items.filter(
        (a) =>
          a.alert_id.toLowerCase().includes(q) ||
          a.result_id?.toLowerCase().includes(q) ||
          a.alert_type?.toLowerCase().includes(q) ||
          a.message?.toLowerCase().includes(q)
      );
    }

    // Attach pagination metadata on the array itself so callers can either iterate directly or read .total
    items.total = items.length;
    items.items = items;
    return items;
  },

  /**
   * Fetches single alert by ID.
   */
  async getAlertById(alertId) {
    const live = await apiRequest(`/api/alerts/${alertId}`);
    if (live) return normalizeAlert(live);
    return memoryAlerts.find((a) => a.alert_id === alertId) || null;
  },

  /**
   * Updates an alert status (e.g. ACKNOWLEDGED or RESOLVED).
   */
  async updateAlertStatus(alertId, newStatus) {
    const live = await apiRequest(`/api/alerts/${alertId}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status: newStatus }),
    });
    if (live) return normalizeAlert(live);

    // Update in-memory state for interactive feedback
    memoryAlerts = memoryAlerts.map((a) =>
      a.alert_id === alertId
        ? { ...a, status: newStatus, alert_status: newStatus }
        : a
    );
    return memoryAlerts.find((a) => a.alert_id === alertId);
  },

  /**
   * Quick helper to acknowledge an incident
   */
  async acknowledgeAlert(alertId) {
    return this.updateAlertStatus(alertId, 'ACKNOWLEDGED');
  },

  /**
   * Quick helper to resolve an incident
   */
  async resolveAlert(alertId) {
    return this.updateAlertStatus(alertId, 'RESOLVED');
  },

  /**
   * Reset in-memory state to seed baseline
   */
  resetState() {
    memoryAlerts = SEED_ALERTS.map(normalizeAlert);
  },

  /**
   * Aggregated metrics for SOC Dashboard Plotly visualizations.
   */
  async getAlertMetrics() {
    const live = await apiRequest('/api/alerts/metrics/summary');
    if (live) return live;

    const criticalCount = memoryAlerts.filter((a) => a.severity === 'CRITICAL').length;
    const highCount = memoryAlerts.filter((a) => a.severity === 'HIGH').length;
    const mediumCount = memoryAlerts.filter((a) => a.severity === 'MEDIUM').length;
    const lowCount = memoryAlerts.filter((a) => a.severity === 'LOW').length;

    return {
      total_alerts: memoryAlerts.length,
      critical_count: criticalCount,
      high_count: highCount,
      medium_count: mediumCount,
      low_count: lowCount,
      unresolved_count: memoryAlerts.filter((a) => a.status === 'NEW').length,
      severity_distribution: {
        CRITICAL: criticalCount,
        HIGH: highCount,
        MEDIUM: mediumCount,
        LOW: lowCount,
      },
      trend: [
        { date: '11-08', critical: 1, high: 2, medium: 4, low: 1 },
        { date: '11-09', critical: 0, high: 3, medium: 2, low: 3 },
        { date: '11-10', critical: 2, high: 5, medium: 3, low: 2 },
        { date: '11-11', critical: 1, high: 4, medium: 5, low: 4 },
        { date: '11-12', critical: criticalCount, high: highCount, medium: mediumCount, low: lowCount },
      ],
    };
  },
};
