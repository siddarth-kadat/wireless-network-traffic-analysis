import { apiRequest, SEED_DETECTION_RESULTS, SEED_RULES } from './api';

function normalizeRule(r) {
  return {
    ...r,
    is_active: r.is_active !== undefined ? r.is_active : (r.is_enabled !== undefined ? r.is_enabled : true),
    rule_condition: r.rule_condition || {
      condition: r.detection_condition,
      threshold: r.threshold_value,
      window_sec: r.time_window_seconds,
    },
    description: r.description || r.suspicious_activity || 'Deterministic detection rule',
  };
}

function normalizeResult(res) {
  return {
    ...res,
    is_suspicious: res.is_suspicious !== undefined ? res.is_suspicious : (res.rule_match_status !== undefined ? res.rule_match_status : true),
    detection_timestamp: res.detection_timestamp || res.detection_time || new Date().toISOString(),
    evidence_data: res.evidence_data || res.detection_evidence || { reason: 'Matched deterministic criteria' },
  };
}

let memoryRules = SEED_RULES.map(normalizeRule);
let memoryResults = SEED_DETECTION_RESULTS.map(normalizeResult);

/**
 * Detection Results and Predefined Rules Service.
 */
export const detectionService = {
  /**
   * Fetches detection results produced by E2.
   */
  async getDetectionResults(params = {}) {
    const query = new URLSearchParams(params).toString();
    const live = await apiRequest(`/api/detection/results${query ? `?${query}` : ''}`);
    if (live && Array.isArray(live)) {
      return live.map(normalizeResult);
    }
    if (live && Array.isArray(live.items)) {
      return live.items.map(normalizeResult);
    }

    let items = [...memoryResults];
    if (params.matchStatus !== undefined && params.matchStatus !== '') {
      const boolStatus = params.matchStatus === 'true' || params.matchStatus === true;
      items = items.filter((r) => r.is_suspicious === boolStatus);
    }
    if (params.search) {
      const q = params.search.toLowerCase();
      items = items.filter(
        (r) =>
          r.result_id.toLowerCase().includes(q) ||
          r.rule_id?.toLowerCase().includes(q) ||
          r.log_id?.toLowerCase().includes(q)
      );
    }

    items.total = items.length;
    items.items = items;
    return items;
  },

  /**
   * Fetches predefined detection rules.
   */
  async getRules() {
    const live = await apiRequest('/api/detection/rules');
    if (live && Array.isArray(live)) {
      return live.map(normalizeRule);
    }
    return [...memoryRules];
  },

  /**
   * Toggles a rule's enabled/active state.
   */
  async toggleRule(ruleId) {
    const live = await apiRequest(`/api/detection/rules/${ruleId}/toggle`, {
      method: 'POST',
    });
    if (live) return normalizeRule(live);

    memoryRules = memoryRules.map((r) =>
      r.rule_id === ruleId ? { ...r, is_active: !r.is_active } : r
    );
    return memoryRules.find((r) => r.rule_id === ruleId);
  },

  /**
   * Reset in-memory state to baseline seed
   */
  resetState() {
    memoryRules = SEED_RULES.map(normalizeRule);
    memoryResults = SEED_DETECTION_RESULTS.map(normalizeResult);
  },
};
