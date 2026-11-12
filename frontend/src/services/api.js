/**
 * Centralized API client and network communication layer.
 * 
 * Interacts with the FastAPI backend service over HTTP REST.
 * Gracefully provides high-fidelity sample data matching the approved 7 database entities
 * if the backend endpoints are currently pending implementation.
 */

export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

// Global state tracking whether backend is actively reachable
let isBackendLive = false;

export function getBackendStatus() {
  return isBackendLive;
}

export function setBackendStatus(status) {
  isBackendLive = status;
}

/**
 * Standard HTTP Request Wrapper
 */
export async function apiRequest(endpoint, options = {}) {
  const token = sessionStorage.getItem('auth_token');
  const headers = {
    'Accept': 'application/json',
    ...(token && { Authorization: `Bearer ${token}` }),
    ...options.headers,
  };

  // Only set Content-Type to application/json if not uploading FormData
  if (!(options.body instanceof FormData) && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }

  const url = `${API_BASE_URL}${endpoint}`;

  try {
    const response = await fetch(url, { ...options, headers });
    if (response.ok) {
      isBackendLive = true;
      return await response.json();
    }
    
    // If endpoint returned 404/501, it is pending implementation
    if (response.status === 404 || response.status === 501) {
      console.warn(`[Backend Integration Notice] Endpoint '${endpoint}' returned ${response.status} (pending backend implementation).`);
      return null;
    }

    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.detail || `HTTP Error ${response.status}: ${response.statusText}`);
  } catch (err) {
    if (err.name === 'TypeError' && err.message.includes('fetch')) {
      // Backend server is offline or unreachable
      isBackendLive = false;
      console.warn(`[Backend Offline] Could not reach '${url}'. Using fallback mock SOC data.`);
      return null;
    }
    throw err;
  }
}

/* ==========================================================================
   High-Fidelity Initial Seed Datasets (Matching 7 Database Entities)
   Used for immediate SOC visualization and offline demonstration
   ========================================================================== */

export const SEED_USERS = [
  { user_id: 'usr-admin-01', username: 'admin', role: 'Network Administrator', full_name: 'Lead Network Admin', email: 'admin@soc.corp' },
  { user_id: 'usr-analyst-01', username: 'analyst', role: 'Security Analyst', full_name: 'Tier-2 SOC Analyst', email: 'analyst@soc.corp' },
  { user_id: 'usr-analyst-02', username: 'nitish', role: 'Security Analyst', full_name: 'Nitish Reddy', email: 'nitish@soc.corp' },
  { user_id: 'usr-admin-02', username: 'siddarth', role: 'Network Administrator', full_name: 'Siddarth Kadat', email: 'siddarth@soc.corp' },
];

export const SEED_BATCHES = [
  {
    batch_id: 'batch-c81f-492a',
    user_id: 'usr-admin-01',
    file_name: 'wifi_enterprise_campus_capture_01.pcap',
    file_format: 'pcap',
    submitted_at: '2026-11-12T10:15:30.000Z',
    processing_status: 'SUCCESS',
    total_records: 2450,
    processed_records: 2450,
    failed_records: 0,
  },
  {
    batch_id: 'batch-9e3b-184c',
    user_id: 'usr-analyst-01',
    file_name: 'perimeter_ap_deauth_flood.pcap',
    file_format: 'pcap',
    submitted_at: '2026-11-12T11:42:15.000Z',
    processing_status: 'SUCCESS',
    total_records: 1200,
    processed_records: 1198,
    failed_records: 2,
  },
  {
    batch_id: 'batch-f432-821e',
    user_id: 'usr-admin-01',
    file_name: 'iot_sensor_network_traffic.pcapng',
    file_format: 'pcapng',
    submitted_at: '2026-11-12T13:20:00.000Z',
    processing_status: 'PARTIAL_SUCCESS',
    total_records: 850,
    processed_records: 820,
    failed_records: 30,
  },
];

export const SEED_TRAFFIC_LOGS = [
  {
    log_id: 'log-001',
    batch_id: 'batch-9e3b-184c',
    timestamp: '2026-11-12T11:42:16.120Z',
    source_address: '192.168.1.105',
    destination_address: '192.168.1.1',
    source_mac: '00:14:22:01:23:45',
    destination_mac: 'ff:ff:ff:ff:ff:ff',
    protocol: '802.11_MGMT',
    log_details: {
      packet_index: 104,
      packet_length: 54,
      captured_length: 54,
      link_layer_type: 'IEEE 802.11 RadioTap',
      wireless: {
        bssid: '00:14:22:01:23:45',
        ssid: 'CorpEnterpriseWPA3',
        frame_type: 'Management',
        frame_subtype: 'Deauthentication',
        channel: 2412,
        signal_strength: -68,
      },
      transport_protocol: null,
      source_port: null,
      destination_port: null,
    },
  },
  {
    log_id: 'log-002',
    batch_id: 'batch-9e3b-184c',
    timestamp: '2026-11-12T11:42:16.122Z',
    source_address: '192.168.1.105',
    destination_address: '192.168.1.1',
    source_mac: '00:14:22:01:23:45',
    destination_mac: 'ff:ff:ff:ff:ff:ff',
    protocol: '802.11_MGMT',
    log_details: {
      packet_index: 105,
      packet_length: 54,
      captured_length: 54,
      link_layer_type: 'IEEE 802.11 RadioTap',
      wireless: {
        bssid: '00:14:22:01:23:45',
        ssid: 'CorpEnterpriseWPA3',
        frame_type: 'Management',
        frame_subtype: 'Deauthentication',
        channel: 2412,
        signal_strength: -67,
      },
    },
  },
  {
    log_id: 'log-003',
    batch_id: 'batch-c81f-492a',
    timestamp: '2026-11-12T10:15:32.400Z',
    source_address: '10.0.4.55',
    destination_address: '10.0.0.1',
    source_mac: 'a4:83:e7:22:11:00',
    destination_mac: '66:77:88:99:aa:bb',
    protocol: 'TCP',
    log_details: {
      packet_index: 12,
      packet_length: 74,
      captured_length: 74,
      link_layer_type: 'Ethernet',
      network_protocol: 'IPv4',
      ip_version: 4,
      transport_protocol: 'TCP',
      source_port: 58492,
      destination_port: 443,
      tcp_flags: { SYN: true, ACK: false, FIN: false, RST: false, PSH: false, URG: false },
    },
  },
  {
    log_id: 'log-004',
    batch_id: 'batch-c81f-492a',
    timestamp: '2026-11-12T10:15:33.010Z',
    source_address: '10.0.4.55',
    destination_address: '10.0.0.1',
    source_mac: 'a4:83:e7:22:11:00',
    destination_mac: '66:77:88:99:aa:bb',
    protocol: 'TCP',
    log_details: {
      packet_index: 13,
      packet_length: 74,
      captured_length: 74,
      link_layer_type: 'Ethernet',
      network_protocol: 'IPv4',
      ip_version: 4,
      transport_protocol: 'TCP',
      source_port: 58494,
      destination_port: 80,
      tcp_flags: { SYN: true, ACK: false, FIN: false, RST: false, PSH: false, URG: false },
    },
  },
  {
    log_id: 'log-005',
    batch_id: 'batch-c81f-492a',
    timestamp: '2026-11-12T10:15:35.800Z',
    source_address: '192.168.1.200',
    destination_address: '192.168.1.255',
    source_mac: '50:3e:aa:11:22:33',
    destination_mac: 'ff:ff:ff:ff:ff:ff',
    protocol: 'UDP',
    log_details: {
      packet_index: 45,
      packet_length: 68,
      captured_length: 68,
      link_layer_type: 'Ethernet',
      network_protocol: 'IPv4',
      transport_protocol: 'UDP',
      source_port: 5353,
      destination_port: 5353,
    },
  },
];

export const SEED_RULES = [
  {
    rule_id: 'rule-deauth-01',
    rule_name: 'Wireless Deauthentication Flood Attack',
    suspicious_activity: 'Deauthentication Denial of Service',
    protocol: '802.11_MGMT',
    detection_condition: 'count(deauth_frames) > threshold',
    threshold_value: 30,
    time_window_seconds: 5,
    severity: 'HIGH',
    is_enabled: true,
  },
  {
    rule_id: 'rule-synflood-02',
    rule_name: 'TCP SYN Packet Burst Flood',
    suspicious_activity: 'SYN Flood Exhaustion',
    protocol: 'TCP',
    detection_condition: 'count(tcp_syn_packets) > threshold',
    threshold_value: 100,
    time_window_seconds: 2,
    severity: 'CRITICAL',
    is_enabled: true,
  },
  {
    rule_id: 'rule-rogue-ap-03',
    rule_name: 'Rogue AP SSID Spoofing & Evil Twin',
    suspicious_activity: 'Rogue Access Point',
    protocol: '802.11',
    detection_condition: 'bssid_divergence(known_bssid_list) == true',
    threshold_value: 1,
    time_window_seconds: 10,
    severity: 'CRITICAL',
    is_enabled: true,
  },
  {
    rule_id: 'rule-portscan-04',
    rule_name: 'High-Rate TCP Port Scanning',
    suspicious_activity: 'Port Sweep Reconnaissance',
    protocol: 'TCP',
    detection_condition: 'unique_dst_ports(src_ip) > threshold',
    threshold_value: 20,
    time_window_seconds: 10,
    severity: 'MEDIUM',
    is_enabled: true,
  },
  {
    rule_id: 'rule-arp-spoof-05',
    rule_name: 'Gratuitous ARP Cache Poisoning',
    suspicious_activity: 'ARP Cache Poisoning',
    protocol: 'ARP',
    detection_condition: 'arp_ip_conflict_rate > threshold',
    threshold_value: 5,
    time_window_seconds: 3,
    severity: 'HIGH',
    is_enabled: false,
  },
];

export const SEED_DETECTION_RESULTS = [
  {
    result_id: 'res-deauth-991',
    log_id: 'log-001',
    rule_id: 'rule-deauth-01',
    rule_name: 'Wireless Deauthentication Flood Attack',
    suspicious_activity: 'Deauthentication Denial of Service',
    rule_match_status: true,
    observed_value: 142,
    threshold_value: 30,
    detection_evidence: {
      burst_count: 142,
      time_window_sec: 5,
      target_ap: 'CorpEnterpriseWPA3',
      transmitter_mac: '00:14:22:01:23:45',
    },
    detection_time: '2026-11-12T11:42:16.300Z',
    severity: 'HIGH',
    source_mac: '00:14:22:01:23:45',
    destination_mac: 'ff:ff:ff:ff:ff:ff',
    protocol: '802.11_MGMT',
  },
  {
    result_id: 'res-syn-992',
    log_id: 'log-003',
    rule_id: 'rule-synflood-02',
    rule_name: 'TCP SYN Packet Burst Flood',
    suspicious_activity: 'SYN Flood Exhaustion',
    rule_match_status: true,
    observed_value: 285,
    threshold_value: 100,
    detection_evidence: {
      syn_rate_pps: 142.5,
      target_port: 443,
      src_ip: '10.0.4.55',
    },
    detection_time: '2026-11-12T10:15:34.000Z',
    severity: 'CRITICAL',
    source_address: '10.0.4.55',
    destination_address: '10.0.0.1',
    protocol: 'TCP',
  },
  {
    result_id: 'res-clean-993',
    log_id: 'log-005',
    rule_id: 'rule-portscan-04',
    rule_name: 'High-Rate TCP Port Scanning',
    suspicious_activity: 'Port Sweep Reconnaissance',
    rule_match_status: false,
    observed_value: 2,
    threshold_value: 20,
    detection_evidence: { ports_scanned: 2 },
    detection_time: '2026-11-12T10:15:36.000Z',
    severity: 'LOW',
    source_address: '192.168.1.200',
    destination_address: '192.168.1.255',
    protocol: 'UDP',
  },
];

export const SEED_ALERTS = [
  {
    alert_id: 'alt-584a-91bf',
    result_id: 'res-syn-992',
    severity: 'CRITICAL',
    alert_status: 'NEW',
    alert_timestamp: '2026-11-12T10:15:34.120Z',
    alert_details: {
      suspicious_activity: 'SYN Flood Exhaustion',
      rule_id: 'rule-synflood-02',
      rule_name: 'TCP SYN Packet Burst Flood',
      log_id: 'log-003',
      network_context: {
        source_address: '10.0.4.55',
        destination_address: '10.0.0.1',
        source_mac: 'a4:83:e7:22:11:00',
        destination_mac: '66:77:88:99:aa:bb',
        protocol: 'TCP',
      },
      metrics: { observed_value: 285, threshold_value: 100 },
      detection_evidence: { syn_rate_pps: 142.5, target_port: 443 },
      summary_description: '[CRITICAL] SYN Flood Exhaustion detected by rule TCP SYN Packet Burst Flood from 10.0.4.55 to 10.0.0.1 (Observed: 285 | Threshold: 100).',
    },
  },
  {
    alert_id: 'alt-84bc-21a4',
    result_id: 'res-deauth-991',
    severity: 'HIGH',
    alert_status: 'ACKNOWLEDGED',
    alert_timestamp: '2026-11-12T11:42:16.450Z',
    alert_details: {
      suspicious_activity: 'Deauthentication Denial of Service',
      rule_id: 'rule-deauth-01',
      rule_name: 'Wireless Deauthentication Flood Attack',
      log_id: 'log-001',
      network_context: {
        source_address: null,
        destination_address: null,
        source_mac: '00:14:22:01:23:45',
        destination_mac: 'ff:ff:ff:ff:ff:ff',
        protocol: '802.11_MGMT',
        wireless: { ssid: 'CorpEnterpriseWPA3', bssid: '00:14:22:01:23:45' },
      },
      metrics: { observed_value: 142, threshold_value: 30 },
      detection_evidence: { burst_count: 142, time_window_sec: 5 },
      summary_description: '[HIGH] Deauthentication Denial of Service detected by rule Wireless Deauthentication Flood Attack from 00:14:22:01:23:45 to ff:ff:ff:ff:ff:ff (Observed: 142 | Threshold: 30).',
    },
  },
];

export const SEED_PROCESSING_ERRORS = [
  {
    error_id: 'err-01',
    batch_id: 'batch-f432-821e',
    log_id: 'log-819',
    error_type: 'PacketParsingCorruption',
    error_message: 'Malformed 802.11 RadioTap header: incomplete flags extension octet',
    error_timestamp: '2026-11-12T13:20:04.210Z',
  },
  {
    error_id: 'err-02',
    batch_id: 'batch-9e3b-184c',
    log_id: 'log-1199',
    error_type: 'TruncatedFramePayload',
    error_message: 'Frame captured length (34 bytes) less than expected minimum IP header size',
    error_timestamp: '2026-11-12T11:42:17.890Z',
  },
];
