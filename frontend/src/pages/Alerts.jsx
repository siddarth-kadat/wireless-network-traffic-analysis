import React, { useState, useEffect } from 'react';
import {
  AlertTriangle,
  Search,
  Clock,
  Eye,
  Download,
  Shield,
  ExternalLink,
  ChevronLeft,
  ChevronRight,
  Zap,
  Info,
} from 'lucide-react';
import StatusBadge from '../components/StatusBadge';
import { alertService } from '../services/alertService';

export default function Alerts() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [activeTab, setActiveTab] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [newNote, setNewNote] = useState('');
  const [triageHistory, setTriageHistory] = useState([
    {
      title: 'Automated Alert Generated (E4)',
      time: '14:32:09',
      desc: 'Breached rule R-WLAN-04 with confidence score 99.4%. Pushed to SOC Queue.',
      color: 'bg-error',
    },
    {
      title: 'Triage Assigned to Tier 3 SecOps',
      time: '14:32:15',
      desc: 'System auto-routed alert to Alex Rivera (Network Administrator).',
      color: 'bg-primary',
    },
    {
      title: 'Pre-Containment Network Isolation Check',
      time: '14:33:02',
      desc: 'Access switch VLAN isolation pending analyst manual confirmation.',
      color: 'bg-tertiary',
    },
  ]);

  // Demo alert queue matching Backlinko Clean Growth layout
  const SAMPLE_ALERTS = [
    {
      alert_id: 'ALT-8841',
      result_id: 'RES-4102',
      name: 'WPA2 4-Way Handshake Cracking',
      rule: 'R-WLAN-04 // Replay Anomaly',
      rule_full: 'R-WLAN-04 (Handshake Replay Anomaly)',
      severity: 'CRITICAL',
      status: 'NEW',
      time: '14:32:09 UTC 2025-05-14',
      time_short: '14:32:09 UTC',
      src_mac: 'a4:c3:f0:88:91:2c',
      src_vendor: 'Espressif Inc (Spoofed)',
      target_bssid: '00:26:86:f1:40:9a',
      target_ap: 'Cisco Meraki MR56 HQ-WLAN',
      ssid: 'CORP_EMPLOYEE_5G',
      channel: 'Channel 44 // 5.220 GHz (80MHz)',
      frame_type: 'EAPoL Key Exchange SubType: Message 1 / Message 2',
      observed_rate: '84 frames / 1.2 sec',
      trigger_policy: 'Normal: < 2 frames / s | Trigger Policy: > 10 frames / 2.0s',
      log_id: 'LOG-9941828',
      hex_dump: `0000 88 42 00 00 00 26 86 f1 40 9a a4 c3 f0 88
91 2c .B...&..@...
0010 00 26 86 f1 40 9a 30 71 88 8e 02 03 00 5f
02 88 .&..@.0q....._..
0020 8a 00 10 00 00 00 00 00 00 00 00 01 f4 a8 bc
11 09 ............
0030 9c e1 42 5c 00 00 00 00 00 00 00 00 00 00 00
00 00 ..B.............
0040 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 ................`,
    },
    {
      alert_id: 'ALT-8840',
      result_id: 'RES-4099',
      name: '802.11 Deauth Broadcast Flood',
      rule: 'R-WLAN-01 // Disassoc Rate',
      rule_full: 'R-WLAN-01 (Deauth Flood Anomaly)',
      severity: 'CRITICAL',
      status: 'INVESTIGATING',
      time: '14:28:44 UTC 2025-05-14',
      time_short: '14:28:44 UTC',
      src_mac: '00:14:22:01:23:45',
      src_vendor: 'Intel Wireless NIC',
      target_bssid: 'ff:ff:ff:ff:ff:ff',
      target_ap: 'Broadcast Gateway AP',
      ssid: 'Corp-Guest-Secure',
      channel: 'Channel 6 // 2.437 GHz (20MHz)',
      frame_type: 'Management Deauthentication (Reason 7: Class 3 frame received from nonassociated STA)',
      observed_rate: '142 frames / 1.0 sec',
      trigger_policy: 'Normal: < 5 frames / s | Trigger Policy: > 30 frames / 2.0s',
      log_id: 'LOG-9941810',
      hex_dump: `0000 c0 00 00 00 ff ff ff ff ff ff 00 14 22 01
23 45 ............#E
0010 00 14 22 01 23 45 00 00 07 00 ..#E....`,
    },
    {
      alert_id: 'ALT-8839',
      result_id: 'RES-4095',
      name: 'Rogue AP Beacon Spoofing',
      rule: 'R-WLAN-03 // Evil Twin Detect',
      rule_full: 'R-WLAN-03 (BSSID Spoofing Vector)',
      severity: 'HIGH',
      status: 'NEW',
      time: '14:15:10 UTC 2025-05-14',
      time_short: '14:15:10 UTC',
      src_mac: '6c:5e:3b:88:91:02',
      src_vendor: 'Unknown / Fake OUI',
      target_bssid: '00:26:86:f1:40:9a',
      target_ap: 'Enterprise-Executive',
      ssid: 'Enterprise-Executive',
      channel: 'Channel 44 // 5.220 GHz (80MHz)',
      frame_type: 'Beacon Frame with conflicting capability flags',
      observed_rate: '10 beacons / sec',
      trigger_policy: 'Trigger Policy: Duplicate SSID with non-registered OUI',
      log_id: 'LOG-9941790',
      hex_dump: `0000 80 00 00 00 ff ff ff ff ff ff 6c 5e 3b 88
91 02 ............l^;.`,
    },
    {
      alert_id: 'ALT-8838',
      result_id: 'RES-4088',
      name: 'Excessive Probe Request Burst',
      rule: 'R-WLAN-07 // Reconnaissance Scan',
      rule_full: 'R-WLAN-07 (Probe Request Burst Rate)',
      severity: 'MEDIUM',
      status: 'INVESTIGATING',
      time: '13:58:22 UTC 2025-05-14',
      time_short: '13:58:22 UTC',
      src_mac: '50:3e:aa:11:22:33',
      src_vendor: 'Realtek Semiconductor Corp',
      target_bssid: 'ff:ff:ff:ff:ff:ff',
      target_ap: 'Wildcard Probe',
      ssid: 'Wildcard SSID Broadcast',
      channel: 'Channel 6 // 2.437 GHz',
      frame_type: 'Probe Request SSID Wildcard Sweep',
      observed_rate: '450 requests / 5 sec',
      trigger_policy: 'Trigger Policy: > 100 probes / 5.0s',
      log_id: 'LOG-9941740',
      hex_dump: `0000 40 00 00 00 ff ff ff ff ff ff 50 3e aa 11
22 33 @.........P>.."3`,
    },
    {
      alert_id: 'ALT-8837',
      result_id: 'RES-4079',
      name: 'KARMA Attack SSID Beacon Response',
      rule: 'R-WLAN-09 // Man-In-The-Middle',
      rule_full: 'R-WLAN-09 (KARMA Adaptive Beacon Response)',
      severity: 'HIGH',
      status: 'RESOLVED',
      time: '13:42:01 UTC 2025-05-14',
      time_short: '13:42:01 UTC',
      src_mac: '00:c0:ca:98:76:54',
      src_vendor: 'Alfa Network Wireless',
      target_bssid: 'a4:c3:f0:88:91:2c',
      target_ap: 'Hostapd Rogue Node',
      ssid: 'CORP_EMPLOYEE_5G',
      channel: 'Channel 11 // 2.462 GHz',
      frame_type: 'Probe Response dynamically matching requested SSID',
      observed_rate: '12 probe responses in 1.0s',
      trigger_policy: 'Trigger Policy: AP responding to probe without prior announcement',
      log_id: 'LOG-9941710',
      hex_dump: `0000 50 00 00 00 a4 c3 f0 88 91 2c 00 c0 ca 98
76 54 P......,...vT`,
    },
    {
      alert_id: 'ALT-8836',
      result_id: 'RES-4061',
      name: 'Weak IV / WEP Frame Injection',
      rule: 'R-WLAN-12 // Legacy Weakness',
      rule_full: 'R-WLAN-12 (Weak Initialization Vector)',
      severity: 'LOW',
      status: 'RESOLVED',
      time: '13:11:15 UTC 2025-05-14',
      time_short: '13:11:15 UTC',
      src_mac: '00:11:22:33:44:55',
      src_vendor: 'Legacy 802.11b Adapter',
      target_bssid: '00:14:22:01:23:45',
      target_ap: 'Legacy Subnet AP',
      ssid: 'Legacy-Inventory-IoT',
      channel: 'Channel 1 // 2.412 GHz',
      frame_type: 'Encrypted Data with repeated IV sequence',
      observed_rate: '2 weak IVs detected',
      trigger_policy: 'Trigger Policy: Weak IV FMS key reconstruction risk',
      log_id: 'LOG-9941650',
      hex_dump: `0000 08 41 00 00 00 14 22 01 23 45 00 11 22 33
44 55 .A....".#E.."3DU`,
    },
  ];

  useEffect(() => {
    async function init() {
      setLoading(true);
      try {
        const live = await alertService.getAlerts();
        if (live && live.length > 0) {
          const merged = SAMPLE_ALERTS.map((sample, idx) => {
            const apiAlert = live[idx];
            return apiAlert ? { ...sample, ...apiAlert } : sample;
          });
          setAlerts(merged);
          setSelectedAlert(merged[0]);
        } else {
          setAlerts(SAMPLE_ALERTS);
          setSelectedAlert(SAMPLE_ALERTS[0]);
        }
      } catch (e) {
        setAlerts(SAMPLE_ALERTS);
        setSelectedAlert(SAMPLE_ALERTS[0]);
      } finally {
        setLoading(false);
      }
    }
    init();
  }, []);

  const handleUpdateStatus = async (alertId, newStatus) => {
    await alertService.updateAlertStatus(alertId, newStatus);
    setAlerts((prev) =>
      prev.map((a) => (a.alert_id === alertId ? { ...a, status: newStatus } : a))
    );
    if (selectedAlert?.alert_id === alertId) {
      setSelectedAlert((prev) => ({ ...prev, status: newStatus }));
      setTriageHistory((prev) => [
        {
          title: `Status Changed to ${newStatus}`,
          time: new Date().toLocaleTimeString(),
          desc: `Updated by Alex Rivera.`,
          color: newStatus === 'RESOLVED' ? 'bg-primary' : 'bg-secondary',
        },
        ...prev,
      ]);
    }
  };

  const handlePostNote = (e) => {
    e.preventDefault();
    if (!newNote.trim()) return;
    setTriageHistory((prev) => [
      {
        title: 'Analyst Forensic Note Added',
        time: new Date().toLocaleTimeString(),
        desc: newNote.trim(),
        color: 'bg-primary',
      },
      ...prev,
    ]);
    setNewNote('');
  };

  const filteredAlerts = alerts.filter((a) => {
    if (activeTab === 'New' && a.status !== 'NEW') return false;
    if (activeTab === 'Investigating' && a.status !== 'INVESTIGATING') return false;
    if (activeTab === 'Resolved' && a.status !== 'RESOLVED') return false;
    if (severityFilter !== 'ALL' && a.severity !== severityFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        a.alert_id.toLowerCase().includes(q) ||
        a.name?.toLowerCase().includes(q) ||
        a.rule?.toLowerCase().includes(q) ||
        a.src_mac?.toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Top Header Strip */}
      <div className="p-6 md:p-8 rounded-md bg-white border border-border flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <div className="text-xs text-primary font-bold tracking-wider uppercase mb-1">
            THREAT DETECTION // ALERT MANAGEMENT
          </div>
          <h1 className="text-3xl font-extrabold tracking-tight text-secondary">
            Alert Management
          </h1>
          <p className="text-sm text-muted mt-1">
            Enterprise incident investigation and response triage station generated by Alert Generation Engine (E4)
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="px-3.5 py-1.5 rounded-full bg-error/10 border border-error/20 text-error text-xs font-bold flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-error animate-pulse" />
            <span>4 UNACKNOWLEDGED CRITICALS</span>
          </div>
          <div className="px-3 py-1.5 rounded-md bg-subtle border border-border text-secondary text-xs font-medium">
            Auto-Sync (3s)
          </div>
        </div>
      </div>

      {/* 5 Summary Metric Boxes */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
        <div className="p-5 rounded-md bg-white border border-border flex items-center justify-between">
          <div>
            <div className="text-xs font-bold text-muted uppercase tracking-wider">TOTAL ALERTS</div>
            <div className="text-2xl font-extrabold text-secondary mt-1">42</div>
          </div>
          <Shield className="w-6 h-6 text-primary" />
        </div>

        <div className="p-5 rounded-md bg-white border border-error/30 flex items-center justify-between">
          <div>
            <div className="text-xs font-bold text-error uppercase tracking-wider flex items-center gap-1.5">
              <span>CRITICAL</span>
              <span className="w-2 h-2 rounded-full bg-error" />
            </div>
            <div className="text-2xl font-extrabold text-error mt-1">04</div>
          </div>
          <AlertTriangle className="w-6 h-6 text-error" />
        </div>

        <div className="p-5 rounded-md bg-white border border-tertiary/30 flex items-center justify-between">
          <div>
            <div className="text-xs font-bold text-tertiary uppercase tracking-wider">HIGH</div>
            <div className="text-2xl font-extrabold text-tertiary mt-1">11</div>
          </div>
          <AlertTriangle className="w-6 h-6 text-tertiary" />
        </div>

        <div className="p-5 rounded-md bg-white border border-amber-300 flex items-center justify-between">
          <div>
            <div className="text-xs font-bold text-amber-700 uppercase tracking-wider">MEDIUM</div>
            <div className="text-2xl font-extrabold text-amber-700 mt-1">15</div>
          </div>
          <Clock className="w-6 h-6 text-amber-600" />
        </div>

        <div className="p-5 rounded-md bg-white border border-primary/30 flex items-center justify-between">
          <div>
            <div className="text-xs font-bold text-primary uppercase tracking-wider">LOW</div>
            <div className="text-2xl font-extrabold text-primary mt-1">12</div>
          </div>
          <Info className="w-6 h-6 text-primary" />
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-md bg-white border border-border flex flex-wrap items-center justify-between gap-4 text-xs">
        <div className="flex flex-wrap items-center gap-3 flex-1">
          {/* Search Input */}
          <div className="relative w-56">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter by ID, rule, MAC..."
              className="w-full pl-9 pr-3 py-2 bg-white border border-border rounded-md text-xs text-secondary placeholder-muted focus:outline-none focus:border-primary"
            />
          </div>

          {/* Time Filter */}
          <select className="px-3 py-2 rounded-md bg-white border border-border text-secondary text-xs focus:outline-none focus:border-primary">
            <option>Last 24 Hours</option>
            <option>Last 1 Hour</option>
            <option>Last 7 Days</option>
          </select>

          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-2 rounded-md bg-white border border-border text-secondary text-xs focus:outline-none focus:border-primary"
          >
            <option value="ALL">Severity: All</option>
            <option value="CRITICAL">Critical Only</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          {/* Status Tabs */}
          <div className="flex items-center gap-1.5 pl-3 border-l border-border">
            {[
              { id: 'ALL', label: 'ALL (42)' },
              { id: 'New', label: 'New (18)' },
              { id: 'Investigating', label: 'Investigating (14)' },
              { id: 'Resolved', label: 'Resolved (10)' },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-3 py-1.5 rounded-md text-xs font-bold transition ${
                  activeTab === tab.id
                    ? 'bg-primary text-white'
                    : 'bg-subtle hover:bg-subtle/80 text-secondary'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        {/* Export STIX/CSV Action */}
        <button className="flex items-center gap-2 px-4 py-2 rounded-md bg-white hover:bg-subtle border border-border text-secondary text-xs font-bold transition">
          <Download className="w-4 h-4 text-muted" />
          <span>Export STIX/CSV</span>
        </button>
      </div>

      {/* Master-Detail Split Screen Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Triage Queue Table (5 of 12 cols on desktop) */}
        <div className="lg:col-span-5 space-y-4">
          <div className="bg-white border border-border rounded-md overflow-hidden">
            <div className="p-4 border-b border-border bg-subtle/50 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-primary" />
                <span className="text-xs font-bold text-secondary tracking-wider uppercase">
                  TRIAGE QUEUE
                </span>
                <span className="px-2 py-0.5 rounded-full bg-primary/10 text-primary text-[10px] font-bold">
                  Showing 6 prioritized
                </span>
              </div>
              <span className="text-[11px] text-muted font-medium">
                SORT: INGESTION (DESC)
              </span>
            </div>

            <div className="divide-y divide-border max-h-[580px] overflow-y-auto">
              {filteredAlerts.map((row) => {
                const isSelected = selectedAlert?.alert_id === row.alert_id;
                return (
                  <div
                    key={row.alert_id}
                    onClick={() => setSelectedAlert(row)}
                    className={`p-4 cursor-pointer transition select-none ${
                      isSelected
                        ? 'bg-subtle/80 border-l-4 border-l-primary'
                        : 'hover:bg-subtle/40 border-l-4 border-l-transparent'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2 text-xs">
                          <span className="font-bold font-mono text-primary">{row.alert_id}</span>
                          <span className="text-muted">/</span>
                          <span className="text-muted font-mono">{row.result_id}</span>
                        </div>
                        <h4 className="text-sm font-bold text-secondary leading-snug">
                          {row.name}
                        </h4>
                        <p className="text-xs text-muted">{row.rule}</p>
                      </div>

                      <div className="text-right space-y-1.5 flex-shrink-0">
                        <StatusBadge value={row.severity} type="severity" size="small" />
                        <div className="text-[11px] text-muted">{row.time_short}</div>
                        <StatusBadge value={row.status} type="status" size="small" />
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Pagination Controls */}
            <div className="p-3.5 border-t border-border bg-subtle/50 flex items-center justify-between text-xs text-muted">
              <span>Displaying 1-6 of 42 security alerts</span>
              <div className="flex items-center gap-1.5">
                <button className="p-1 rounded-md border border-border hover:bg-subtle disabled:opacity-40">
                  <ChevronLeft className="w-3.5 h-3.5" />
                </button>
                <span className="px-2.5 py-0.5 rounded-md bg-primary text-white font-bold text-xs">1</span>
                <span className="px-2.5 py-0.5 rounded-md hover:bg-subtle text-secondary text-xs">2</span>
                <span className="px-2.5 py-0.5 rounded-md hover:bg-subtle text-secondary text-xs">3</span>
                <button className="p-1 rounded-md border border-border hover:bg-subtle">
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          </div>

          {/* Bottom Deterministic Mitigation Card */}
          <div className="p-5 rounded-md bg-subtle border border-border flex items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-md bg-secondary flex items-center justify-center text-white flex-shrink-0">
                <Zap className="w-5 h-5 text-primary" />
              </div>
              <div>
                <h5 className="text-xs font-bold text-secondary leading-tight">
                  Deterministic Mitigation Ready
                </h5>
                <p className="text-[11px] text-muted mt-0.5">
                  Batch triage 4 critical Handshake &amp; Deauth events matching MITRE T1498
                </p>
              </div>
            </div>
            <button className="px-4 py-2 rounded-md bg-primary hover:bg-primary-hover text-white font-bold text-xs whitespace-nowrap transition">
              Apply Action
            </button>
          </div>
        </div>

        {/* Right Column: Live Inspector Detail Panel (7 of 12 cols on desktop) */}
        {selectedAlert && (
          <div className="lg:col-span-7 bg-white border border-border rounded-md p-6 space-y-5">
            {/* Header: Alert ID, Badges, Title, Action Buttons */}
            <div className="border-b border-border pb-5 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-2.5">
                  <span className="text-lg font-extrabold font-mono text-secondary">{selectedAlert.alert_id}</span>
                  <StatusBadge value={selectedAlert.severity} type="severity" />
                  <span className="px-2.5 py-1 rounded-full bg-subtle border border-border text-secondary text-xs font-bold">
                    STATUS: {selectedAlert.status}
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleUpdateStatus(selectedAlert.alert_id, 'INVESTIGATING')}
                    className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-md bg-primary hover:bg-primary-hover text-white font-bold text-xs transition"
                  >
                    <Eye className="w-3.5 h-3.5" />
                    <span>Investigating</span>
                  </button>
                  <button
                    onClick={() => handleUpdateStatus(selectedAlert.alert_id, 'ESCALATED')}
                    className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-md bg-tertiary hover:bg-tertiary-hover text-white font-bold text-xs transition"
                  >
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>Escalate</span>
                  </button>
                  <button
                    onClick={() => handleUpdateStatus(selectedAlert.alert_id, 'RESOLVED')}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-white hover:bg-subtle border border-border text-secondary font-bold text-xs transition"
                  >
                    <span>False Pos.</span>
                  </button>
                </div>
              </div>

              <div>
                <h2 className="text-xl font-extrabold text-secondary tracking-tight">
                  {selectedAlert.name} Attempt
                </h2>
              </div>
            </div>

            {/* Pipeline Provenance Card */}
            <div className="p-4 rounded-md bg-subtle border border-border space-y-3 text-xs">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-muted uppercase tracking-wider">PIPELINE PROVENANCE</span>
                <span className="text-primary hover:text-primary-hover font-bold cursor-pointer flex items-center gap-1">
                  <span>View Result {selectedAlert.result_id}</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                <div>
                  <span className="text-muted block text-[11px]">Associated Rule:</span>
                  <span className="text-secondary font-bold">{selectedAlert.rule_full}</span>
                </div>
                <div>
                  <span className="text-muted block text-[11px]">Detection Engine:</span>
                  <span className="text-secondary font-bold">E2 Threshold &amp; Sequence Evaluator</span>
                </div>
              </div>

              {/* Execution Chain */}
              <div className="pt-3 border-t border-border text-xs">
                <span className="text-muted block mb-1.5 text-[11px] uppercase tracking-wider">Execution Chain Pipeline:</span>
                <div className="flex items-center gap-2">
                  <span className="px-2.5 py-1 rounded-md bg-white border border-border text-secondary font-bold text-[11px]">E1:SCAPY</span>
                  <span className="text-muted">&rarr;</span>
                  <span className="px-2.5 py-1 rounded-md bg-white border border-border text-secondary font-bold text-[11px]">E2:EVAL</span>
                  <span className="text-muted">&rarr;</span>
                  <span className="px-2.5 py-1 rounded-md bg-primary text-white font-bold text-[11px]">E4:ALERT</span>
                  <span className="text-muted">&rarr;</span>
                  <span className="px-2.5 py-1 rounded-md bg-white border border-border text-secondary font-bold text-[11px]">E3:STORE</span>
                </div>
              </div>
            </div>

            {/* Technical Threat Evidence */}
            <div className="p-5 rounded-md bg-white border border-border space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-muted uppercase tracking-wider">
                  TECHNICAL THREAT EVIDENCE
                </span>
                <span className="px-2.5 py-1 rounded-full bg-error/10 text-error border border-error/20 text-xs font-bold">
                  THRESHOLD BREACH
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                <div className="p-3 rounded-md bg-subtle border border-border">
                  <span className="text-[11px] text-muted uppercase tracking-wider block">SOURCE MAC (ROGUE CLIENT)</span>
                  <span className="text-secondary font-extrabold font-mono text-sm block mt-1">{selectedAlert.src_mac}</span>
                  <span className="text-xs text-muted">Vendor: {selectedAlert.src_vendor}</span>
                </div>

                <div className="p-3 rounded-md bg-subtle border border-border">
                  <span className="text-[11px] text-muted uppercase tracking-wider block">TARGET AP BSSID</span>
                  <span className="text-secondary font-extrabold font-mono text-sm block mt-1">{selectedAlert.target_bssid}</span>
                  <span className="text-xs text-muted">{selectedAlert.target_ap}</span>
                </div>

                <div className="p-3 rounded-md bg-subtle border border-border">
                  <span className="text-[11px] text-muted uppercase tracking-wider block">SSID / RADIO CHANNEL</span>
                  <span className="text-secondary font-bold block mt-1">{selectedAlert.ssid}</span>
                  <span className="text-xs text-muted">{selectedAlert.channel}</span>
                </div>

                <div className="p-3 rounded-md bg-subtle border border-border">
                  <span className="text-[11px] text-muted uppercase tracking-wider block">802.11 FRAME TYPE</span>
                  <span className="text-secondary font-bold block mt-1 truncate">{selectedAlert.frame_type}</span>
                </div>
              </div>

              {/* Observed Frequency Rate Warning Box */}
              <div className="p-3.5 rounded-md bg-error/5 border border-error/20 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
                <div className="text-error font-bold">
                  Observed Frequency Rate: <span className="font-extrabold">{selectedAlert.observed_rate}</span>
                </div>
                <div className="text-muted text-[11px]">
                  {selectedAlert.trigger_policy}
                </div>
              </div>
            </div>

            {/* Raw Traffic Log & Packet Hex (Dark Terminal Container) */}
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted font-bold uppercase tracking-wider">RAW TRAFFIC LOG &amp; PACKET HEX</span>
                <span className="text-primary font-bold font-mono">
                  {selectedAlert.log_id}
                </span>
              </div>
              <div className="p-4 rounded-md bg-[#0F172A] text-emerald-400 font-mono text-xs overflow-x-auto border border-border">
                <div className="text-slate-500 mb-1.5">### [ Scapy Dissected 802.11 / EAPoL Frame #1084 ] ###</div>
                <pre className="text-slate-300 whitespace-pre leading-relaxed">{selectedAlert.hex_dump}</pre>
                <div className="text-primary mt-2.5 font-bold">
                  // ANOMALY: Nonce replay index zeroed; rapid repeated pairwise key derivation detected
                </div>
              </div>
            </div>

            {/* Incident Triage History Timeline */}
            <div className="space-y-3 pt-3 border-t border-border">
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted font-bold uppercase tracking-wider">INCIDENT TRIAGE HISTORY</span>
                <span className="text-muted font-medium">{triageHistory.length} Events</span>
              </div>

              <div className="space-y-3 pl-2 border-l-2 border-border text-xs">
                {triageHistory.map((item, idx) => (
                  <div key={idx} className="relative pl-4 space-y-1">
                    <span className={`w-2.5 h-2.5 rounded-full ${item.color} absolute -left-[19px] top-1 border-2 border-white`} />
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-secondary">{item.title}</span>
                      <span className="text-xs text-muted">{item.time}</span>
                    </div>
                    <p className="text-xs text-muted">{item.desc}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Add Forensic Note / IoC Input Box */}
            <form onSubmit={handlePostNote} className="pt-3 flex gap-3">
              <input
                type="text"
                value={newNote}
                onChange={(e) => setNewNote(e.target.value)}
                placeholder="Add forensic note or IoC reference..."
                className="flex-1 px-4 py-2 bg-white border border-border rounded-md text-xs text-secondary placeholder-muted focus:outline-none focus:border-primary"
              />
              <button
                type="submit"
                className="px-5 py-2 rounded-md bg-secondary hover:bg-muted text-white font-bold text-xs transition"
              >
                Post Note
              </button>
            </form>
          </div>
        )}
      </div>
    </div>
  );
}
