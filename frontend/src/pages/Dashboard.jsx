import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  AlertTriangle,
  Activity,
  Layers,
  ArrowRight,
  UploadCloud,
  Clock,
  Database,
  Bell,
  Cpu,
  Sliders,
  Filter,
} from 'lucide-react';
import MetricCard from '../components/MetricCard';
import StatusBadge from '../components/StatusBadge';
import TrafficChart from '../charts/TrafficChart';
import ProtocolDistributionChart from '../charts/ProtocolDistributionChart';
import SeverityChart from '../charts/SeverityChart';
import AlertTrendChart from '../charts/AlertTrendChart';

import { alertService } from '../services/alertService';
import { logService } from '../services/logService';
import { batchService } from '../services/batchService';
import { detectionService } from '../services/detectionService';
import { getBackendStatus } from '../services/api';
import { useAuth } from '../context/AuthContext';

export default function Dashboard() {
  const { user, isAdmin } = useAuth();
  const navigate = useNavigate();

  const [loading, setLoading] = useState(true);
  const [alerts, setAlerts] = useState([]);
  const [batches, setBatches] = useState([]);
  const [rules, setRules] = useState([]);
  const [logs, setLogs] = useState([]);
  const [detectionResults, setDetectionResults] = useState([]);
  const [lastUpdated, setLastUpdated] = useState(new Date());

  const isLive = getBackendStatus();

  const loadDashboardData = async () => {
    setLoading(true);
    try {
      const [fetchedAlerts, fetchedBatches, fetchedRules, fetchedLogs, fetchedResults] = await Promise.all([
        alertService.getAlerts(),
        batchService.getBatches(),
        detectionService.getRules(),
        logService.getTrafficLogs(),
        detectionService.getDetectionResults(),
      ]);

      setAlerts(fetchedAlerts);
      setBatches(fetchedBatches);
      setRules(fetchedRules);
      setLogs(fetchedLogs);
      setDetectionResults(fetchedResults);
      setLastUpdated(new Date());
    } catch (err) {
      console.error('Failed to load SOC dashboard metrics:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDashboardData();
  }, []);

  return (
    <div className="space-y-6">
      {/* Top Operational Header Bar */}
      <div className="p-6 md:p-8 rounded-md bg-white border border-border flex flex-col lg:flex-row lg:items-center justify-between gap-6">
        <div className="space-y-2">
          <div className="flex items-center gap-3">
            <span className="px-2.5 py-1 rounded-full bg-primary/10 text-primary border border-primary/20 text-xs font-bold uppercase tracking-wider">
              Operational Live
            </span>
            <span className="flex items-center gap-2 text-xs text-muted font-medium">
              <span className="w-2 h-2 rounded-full bg-primary animate-pulse" />
              <span>Real-time Wireless Ingress Stream</span>
            </span>
          </div>
          <h1 className="text-3xl font-extrabold tracking-tight text-secondary">
            SOC Telemetry &amp; Incident Overview
          </h1>
          <p className="text-sm text-muted max-w-2xl">
            Wireless Network Security Monitoring and Threat Intelligence (802.11 Layer 2/3 Vector Engine)
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3 text-xs">
          <div className="px-3.5 py-2 rounded-md bg-subtle border border-border text-secondary font-medium">
            <span className="text-muted">PIPELINE:</span>{' '}
            <strong className="text-secondary font-bold">E1-E4 Nominal</strong>
          </div>
          <div className="px-3.5 py-2 rounded-md bg-subtle border border-border text-secondary font-medium">
            <span className="text-muted">BACKEND:</span>{' '}
            <strong className="text-primary font-bold">200 OK (21ms)</strong>
          </div>
          <div className="px-3.5 py-2 rounded-md bg-subtle border border-border text-secondary font-medium flex items-center gap-1.5">
            <Clock className="w-3.5 h-3.5 text-muted" />
            <span>LAST SYNC: 2m ago</span>
          </div>

          <button
            onClick={() => navigate('/upload')}
            className="flex items-center gap-2 px-4 py-2 rounded-md bg-primary hover:bg-primary-hover active:bg-primary text-white font-semibold text-xs transition"
          >
            <UploadCloud className="w-4 h-4" />
            <span>+ Upload Capture (PCAP/PCAPNG)</span>
          </button>
        </div>
      </div>

      {/* Integrated Packet Architecture Strip */}
      <div className="p-4 md:p-5 rounded-md bg-white border border-border flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-md bg-subtle border border-border flex items-center justify-center text-primary">
            <Cpu className="w-5 h-5" />
          </div>
          <div>
            <span className="text-sm font-extrabold text-secondary block">Integrated Packet Architecture</span>
            <span className="text-xs text-muted">Real-time modular flow through deterministic detection filters</span>
          </div>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
          <div className="p-2.5 rounded-md bg-subtle border border-border flex items-center gap-2">
            <span className="px-1.5 py-0.5 rounded-full bg-primary text-white font-bold text-[10px]">E1</span>
            <div className="truncate">
              <span className="text-secondary font-bold block text-xs">Scapy Dissector</span>
              <span className="text-muted text-[11px]">48.2k pkt/s</span>
            </div>
          </div>
          <div className="p-2.5 rounded-md bg-subtle border border-border flex items-center gap-2">
            <span className="px-1.5 py-0.5 rounded-full bg-secondary text-white font-bold text-[10px]">E2</span>
            <div className="truncate">
              <span className="text-secondary font-bold block text-xs">Pattern Match</span>
              <span className="text-primary font-bold text-[11px]">Active Filter</span>
            </div>
          </div>
          <div className="p-2.5 rounded-md bg-subtle border border-border flex items-center gap-2">
            <span className="px-1.5 py-0.5 rounded-full bg-muted text-white font-bold text-[10px]">E3</span>
            <div className="truncate">
              <span className="text-secondary font-bold block text-xs">SQLite Storage</span>
              <span className="text-muted text-[11px]">In-Memory Sync</span>
            </div>
          </div>
          <div className="p-2.5 rounded-md bg-subtle border border-border flex items-center gap-2">
            <span className="px-1.5 py-0.5 rounded-full bg-tertiary text-white font-bold text-[10px]">E4</span>
            <div className="truncate">
              <span className="text-secondary font-bold block text-xs">Alert Dispatch</span>
              <span className="text-tertiary font-bold text-[11px]">4 Pending</span>
            </div>
          </div>
        </div>
      </div>

      {/* 6 Metric Cards Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        <MetricCard
          title="PROCESSED PACKETS"
          value="2,841,920"
          subtext="+12.4% vs shift"
          footnote="Scapy E1 Dissector 48.2k pkt/s"
          icon={Activity}
          variant="info"
          onClick={() => navigate('/traffic-logs')}
        />
        <MetricCard
          title="TRAFFIC RECORDS"
          value="1,419,080"
          subtext="SQLite E3 Normalized"
          footnote="Retention 100% Synced"
          icon={Database}
          variant="default"
          onClick={() => navigate('/traffic-logs')}
        />
        <MetricCard
          title="E2 DETECTIONS"
          value="348"
          subtext="Deterministic Thresholds"
          footnote="6 Pattern Matching Rules"
          icon={Sliders}
          variant="warning"
          onClick={() => navigate('/detections')}
        />
        <MetricCard
          title="E4 NEW ALERTS"
          value="42"
          subtext="Last 24 Hours"
          footnote="Triage Velocity: 4.3m response"
          icon={Bell}
          variant="info"
          onClick={() => navigate('/alerts')}
        />
        <MetricCard
          title="CRITICAL ALERTS"
          value="4 Requires Triage"
          subtext="Deauth & Rogue AP Floods"
          footnote="Priority Queue: Review Now"
          icon={AlertTriangle}
          variant="critical"
          onClick={() => navigate('/alerts')}
        />
        <MetricCard
          title="INGESTION BATCHES"
          value="88"
          subtext="86 Done / 2 Partial"
          footnote="PCAP Ingestion Success 97.7%"
          icon={Layers}
          variant="success"
          onClick={() => navigate('/batches')}
        />
      </div>

      {/* 2 Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <TrafficChart height={220} />
        <ProtocolDistributionChart height={220} />
      </div>

      {/* Next Row: Alert Severity Distribution + Suspicious Activity Trends */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <SeverityChart />
        <AlertTrendChart />
      </div>

      {/* Recent Security Alerts - E4 Engine */}
      <div className="bg-white border border-border rounded-md p-6 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border pb-4">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-md bg-error/10 border border-error/20 flex items-center justify-center text-error">
              <Bell className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-base font-extrabold text-secondary tracking-tight">
                Recent Security Alerts - E4 Engine
              </h3>
              <p className="text-xs text-muted">
                Live correlated threat triage queue with MAC origin signatures
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 text-xs">
            <span className="px-3 py-1 rounded-full bg-subtle border border-border text-muted font-medium">
              Auto-Refresh: 5s
            </span>
            <button
              onClick={() => navigate('/alerts')}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-white hover:bg-subtle border border-border text-secondary font-semibold text-xs transition"
            >
              <Filter className="w-3.5 h-3.5 text-muted" />
              <span>Filter Queue</span>
            </button>
          </div>
        </div>

        {/* Alerts Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-subtle text-xs font-bold text-secondary uppercase tracking-wider border-b border-border">
              <tr>
                <th className="py-3 px-4">ALERT ID</th>
                <th className="py-3 px-4">SUSPICIOUS ACTIVITY</th>
                <th className="py-3 px-4">WIRELESS TARGET / CHANNEL</th>
                <th className="py-3 px-4">SEVERITY</th>
                <th className="py-3 px-4">DETECTION TIME</th>
                <th className="py-3 px-4">STATUS</th>
                <th className="py-3 px-4 text-right">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border text-xs">
              {[
                {
                  id: '#ALT-9821',
                  name: '802.11 Deauthentication Flood Attack',
                  target: 'Targeting gateway client disconnect vectors',
                  bssid: '00:14:22:01:23:45',
                  ssid: 'Corp-Guest-Secure (Ch 6)',
                  severity: 'CRITICAL',
                  time: '2026-05-14 14:28:33 UTC',
                  status: 'NEW',
                },
                {
                  id: '#ALT-9820',
                  name: 'Evil Twin AP Deployment',
                  target: 'Duplicate SSID broadcast with anomalous OUI match',
                  bssid: '6C:5E:3B:88:91:02',
                  ssid: 'Enterprise-Executive (Ch 44)',
                  severity: 'CRITICAL',
                  time: '2026-05-14 14:25:40 UTC',
                  status: 'TRIAGED',
                },
                {
                  id: '#ALT-9819',
                  name: 'WPA2/WPA3 4-Way Handshake EAPOL Tamper',
                  target: 'Nonce reuse pattern observed in rapid exchange',
                  bssid: '00:14:22:98:A1:CC',
                  ssid: 'Research-Lab-WLAN (Ch 11)',
                  severity: 'HIGH',
                  time: '2026-05-14 14:19:02 UTC',
                  status: 'ESCALATED',
                },
                {
                  id: '#ALT-9818',
                  name: 'Beacon Interval Anomaly (>1000ms drift)',
                  target: 'Suspected low-power unauthorized rogue micro-repeater',
                  bssid: 'D8:48:B8:22:54:F1',
                  ssid: '<Hidden SSID> (Ch 1)',
                  severity: 'MEDIUM',
                  time: '2026-05-14 14:04:18 UTC',
                  status: 'NEW',
                },
                {
                  id: '#ALT-9817',
                  name: 'Excessive Probe Requests (MAC Randomization Sweep)',
                  target: '5,000+ probes/sec generated by single physical radio',
                  bssid: 'FF:FF:FF:FF:FF:FF',
                  ssid: 'Wildcard Broadcast (Ch 6)',
                  severity: 'MEDIUM',
                  time: '2026-05-14 13:58:55 UTC',
                  status: 'TRIAGED',
                },
              ].map((row) => (
                <tr key={row.id} className="hover:bg-subtle/50 transition">
                  <td className="py-3 px-4 font-mono font-bold text-primary">{row.id}</td>
                  <td className="py-3 px-4">
                    <div className="font-bold text-secondary">{row.name}</div>
                    <div className="text-xs text-muted">{row.target}</div>
                  </td>
                  <td className="py-3 px-4 text-xs">
                    <div className="text-secondary font-medium">BSSID: <span className="font-mono font-bold text-secondary">{row.bssid}</span></div>
                    <div className="text-muted text-[11px]">SSID: {row.ssid}</div>
                  </td>
                  <td className="py-3 px-4">
                    <StatusBadge value={row.severity} type="severity" size="small" />
                  </td>
                  <td className="py-3 px-4 text-xs text-muted">{row.time}</td>
                  <td className="py-3 px-4">
                    <StatusBadge value={row.status} type="status" size="small" />
                  </td>
                  <td className="py-3 px-4 text-right">
                    <button
                      onClick={() => navigate('/alerts')}
                      className="px-3 py-1.5 rounded-md bg-secondary hover:bg-muted text-white font-semibold text-xs transition"
                    >
                      Investigate
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Footer Link */}
        <div className="pt-3 border-t border-border flex items-center justify-between text-xs text-muted">
          <span>Showing 5 of 42 active alerts</span>
          <button
            onClick={() => navigate('/alerts')}
            className="text-primary hover:text-primary-hover font-bold flex items-center gap-1.5"
          >
            <span>Open Incident Response Command Triage</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Recent Processing Batches - E1 & E3 Ingestion Engine */}
      <div className="bg-white border border-border rounded-md p-6 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border pb-4">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-md bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
              <Layers className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-base font-extrabold text-secondary tracking-tight">
                Recent Processing Batches - E1 &amp; E3 Ingestion Engine
              </h3>
              <p className="text-xs text-muted">
                Scapy packet extraction and SQLite batch serialization status
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 text-xs">
            <span className="px-3 py-1 rounded-full bg-primary/10 text-primary border border-primary/20 font-bold">
              Rate: 48,200 pkt/s
            </span>
            <button
              onClick={() => navigate('/batches')}
              className="text-primary hover:text-primary-hover font-bold text-xs flex items-center gap-1.5"
            >
              <span>View History</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Batches Table with Progress Bars */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-subtle text-xs font-bold text-secondary uppercase tracking-wider border-b border-border">
              <tr>
                <th className="py-3 px-4">BATCH ID</th>
                <th className="py-3 px-4">SOURCE CAPTURE FILE</th>
                <th className="py-3 px-4">SUBMITTED AT</th>
                <th className="py-3 px-4">TOTAL RECORDS</th>
                <th className="py-3 px-4">INGESTION PROGRESS</th>
                <th className="py-3 px-4">FAILED / CORRUPT</th>
                <th className="py-3 px-4 text-right">STATUS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border text-xs">
              {[
                {
                  id: '#BAT-2025-089',
                  file: 'wlan_capture_office_floor3.pcapng',
                  time: '14:12:05 UTC',
                  total: '148,200',
                  parsed: '148,188 parsed',
                  pct: 99.9,
                  failed: '12 pkt',
                  status: 'COMPLETED',
                },
                {
                  id: '#BAT-2025-088',
                  file: 'gateway_mesh_monitor_node2.pcap',
                  time: '13:45:19 UTC',
                  total: '320,440',
                  parsed: '320,440 parsed',
                  pct: 100,
                  failed: '0 pkt',
                  status: 'COMPLETED',
                },
                {
                  id: '#BAT-2025-087',
                  file: 'perimeter_ids_ch1_sweep.pcapng',
                  time: '13:10:02 UTC',
                  total: '512,100',
                  parsed: '489,050 parsed',
                  pct: 95.4,
                  failed: '23,050 CRC ERR',
                  status: 'PARTIAL',
                },
                {
                  id: '#BAT-2025-086',
                  file: 'drone_telemetry_survey_80211.pcap',
                  time: '12:30:44 UTC',
                  total: '98,000',
                  parsed: '98,000 parsed',
                  pct: 100,
                  failed: '0 pkt',
                  status: 'COMPLETED',
                },
              ].map((b) => (
                <tr key={b.id} className="hover:bg-subtle/50 transition">
                  <td className="py-3 px-4 font-mono font-bold text-primary">{b.id}</td>
                  <td className="py-3 px-4 font-mono text-secondary font-medium">{b.file}</td>
                  <td className="py-3 px-4 text-xs text-muted">{b.time}</td>
                  <td className="py-3 px-4 text-secondary font-bold">{b.total}</td>
                  <td className="py-3 px-4 min-w-[180px]">
                    <div className="flex items-center justify-between text-xs text-muted mb-1">
                      <span>{b.parsed}</span>
                      <span className="font-bold text-secondary">{b.pct}%</span>
                    </div>
                    <div className="w-full h-2 bg-subtle rounded-full overflow-hidden">
                      <div
                        className="h-full bg-primary rounded-full transition-all duration-300"
                        style={{ width: `${b.pct}%` }}
                      />
                    </div>
                  </td>
                  <td className="py-3 px-4 text-xs font-medium">
                    <span className={b.failed.includes('ERR') ? 'text-error font-bold' : 'text-muted'}>
                      {b.failed}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-right">
                    <StatusBadge value={b.status} type="status" size="small" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Footer Database Engine Size Note */}
        <div className="pt-3 border-t border-border flex items-center justify-between text-xs text-muted">
          <span className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-primary" />
            <span>E3 SQLite Database engine file size: <strong className="text-secondary font-bold">1.84 MB</strong> (WAL mode enabled)</span>
          </span>
          <span>Storage sync interval: <strong className="text-secondary font-bold">Realtime</strong></span>
        </div>
      </div>
    </div>
  );
}
