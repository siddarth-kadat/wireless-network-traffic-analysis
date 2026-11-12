# W-NTAAS Cybersecurity Monitoring Frontend

Professional Security Operations Center (SOC) web application for the **Wireless Network Traffic Analysis and Alerting System**.

---

## 1. System Overview

The frontend interface serves two key stakeholders:
- **Network Administrator:** Uploads PCAP captures, supervises batch processing diagnostics, manages user accounts, and reviews telemetry.
- **Security Analyst:** Triages incoming threat alerts, explores decoded wireless/IP packet logs, reviews detection results, and inspects deterministic detection rules.

### Design Principles
- **Deep Navy SOC Theme:** Built with custom dark cybersecurity elevations (`#080C14`, `#0F172A`, `#1E293B`, `#00E5FF`).
- **Data Visualizations:** Built using **Plotly** for high-density time-series traffic rates, protocol breakdowns, severity distributions, and incident frequency trends.
- **Deterministic Threat Representation:** Strictly reflects the predefined deterministic rule detection contracts from E2 and alert generation from E4 (zero black-box ML/AI).
- **Relational Integrity:** Maps 1-to-1 to the approved 7-entity relational database design (`User`, `Log_Batch`, `Traffic_Log`, `Detection_Rule`, `Detection_Result`, `Alert`, `Processing_Error`).

---

## 2. Technology Stack

| Layer | Technology |
|---|---|
| **Framework** | React 18 |
| **Language** | JavaScript (ESNext / JSX) |
| **Build Tool** | Vite |
| **Data Visualizations** | Plotly (`plotly.js-dist-min` + `react-plotly.js`) |
| **Icons** | Lucide React |
| **Routing** | React Router v6 |
| **Testing** | Vitest |

---

## 3. Pages & Features

1. **Authentication (`/login`)**
   - Stakeholder login form with quick single-click demo access buttons for both **Network Administrator** and **Security Analyst**.
2. **SOC Overview Dashboard (`/`)**
   - Real-time KPI metric cards (Active Critical Threats, Analyzed Wireless Frames, Active Rules, Ingestion Batches).
   - 4 Plotly interactive charts:
     - `TrafficChart`: Temporal wireless throughput and packet velocity area chart.
     - `ProtocolDistributionChart`: Wireless management, data, and transport protocol donut chart.
     - `SeverityChart`: Horizontal alert severity distribution bar chart.
     - `AlertTrendChart`: Stacked hourly incident volume bar chart.
   - Live triage feed with quick Acknowledge and deep Inspection modals.
3. **PCAP Ingestion Station (`/upload`)**
   - Drag-and-drop file upload station supporting `.pcap` and `.pcapng`.
   - File extension validation, real-time ingestion simulation, and instant batch diagnostic summary.
4. **Traffic Log Explorer (`/traffic-logs`)**
   - Searchable, sortable, paginated table representing the `Traffic_Log` entity.
   - Quick protocol filters (`802.11_MGMT`, `802.11_DATA`, `TCP`, `UDP`, `ARP`).
   - Deep packet dissection modal displaying link layer RadioTap/wireless headers, BSSID, SSID, signal strength, and network addressing.
   - CSV export capability.
5. **Security Alerts Triage (`/alerts`)**
   - Incident triage console representing the `Alert` entity.
   - Severity filters (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and status filters (`NEW`, `ACKNOWLEDGED`, `RESOLVED`).
   - Inline action buttons to acknowledge and resolve incidents.
6. **Detection Results (`/detections`)**
   - Forensics viewer representing the `Detection_Result` entity.
   - Filter by suspicious threats vs benign traffic.
   - Inspects forensic evidence, triggered rule conditions, and linked traffic logs.
7. **Deterministic Detection Rules (`/rules`)**
   - Rule manager representing the `Detection_Rule` entity.
   - Active/disabled engine state toggles.
   - Inspects exact mathematical threshold conditions and sliding time windows.
8. **Processing Batches & Diagnostics (`/batches`)**
   - Audit trail representing `Log_Batch` and `Processing_Error` entities.
   - Displays parsed record counts, corruption counts, and drill-down into packet parsing error telemetry.
9. **Stakeholder User Management (`/users`)**
   - Role-protected route accessible strictly to the **Network Administrator**.
   - User creation modal and stakeholder directory representing the `User` entity.
10. **Executive SOC Reports (`/reports`)**
    - Executive audit report generator with printable view and JSON export.
11. **System Settings & Telemetry (`/settings`)**
    - Backend API gateway URL configuration and live ping check.
    - Health cards for the 4 modular engines (E1, E2, E3, E4).
    - Database entity compliance summary and demo state reset button.

---

## 4. Getting Started

### Prerequisites
- Node.js (v18+)
- npm (v9+)

### Installation
```bash
cd frontend
npm install
```

### Running the Development Server
```bash
npm run dev
```
The application will launch on `http://localhost:5173`.

### Running Unit Tests
```bash
npm test
```

### Production Build
```bash
npm run build
```
Generates production-optimized static assets in the `dist/` directory.

---

## 5. Stakeholder Demo Credentials

| Role | Username | Password | Access Scope |
|---|---|---|---|
| **Network Administrator** | `admin` | `admin123` | Full access including User Management & PCAP Ingestion |
| **Security Analyst** | `analyst` | `analyst123` | SOC Monitoring, Traffic Explorer, Detection Results, Alerts Triage |

