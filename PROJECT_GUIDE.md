# Wireless Network Traffic Analysis and Alerting System (NetWatch)
## Master Project Architecture, Functional Specification & Execution Guide

---

## 1. Executive Project Overview

**NetWatch** (officially registered as the **Wireless Network Traffic Analysis and Alerting System** — *W-NTASSOC*) is an enterprise-grade, deterministic cybersecurity platform engineered for analyzing IEEE 802.11 wireless network traffic, detecting malicious behavior and anomalous radio-frequency activity, and routing security incidents to security operations center (SOC) analysts in real time.

The system is constructed with a decoupled, four-engine architecture where each engine specializes in a distinct domain of the packet processing and threat analysis lifecycle:
- **E1: Log Processing Engine**: Ingests, parses, validates, and normalizes raw PCAP/PCAPNG packet captures.
- **E2: Suspicious Pattern Detection Engine**: Evaluates parsed network traffic records against deterministic signature, threshold, and statistical detection rules.
- **E3: Log and Alert Storage Engine**: Provides high-performance, ACID-compliant persistence with SQLite WAL mode, powering analytics and query indexing.
- **E4: Alert Generation Engine**: Ingests detection outcomes, computes MITRE-aligned severity, deduplicates bursts, and dispatches structured alerts.
- **Integration & Coordination Layer**: Coordinates inter-engine data pipelines, manages thread pools, and brokers pub/sub events.
- **FastAPI REST API Layer**: Provides authenticated, asynchronous REST endpoints for frontend telemetry, data queries, and incident triage.
- **React Tailwind SOC Dashboard**: A high-density cybersecurity monitoring dashboard featuring collapsible navigation, live pipeline metrics, threat distribution visualizations, and alert triage.

```
+-------------------------------------------------------------------------------------------------------+
|                                          NetWatch Architecture                                        |
+-------------------------------------------------------------------------------------------------------+
                                                     |
                                   +-----------------+-----------------+
                                   | Raw PCAP/PCAPNG Capture Files     |
                                   +-----------------+-----------------+
                                                     |
                                                     v
                                   +-----------------------------------+
                                   | E1: Log Processing Engine         |
                                   | - Scapy Packet Dissection         |
                                   | - 802.11 Frame Parsing            |
                                   | - Normalization & Validation      |
                                   +-----------------+-----------------+
                                                     |
                                                     | Normalized Batch Records
                                                     v
                                   +-----------------------------------+
                                   | E3: Log and Alert Storage Engine  |
                                   | - Bulk Ingestion / WAL SQLite     |
                                   | - Traffic Indexing & Persistence  |
                                   +-----------------+-----------------+
                                                     |
                                                     | Persisted Record Batches
                                                     v
                                   +-----------------------------------+
                                   | E2: Pattern Detection Engine      |
                                   | - Deterministic Signatures        |
                                   | - Sliding-Window Thresholds       |
                                   | - Statistical Anomalies           |
                                   +-----------------+-----------------+
                                                     |
                                                     | Detection Outcomes
                                                     v
                                   +-----------------------------------+
                                   | E4: Alert Generation Engine       |
                                   | - Severity Calculation            |
                                   | - Deduplication & Suppression     |
                                   | - Triage Dispatch Payload         |
                                   +-----------------+-----------------+
                                                     |
                                                     | Structured Alerts
                                                     v
                                   +-----------------------------------+
                                   | E3: Alert Persistence Gateway     |
                                   | - Alert Table Storage             |
                                   | - Foreign Key Linking to Logs     |
                                   +-----------------+-----------------+
                                                     |
                                                     v
                                   +-----------------------------------+
                                   | FastAPI REST API Service (8000)   |
                                   | - Auth, Ingestion, Triage, Rules  |
                                   +-----------------+-----------------+
                                                     |
                                                     v
                                   +-----------------------------------+
                                   | React SOC Web Dashboard (5173)    |
                                   | - NetWatch Triage & Telemetry UI  |
                                   +-----------------------------------+
```

---

## 2. Technology Stack

| Layer | Component | Technology / Library | Role & Function |
| :--- | :--- | :--- | :--- |
| **Backend Core** | Runtime | Python 3.12+ | Core execution environment |
| **Backend Core** | REST API Framework | FastAPI & Starlette | Asynchronous HTTP endpoints and OpenAPI documentation |
| **Backend Core** | ASGI Web Server | Uvicorn | High-throughput asynchronous server |
| **Packet Dissection** | Frame Engine | Scapy 2.5+ | Deep packet inspection for IEEE 802.11, RadioTap, EAPoL, IP |
| **Data Engine** | Data Processing | Pandas & NumPy | High-performance batch array manipulations and statistical calculations |
| **Data Engine** | ORM & Persistence | SQLAlchemy 2.0+ & SQLite3 | Normalized relational persistence with WAL journal mode |
| **Security Layer** | Authentication | Python-JOSE, Passlib & Bcrypt | JWT authentication, role-based access control, password hashing |
| **Frontend Core** | Framework | React 18 & Vite | Single-page application framework and build tooling |
| **Frontend Core** | Styling & UI | Tailwind CSS | Utility-first styling for dark/light SOC themes |
| **Frontend Core** | Visualizations | Lucide Icons & Plotly | Interactive charting, sparklines, and metric cards |
| **Testing** | Verification | Pytest & Vitest | Backend and frontend unit, integration, and end-to-end tests |

---

## 3. How Each Function Works (Engine-by-Engine Deep Dive)

### E1: Log Processing Engine (`backend/src/engines/e1_log_processing/`)

E1 is responsible for reading raw PCAP or PCAPNG packet capture files, extracting IEEE 802.11 Layer 2 frame metadata, validating packet integrity, and formatting the records into normalized dictionaries for downstream engines.

#### Key Functions and Classes:
1. `PCAPParser.parse_file(file_path: str, batch_size: int = 5000) -> Generator[List[Dict]]`
   - **Location**: `backend/src/engines/e1_log_processing/parser.py`
   - **How it works**: Uses Scapy's streaming `PcapReader` to process capture files iteratively without loading entire gigabyte captures into memory. Dissects RadioTap headers, 802.11 Management frames (Deauth, Disassoc, Beacon, Probe Request/Response, Association), 802.11 Control frames (RTS, CTS, ACK), and 802.11 Data frames (including EAPoL 4-Way Handshakes and encapsulated IPv4/IPv6 packets).
2. `PacketDecoder.decode_packet(packet) -> Optional[NormalizedPacketRecord]`
   - **Location**: `backend/src/engines/e1_log_processing/decoder.py`
   - **How it works**: Extracts critical fields including `timestamp`, `frame_type`, `frame_subtype`, `source_mac`, `destination_mac`, `bssid`, `ssid`, `channel`, `signal_strength_dbm`, `sequence_number`, `retry_flag`, `duration`, `wep_iv`, and `payload_size`.
3. `FrameValidator.validate(packet_record: Dict) -> ValidationResult`
   - **Location**: `backend/src/engines/e1_log_processing/validator.py`
   - **How it works**: Validates MAC address structure against standard IEEE EUI-48 formats, checks FCS (Frame Check Sequence) validity, and identifies truncated or corrupted frames. Bad records are routed to an error-tracking log rather than crashing the pipeline.
4. `BatchProcessor.process_stream(packets) -> BatchProcessingSummary`
   - **Location**: `backend/src/engines/e1_log_processing/batch_processor.py`
   - **How it works**: Aggregates decoded packets into fixed chunks (e.g. 1,000 to 5,000 records), generates a unique `batch_id` (UUID4), calculates processing throughput (packets/second), and delivers the clean records to the Coordinator.

---

### E2: Suspicious Pattern Detection Engine (`backend/src/engines/e2_suspicious_pattern_detection/`)

E2 is the deterministic threat detection core. It evaluates stream-batched network traffic against preconfigured rules without relying on unexplainable black-box models. Every detection produces an auditable rule-hit record.

#### Key Functions and Classes:
1. `SuspiciousPatternDetectionEngine.process_packet_batch(batch_records: List[Dict]) -> DetectionBatchResult`
   - **Location**: `backend/src/engines/e2_suspicious_pattern_detection/detection_engine.py`
   - **How it works**: Orchestrates three internal detectors (Signature, Threshold, and Statistical) across the incoming batch. Aggregates matched outcomes, measures evaluation latency, and returns a `DetectionBatchResult` containing all rule breaches and performance metrics.
2. `SignatureDetector.evaluate(records: List[Dict]) -> List[RuleMatch]`
   - **Location**: `backend/src/engines/e2_suspicious_pattern_detection/detectors/signature_detector.py`
   - **How it works**: Executes deterministic checks on individual frame fields:
     - *802.11 Deauthentication Flood*: Identifies Type 0 (Management), Subtype 12 (Deauth) with broadcast or spoofed gateway BSSIDs.
     - *Evil Twin AP Detection*: Identifies identical SSIDs advertised from unauthorized BSSIDs or conflicting encryption capabilities.
     - *WPA 4-Way Handshake Cracking*: Detects EAPoL key exchanges with anomalous nonce repetition or excessive rapid exchanges.
     - *Weak IV / WEP Injection*: Identifies static or repeated Initialization Vectors in legacy frames.
3. `ThresholdDetector.evaluate(records: List[Dict]) -> List[RuleMatch]`
   - **Location**: `backend/src/engines/e2_suspicious_pattern_detection/detectors/threshold_detector.py`
   - **How it works**: Organizes packets into sliding time windows (e.g. 1 to 5 seconds) per source MAC address:
     - *Excessive Probe Requests*: Triggers if a client generates more than 50 probe requests within 2 seconds (indicative of active Wi-Fi scanning tools).
     - *Disassociation Storm*: Triggers if disassociation frames exceed the threshold within a rolling 3-second window.
4. `StatisticalDetector.evaluate(records: List[Dict]) -> List[RuleMatch]`
   - **Location**: `backend/src/engines/e2_suspicious_pattern_detection/detectors/statistical_detector.py`
   - **How it works**: Computes moving standard deviations and inter-arrival time distributions:
     - *Beacon Interval Anomaly*: Identifies APs whose beacon frequency drifts by more than 3 standard deviations from the 100ms baseline.
5. `RuleRegistry.get_active_rules() / toggle_rule(rule_id: str, enabled: bool)`
   - **Location**: `backend/src/engines/e2_suspicious_pattern_detection/rules/rule_registry.py`
   - **How it works**: Manages the life cycle of detection rules, allowing analysts to dynamically enable or disable rules through the API without restarting the engine.

---

### E3: Log and Alert Storage Engine (`backend/src/engines/e3_log_alert_storage/`)

E3 is the persistence authority of NetWatch. No engine communicates directly with the raw database; all storage operations must pass through E3.

#### Key Functions and Classes:
1. `E3StorageEngine.store_batch(batch_metadata: Dict, records: List[Dict]) -> int`
   - **Location**: `backend/src/engines/e3_log_alert_storage/storage_engine.py`
   - **How it works**: Inserts batch metadata into `processing_batches` and executes a bulk insert of normalized frame records into the `network_traffic_logs` table. Operates inside an atomic database transaction to prevent orphaned batches.
2. `E3StorageEngine.store_alerts(alerts: List[Dict]) -> int`
   - **Location**: `backend/src/engines/e3_log_alert_storage/storage_engine.py`
   - **How it works**: Persists generated security alerts into the `security_alerts` table, establishing foreign-key references to corresponding batch IDs and triggering log records.
3. `E3StorageEngine.query_logs(filters: Dict, page: int, limit: int) -> Tuple[List[Dict], int]`
   - **Location**: `backend/src/engines/e3_log_alert_storage/query_service.py`
   - **How it works**: Constructs dynamic SQLAlchemy queries supporting filtering by timestamp range, MAC address, BSSID, frame type, protocol, and batch ID, with indexed pagination.
4. `DatabaseManager.get_session()`
   - **Location**: `backend/src/engines/e3_log_alert_storage/database.py`
   - **How it works**: Manages the SQLite engine configured with Write-Ahead Logging (`PRAGMA journal_mode=WAL`), zero-lock contention, foreign keys enabled (`PRAGMA foreign_keys=ON`), and thread-safe session factories.

---

### E4: Alert Generation Engine (`backend/src/engines/e4_alert_generation/`)

E4 ingests raw detection matches from E2, contextualizes the security incident, eliminates redundant alerts, and formats the output for SOC analyst consumption.

#### Key Functions and Classes:
1. `E4AlertEngine.generate_alerts(detection_result: DetectionBatchResult) -> List[SecurityAlert]`
   - **Location**: `backend/src/engines/e4_alert_generation/e4_engine.py`
   - **How it works**: Iterates over matched outcomes from E2. For each breach, it checks deduplication criteria, calculates the contextual severity, enriches the alert with MITRE ATT&CK wireless classification, and outputs structured alert models.
2. `DeduplicationEngine.is_duplicate(match: RuleMatch) -> bool`
   - **Location**: `backend/src/engines/e4_alert_generation/deduplication.py`
   - **How it works**: Computes an incident hash based on `(rule_id, source_mac, target_bssid)`. If an identical incident occurred within the deduplication suppression window (e.g. 60 seconds), the alert counter is incremented without creating a redundant alert record.
3. `SeverityCalculator.calculate_severity(rule_match: RuleMatch, context: Dict) -> AlertSeverity`
   - **Location**: `backend/src/engines/e4_alert_generation/severity_calculator.py`
   - **How it works**: Maps detection metrics to standard severity tiers:
     - `CRITICAL`: Active attacks (Deauth floods, WPA handshake cracking, Evil Twin).
     - `HIGH`: Reconnaissance and rogue probes (KARMA attacks, unauthenticated beacon injection).
     - `MEDIUM`: Threshold violations (excessive probe scans, frame rate anomalies).
     - `LOW`: Protocol warnings (beacon drift, legacy encryption usage).
4. `DispatchManager.dispatch(alert: SecurityAlert)`
   - **Location**: `backend/src/engines/e4_alert_generation/dispatcher.py`
   - **How it works**: Routes alerts to active subscribers, prepares incident response triage records, and triggers webhooks if configured.

---

### Backend Coordination & Integration (`backend/src/coordination/`)

The coordination package bridges the independent engines into a unified pipeline without altering the internal source code of any engine.

#### Key Functions and Classes:
1. `EngineCoordinator.process_pcap_file(file_path: str, filename: str) -> Dict`
   - **Location**: `backend/src/coordination/engine_coordinator.py`
   - **How it works**: The master end-to-end orchestration pipeline:
     1. Dispatches PCAP file to **E1** (`PCAPParser.parse_file`).
     2. Persists normalized packet records to **E3** (`E3StorageEngine.store_batch`).
     3. Feeds normalized records into **E2** (`SuspiciousPatternDetectionEngine.process_packet_batch`).
     4. Passes detection outcomes to **E4** (`E4AlertEngine.generate_alerts`).
     5. Saves generated alerts to **E3** (`E3StorageEngine.store_alerts`).
     6. Returns a comprehensive execution summary containing packet counts, detection matches, and alert counts.
2. `MessageHandler` (Pub/Sub Event Broker)
   - **Location**: `backend/src/coordination/message_handler.py`
   - **How it works**: In-memory event bus providing thread-safe pub/sub messaging (`publish`, `subscribe`, `get_event_history`) for inter-engine notifications and audit trails.
3. `PipelineController`
   - **Location**: `backend/src/coordination/pipeline_controller.py`
   - **How it works**: Wraps asynchronous batch execution inside a Python `ThreadPoolExecutor`, preventing CPU-heavy packet dissection from blocking FastAPI's asynchronous event loop.

---

### FastAPI REST API Layer (`backend/src/api/`)

The API layer exposes the coordination pipeline and database queries as RESTful endpoints for the frontend.

| Method | Endpoint | File | Purpose |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/auth/login` | `auth_routes.py` | Authenticates username/password and issues JWT access tokens |
| `GET` | `/api/auth/me` | `auth_routes.py` | Retrieves currently authenticated user profile and roles |
| `POST` | `/api/batches/upload` | `log_routes.py` | Accepts `.pcap`/`.pcapng` uploads and triggers pipeline execution |
| `GET` | `/api/batches` | `log_routes.py` | Returns paginated list of all processed capture batches |
| `GET` | `/api/batches/{id}` | `log_routes.py` | Returns details and statistics for a specific batch |
| `GET` | `/api/logs` | `log_routes.py` | Returns paginated, searchable network traffic records from E3 |
| `GET` | `/api/logs/stats/summary`| `log_routes.py` | Returns aggregate packet counts, protocol distribution, and rates |
| `GET` | `/api/detection/rules` | `detection_routes.py`| Lists all deterministic rules and their current enabled/disabled state |
| `POST` | `/api/detection/rules/{id}/toggle` | `detection_routes.py`| Toggles rule active state |
| `GET` | `/api/detection/results`| `detection_routes.py`| Lists detection rule breaches from E2 |
| `GET` | `/api/alerts` | `alert_routes.py` | Returns security alerts with severity filters and pagination |
| `GET` | `/api/alerts/{id}` | `alert_routes.py` | Fetches full forensic detail of a specific alert |
| `PATCH`| `/api/alerts/{id}/status`| `alert_routes.py` | Updates alert triage state (`NEW`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`) |
| `GET` | `/api/admin/metrics` | `administrator_routes.py`| Live pipeline telemetry and memory health across E1-E4 |
| `GET` | `/api/admin/system/status`| `administrator_routes.py`| Operational status of all four engines |

---

### React Frontend Dashboard (`frontend/src/`)

The frontend is a modern React application utilizing Tailwind CSS for high-density SOC visualization.

#### Key Components and Pages:
1. `SOCLayout.jsx`: Master layout implementing a flexbox direct-sibling structure (`<Sidebar />` and `<main className="flex-1 min-w-0">`). This completely eliminates sidebar-overlapping bugs and dynamically adapts to sidebar collapse/expansion and screen resizing. Supports `Ctrl+B` keyboard toggle.
2. `Sidebar.jsx`: Collapsible navigation menu supporting:
   - **Expanded Mode**: Full navigation labels, section headings (*Overview*, *Network Monitoring*, *Threat Detection*, *System*), and active indicators.
   - **Collapsed Mode**: Narrow icon-only bar with hover tooltips displaying title, category, and description.
   - **Mobile Drawer**: Slide-in navigation drawer with background backdrop for screens under 1024px.
3. `Navbar.jsx`: Displays the official branding **NetWatch** with subtitle **Wireless Network Security Monitoring**, mobile drawer trigger, desktop collapse button, live Four-Engine Pipeline status badge, and user session controls.
4. `Dashboard.jsx`: Executive telemetry view displaying:
   - Total processed packets, normalized traffic records, E2 detections, generated alerts, and critical triage counts.
   - Live Network Traffic Over Time chart.
   - 802.11 Protocol & Frame Distribution breakdown.
   - Alert Severity Distribution bars.
   - Top Suspicious Activity Trends (Deauth floods, Beacon spoofing, Evil Twin, etc.).
   - Live Recent Security Alerts triage table.
   - Recent Processing Batches status list.
5. `EngineStatus.jsx`: Dedicated engine health and telemetry monitor displaying live operational metrics for E1, E2, E3, and E4, including memory usage, processing rate, active rules, and data flow architecture.
6. `UploadPCAP.jsx`: Drag-and-drop file ingestion portal allowing operators to upload `.pcap`/`.pcapng` captures, configure batch sizing, and track parsing progress.
7. `TrafficLogs.jsx`: Deep forensic traffic explorer for filtering, searching, and inspecting decoded 802.11 frames.
8. `Alerts.jsx`: Incident triage station supporting severity filtering, status updates, and full forensic payload inspection.

---

## 4. Step-by-Step Instructions: How to Run the Project

### Prerequisites
Make sure your system has the following installed:
- **Python**: Version 3.12 or higher (Python 3.12, 3.13, or 3.14).
- **Node.js**: Version 18.0 or higher.
- **npm** or **pnpm**: Package manager for frontend dependencies.
- **Git**: For version control.

---

### Step 1: Open the Project Directory
Open your terminal (PowerShell, Command Prompt, or Bash) and navigate to the repository root:
```bash
cd "d:\SEM V\Mini Project\Implementation\wireless-network-traffic-analysis"
```

---

### Step 2: Set Up Backend Environment & Dependencies
1. Create and activate a Python virtual environment (optional but recommended):
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```
2. Install the required backend Python dependencies:
   ```bash
   pip install fastapi uvicorn scapy pandas numpy sqlalchemy pydantic python-jose passlib bcrypt python-multipart pytest httpx
   ```

---

### Step 3: Initialize Database and Default Users
The database is automatically initialized on the first run, but you can verify or seed the default accounts by running the database migration/init script:
```powershell
$env:PYTHONPATH="."
python -c "from backend.src.database.init_db import init_db; init_db(); print('Database initialized successfully with default users.')"
```

#### Pre-Configured User Credentials:
| Role | Username | Password | Access Level |
| :--- | :--- | :--- | :--- |
| **System Administrator** | `admin` | `admin123` | Full access: Configuration, rule toggling, user management, engine status |
| **SOC Security Analyst** | `analyst` | `analyst123` | Operational access: PCAP upload, traffic inspection, alert triage, reports |

---

### Step 4: Start the FastAPI Backend Server
Run the FastAPI application using Uvicorn on port **8000**:
```powershell
$env:PYTHONPATH="."
python -m uvicorn backend.src.api.main:app --host 0.0.0.0 --port 8000 --reload
```
- **Backend API URL**: `http://localhost:8000`
- **Interactive Swagger Documentation**: `http://localhost:8000/docs`
- **ReDoc Documentation**: `http://localhost:8000/redoc`
- **API Health Check**: `http://localhost:8000/api/health`

---

### Step 5: Set Up and Start the React Frontend
Open a **new separate terminal** window and navigate to the `frontend/` directory:
```bash
cd "d:\SEM V\Mini Project\Implementation\wireless-network-traffic-analysis\frontend"
```

1. Install frontend dependencies (if not already installed):
   ```bash
   npm install
   ```
2. Start the Vite development server:
   ```bash
   npm run dev
   ```
- **Frontend Web Application**: `http://localhost:5173`

---

### Step 6: Using the Web Application
1. Open your browser and navigate to `http://localhost:5173`.
2. Sign in using `admin` / `admin123` or `analyst` / `analyst123`.
3. In the sidebar:
   - Click **PCAP File Upload** under *Network Monitoring* to upload a sample capture.
   - View live telemetry and metrics on the **Dashboard**.
   - Inspect individual decoded 802.11 frames in the **Traffic Explorer**.
   - Triage detected security threats in **Alert Management**.
   - Check the health of E1, E2, E3, and E4 on the **Engine Status** page.
   - Toggle the sidebar collapsed/expanded mode using the toggle button in the sidebar or navbar (or press `Ctrl+B`).

---

### Step 7: Running the Automated Test Suites

#### 1. Backend Integration & Engine Tests:
Run pytest from the project root:
```powershell
$env:PYTHONPATH="."
pytest backend/tests/ -v
```
All engine tests (E1, E2, E3, E4) and coordination integration tests should pass with 100% success.

#### 2. Frontend Component & Unit Tests:
Run Vitest from the `frontend/` directory:
```bash
cd frontend
npm test -- --run
```

#### 3. Production Build Verification:
Verify that the frontend builds cleanly without syntax or bundling errors:
```bash
cd frontend
npm run build
```

---

## 5. Security Architecture & Preserved Integrity

- **Strict Engine Preservation**: All internal algorithms, threshold constants, frame decoders, and database schemas in `backend/src/engines/` (`e1_log_processing`, `e2_suspicious_pattern_detection`, `e3_log_alert_storage`, `e4_alert_generation`) remain completely unmodified.
- **Auditable Security**: Detection rules rely on deterministic signatures, sliding windows, and statistical models, guaranteeing zero false-positive hallucination.
- **Fail-Safe Processing**: Corrupted or incomplete frames are segregated into batch error logs without interrupting the processing of valid traffic.
