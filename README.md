# wireless-network-traffic-analysis
Wireless Network Traffic Analysis and Alerting System

## Overview
A modular, engine-based system for analyzing wireless network traffic logs, detecting suspicious patterns via deterministic rules, and alerting security administrators and analysts.

### Architecture & Engines
- **E1: Log Processing Engine**: Ingestion, validation, parsing, and concurrent preprocessing.
- **E2: Suspicious Pattern Detection Engine**: Deterministic signature, threshold, and statistical rule evaluation.
- **E3: Log and Alert Storage Engine**: Central database gateway owning all persistence operations.
- **E4: Alert Generation Engine**: Context-rich security alert generation and deduplication.

### Technology Stack
- **Backend**: Python 3.12+, FastAPI, SQLAlchemy, SQLite, Pandas, NumPy
- **Frontend**: React, JavaScript, HTML, CSS, Plotly
- **Detection**: Deterministic Rule-Based (Signature, Threshold, Statistical)

### Project Structure
- `backend/`: FastAPI application, modular engines (E1-E4), database models, coordination, security, and tests.
- `frontend/`: React single-page application with components, pages, layouts, services, and charts.
- `data/`: Data staging directories (`input/`, `processed/`, `archive/`, `quarantine/`).
- `docs/`: Handbooks (G0, G1, S1), architecture diagrams, algorithms, and database design.
