# Backend API Requirements Specification

## Project
**Wireless Network Traffic Analysis and Alerting System (W-NTAAS)**

## Document Purpose
This document catalogs all backend HTTP REST endpoints required by the React cybersecurity monitoring frontend. Each specification defines the route, HTTP method, required query/body parameters, response status codes, JSON payload schemas, and alignment with the approved 7-entity relational database design.

---

## 1. Authentication & Session Endpoints (`/api/auth`)

### 1.1 Stakeholder Login
- **Endpoint:** `POST /api/auth/login`
- **Current Status:** `Pending Backend Implementation`
- **Description:** Authenticates Network Administrator or Security Analyst using credentials.
- **Request Body:**
  ```json
  {
    "username": "string (required)",
    "password": "string (required)"
  }
  ```
- **Responses:**
  - `200 OK`:
    ```json
    {
      "access_token": "string (JWT)",
      "token_type": "bearer",
      "user": {
        "user_id": "string",
        "username": "string",
        "role": "Network Administrator | Security Analyst",
        "full_name": "string",
        "email": "string"
      }
    }
    ```
  - `401 Unauthorized`: Invalid credentials.

### 1.2 Current Stakeholder Profile
- **Endpoint:** `GET /api/auth/me`
- **Current Status:** `Pending Backend Implementation`
- **Headers:** `Authorization: Bearer <token>`
- **Response `200 OK`:**
  ```json
  {
    "user_id": "string",
    "username": "string",
    "role": "Network Administrator | Security Analyst",
    "full_name": "string",
    "email": "string"
  }
  ```

---

## 2. PCAP Ingestion & Batch Endpoints (`/api/batches`)

### 2.1 Retrieve All Ingestion Batches
- **Endpoint:** `GET /api/batches`
- **Current Status:** `Pending Backend Implementation`
- **Query Parameters:** `status` (optional: `SUCCESS`, `PARTIAL_SUCCESS`, `FAILED`, `PROCESSING`)
- **Entity Alignment:** `Log_Batch`
- **Response `200 OK`:**
  ```json
  [
    {
      "batch_id": "string (UUID)",
      "user_id": "string (FK to User)",
      "file_name": "string",
      "file_format": "pcap | pcapng",
      "submitted_at": "string (ISO 8601)",
      "processing_status": "SUCCESS | PARTIAL_SUCCESS | FAILED | PROCESSING",
      "total_records": 1200,
      "processed_records": 1198,
      "failed_records": 2
    }
  ]
  ```

### 2.2 Upload PCAP Capture File
- **Endpoint:** `POST /api/batches/upload`
- **Current Status:** `Pending Backend Implementation`
- **Payload:** `multipart/form-data`
  - `file`: Raw binary `.pcap` or `.pcapng` file
  - `user_id`: String (authenticated stakeholder ID)
- **Response `201 Created`:** Returns newly instantiated `Log_Batch` entity.

### 2.3 Batch Processing Errors Telemetry
- **Endpoint:** `GET /api/batches/{batch_id}/errors`
- **Current Status:** `Pending Backend Implementation`
- **Entity Alignment:** `Processing_Error`
- **Response `200 OK`:**
  ```json
  [
    {
      "error_id": "string (UUID)",
      "batch_id": "string (FK to Log_Batch)",
      "packet_index": 42,
      "error_type": "CORRUPTED_FRAME_HEADER",
      "error_message": "Truncated RadioTap frame header encountered",
      "occurred_at": "string (ISO 8601)"
    }
  ]
  ```

---

## 3. Traffic Log Endpoints (`/api/logs`)

### 3.1 Query Traffic Logs
- **Endpoint:** `GET /api/logs`
- **Current Status:** `Pending Backend Implementation`
- **Entity Alignment:** `Traffic_Log`
- **Query Parameters:** `batch_id`, `protocol`, `search`, `page`, `limit`
- **Response `200 OK`:**
  ```json
  [
    {
      "log_id": "string (UUID)",
      "batch_id": "string (FK to Log_Batch)",
      "timestamp": "string (ISO 8601)",
      "source_address": "string (IP or MAC)",
      "destination_address": "string (IP or MAC)",
      "source_mac": "string (MAC format)",
      "destination_mac": "string (MAC format)",
      "protocol": "802.11_MGMT | 802.11_DATA | TCP | UDP | ARP",
      "log_details": {
        "packet_index": 104,
        "packet_length": 54,
        "link_layer_type": "IEEE 802.11 RadioTap",
        "wireless": {
          "bssid": "string",
          "ssid": "string",
          "frame_type": "string",
          "frame_subtype": "string",
          "channel": 2412,
          "signal_strength": -68
        }
      }
    }
  ]
  ```

---

## 4. Detection Rules & Results Endpoints (`/api/detection`)

### 4.1 Retrieve Deterministic Detection Rules
- **Endpoint:** `GET /api/detection/rules`
- **Current Status:** `Pending Backend Implementation`
- **Entity Alignment:** `Detection_Rule`
- **Response `200 OK`:**
  ```json
  [
    {
      "rule_id": "string",
      "rule_name": "string",
      "description": "string",
      "rule_condition": {
        "frame_type": "Management",
        "frame_subtype": "Deauthentication",
        "threshold": 30,
        "time_window_seconds": 5
      },
      "severity": "CRITICAL | HIGH | MEDIUM | LOW",
      "is_active": true
    }
  ]
  ```

### 4.2 Toggle Rule Operational State
- **Endpoint:** `POST /api/detection/rules/{rule_id}/toggle`
- **Current Status:** `Pending Backend Implementation`
- **Response `200 OK`:** Returns updated `Detection_Rule` entity.

### 4.3 Retrieve Suspicious Detection Results
- **Endpoint:** `GET /api/detection/results`
- **Current Status:** `Pending Backend Implementation`
- **Entity Alignment:** `Detection_Result`
- **Query Parameters:** `is_suspicious` (boolean), `rule_id`, `log_id`
- **Response `200 OK`:**
  ```json
  [
    {
      "result_id": "string (UUID)",
      "log_id": "string (FK to Traffic_Log)",
      "rule_id": "string (FK to Detection_Rule)",
      "detection_timestamp": "string (ISO 8601)",
      "is_suspicious": true,
      "evidence_data": {
        "detected_rate": 42.5,
        "threshold": 30,
        "reason": "Deauthentication threshold exceeded"
      }
    }
  ]
  ```

---

## 5. Security Alerts Endpoints (`/api/alerts`)

### 5.1 Retrieve Security Alerts
- **Endpoint:** `GET /api/alerts`
- **Current Status:** `Pending Backend Implementation`
- **Entity Alignment:** `Alert`
- **Query Parameters:** `severity`, `status`, `page`, `limit`
- **Response `200 OK`:**
  ```json
  [
    {
      "alert_id": "string (UUID)",
      "result_id": "string (FK to Detection_Result)",
      "generated_at": "string (ISO 8601)",
      "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
      "status": "NEW | ACKNOWLEDGED | RESOLVED",
      "alert_type": "string",
      "message": "string"
    }
  ]
  ```

### 5.2 Update Alert Triage Status
- **Endpoint:** `PATCH /api/alerts/{alert_id}/status`
- **Current Status:** `Pending Backend Implementation`
- **Request Body:**
  ```json
  {
    "status": "ACKNOWLEDGED | RESOLVED"
  }
  ```
- **Response `200 OK`:** Returns updated `Alert` entity.

### 5.3 Alert Metrics Summary
- **Endpoint:** `GET /api/alerts/metrics/summary`
- **Current Status:** `Pending Backend Implementation`
- **Response `200 OK`:**
  ```json
  {
    "total_alerts": 12,
    "critical_count": 3,
    "high_count": 4,
    "medium_count": 3,
    "low_count": 2,
    "unresolved_count": 5,
    "severity_distribution": {
      "CRITICAL": 3,
      "HIGH": 4,
      "MEDIUM": 3,
      "LOW": 2
    }
  }
  ```

---

## 6. Stakeholder User Management (`/api/users`)

### 6.1 List Registered Users
- **Endpoint:** `GET /api/users`
- **Current Status:** `Pending Backend Implementation`
- **Entity Alignment:** `User`
- **Access:** Network Administrator only
- **Response `200 OK`:** List of user objects.

### 6.2 Create User
- **Endpoint:** `POST /api/users`
- **Current Status:** `Pending Backend Implementation`
- **Request Body:**
  ```json
  {
    "username": "string",
    "role": "Network Administrator | Security Analyst",
    "full_name": "string",
    "email": "string"
  }
  ```
- **Response `201 Created`:** Newly registered `User` entity.

