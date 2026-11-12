"""SQLAlchemy ORM models representing the 7 approved database entities.

Entities:
1. User: Stores user account details and credentials.
2. Log_Batch: Metadata for uploaded network traffic log batches.
3. Traffic_Log: Individual processed wireless network traffic records.
4. Detection_Rule: Predefined detection rules and anomaly thresholds.
5. Detection_Result: Evaluation results of traffic logs against rules.
6. Alert: Security alerts generated from suspicious detection results.
7. Processing_Error: Errors during ingestion, parsing, and processing.
"""


class User:
    """User entity.

    Attributes:
        user_id: Primary Key
        username: Unique username
        password_hash: Securely hashed password
        role: Network Administrator or Security Analyst
    """
    pass


class Log_Batch:
    """Log_Batch entity.

    Attributes:
        batch_id: Primary Key
        user_id: Foreign Key -> User.user_id
        file_name: Name of uploaded file
        file_format: CSV, JSON, etc.
        submitted_at: Submission timestamp
        processing_status: Status of batch processing
        total_records: Total records count
        processed_records: Successfully processed records count
        failed_records: Failed records count
    """
    pass


class Traffic_Log:
    """Traffic_Log entity.

    Attributes:
        log_id: Primary Key
        batch_id: Foreign Key -> Log_Batch.batch_id
        timestamp: Packet / event timestamp
        source_address: Source IP address
        destination_address: Destination IP address
        source_mac: Source MAC address
        destination_mac: Destination MAC address
        protocol: Network protocol
        log_details: Structured packet/event payload details
    """
    pass


class Detection_Rule:
    """Detection_Rule entity.

    Attributes:
        rule_id: Primary Key
        rule_name: Name of the detection rule
        suspicious_activity: Category of suspicious behavior
        protocol: Target protocol
        detection_condition: Deterministic condition expression
        threshold_value: Value threshold for trigger
        time_window_seconds: Observation time window in seconds
        severity: Severity rating
        is_enabled: Boolean flag indicating rule activation
    """
    pass


class Detection_Result:
    """Detection_Result entity.

    Attributes:
        result_id: Primary Key
        log_id: Foreign Key -> Traffic_Log.log_id
        rule_id: Foreign Key -> Detection_Rule.rule_id
        rule_match_status: True/False rule match
        observed_value: Measured metric value
        threshold_value: Expected rule threshold
        detection_evidence: Structured evidence summary
        detection_time: Evaluation timestamp
    """
    pass


class Alert:
    """Alert entity.

    Attributes:
        alert_id: Primary Key
        result_id: Foreign Key -> Detection_Result.result_id
        alert_details: Context and alert description
        alert_timestamp: Generation timestamp
        severity: Low, Medium, High, Critical
        alert_status: New, Acknowledged, Resolved
    """
    pass


class Processing_Error:
    """Processing_Error entity.

    Attributes:
        error_id: Primary Key
        batch_id: Foreign Key -> Log_Batch.batch_id
        log_id: Foreign Key -> Traffic_Log.log_id (nullable)
        error_type: Classification of processing failure
        error_message: Detailed diagnostic message
        error_timestamp: Error timestamp
    """
    pass
