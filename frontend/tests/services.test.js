import { describe, it, expect, beforeEach } from 'vitest';
import { authService } from '../src/services/authService';
import { batchService } from '../src/services/batchService';
import { alertService } from '../src/services/alertService';
import { detectionService } from '../src/services/detectionService';
import { userService } from '../src/services/userService';

describe('Cybersecurity SOC Frontend Services', () => {
  beforeEach(() => {
    sessionStorage.clear();
    batchService.resetState();
    alertService.resetState();
    detectionService.resetState();
    userService.resetState();
  });

  describe('authService', () => {
    it('authenticates Network Administrator correctly', async () => {
      const user = await authService.login('admin', 'admin123');
      expect(user).toBeDefined();
      expect(user.role).toBe('Network Administrator');
      expect(user.username).toBe('admin');
    });

    it('authenticates Security Analyst correctly', async () => {
      const user = await authService.login('analyst', 'analyst123');
      expect(user).toBeDefined();
      expect(user.role).toBe('Security Analyst');
      expect(user.username).toBe('analyst');
    });

    it('rejects invalid credentials', async () => {
      await expect(authService.login('invalid_hacker', 'wrong_pass')).rejects.toThrow();
    });

    it('switches roles smoothly for demonstration', () => {
      const switched = authService.switchRole('Security Analyst');
      expect(switched.role).toBe('Security Analyst');
    });
  });

  describe('batchService', () => {
    it('retrieves baseline log batches', async () => {
      const batches = await batchService.getBatches();
      expect(batches.length).toBeGreaterThan(0);
      expect(batches[0]).toHaveProperty('batch_id');
      expect(batches[0]).toHaveProperty('processing_status');
    });

    it('rejects unsupported file formats', async () => {
      const fakeFile = new File(['dummy content'], 'malicious.exe', { type: 'application/octet-stream' });
      await expect(batchService.uploadBatch(fakeFile, 'usr-admin-01')).rejects.toThrow(/Invalid file format/);
    });

    it('processes valid .pcap captures', async () => {
      const pcapFile = new File(['\xd4\xc3\xb2\xa1' + '0'.repeat(1000)], 'test_capture.pcap', { type: 'application/vnd.tcpdump.pcap' });
      const batch = await batchService.uploadBatch(pcapFile, 'usr-admin-01');
      expect(batch).toBeDefined();
      expect(batch.file_name).toBe('test_capture.pcap');
      expect(batch.file_format).toBe('pcap');
      expect(batch.processing_status).toBe('SUCCESS');
      expect(batch.total_records).toBeGreaterThan(0);
    });
  });

  describe('alertService', () => {
    it('retrieves security alerts matching Alert entity', async () => {
      const alerts = await alertService.getAlerts();
      expect(alerts.length).toBeGreaterThan(0);
      const first = alerts[0];
      expect(first).toHaveProperty('alert_id');
      expect(first).toHaveProperty('severity');
      expect(first).toHaveProperty('status');
      expect(first).toHaveProperty('alert_type');
    });

    it('acknowledges an alert incident', async () => {
      const alerts = await alertService.getAlerts();
      const target = alerts.find((a) => a.status === 'NEW') || alerts[0];
      const updated = await alertService.acknowledgeAlert(target.alert_id);
      expect(updated.status).toBe('ACKNOWLEDGED');
    });

    it('resolves an alert incident', async () => {
      const alerts = await alertService.getAlerts();
      const target = alerts[0];
      const updated = await alertService.resolveAlert(target.alert_id);
      expect(updated.status).toBe('RESOLVED');
    });
  });

  describe('detectionService', () => {
    it('retrieves deterministic detection rules', async () => {
      const rules = await detectionService.getRules();
      expect(rules.length).toBeGreaterThan(0);
      expect(rules[0]).toHaveProperty('rule_condition');
      expect(rules[0]).toHaveProperty('is_active');
    });

    it('toggles rule active state', async () => {
      const rules = await detectionService.getRules();
      const rule = rules[0];
      const originalState = rule.is_active;
      const toggled = await detectionService.toggleRule(rule.rule_id);
      expect(toggled.is_active).toBe(!originalState);
    });
  });

  describe('userService', () => {
    it('retrieves registered stakeholders', async () => {
      const users = await userService.getUsers();
      expect(users.length).toBeGreaterThan(0);
    });

    it('creates a new stakeholder with valid role', async () => {
      const newUser = await userService.createUser({
        username: 'analyst_bob',
        role: 'Security Analyst',
        full_name: 'Bob Analyst',
        email: 'bob@soc.corp',
      });
      expect(newUser).toBeDefined();
      expect(newUser.username).toBe('analyst_bob');
      expect(newUser.role).toBe('Security Analyst');
    });
  });
});

