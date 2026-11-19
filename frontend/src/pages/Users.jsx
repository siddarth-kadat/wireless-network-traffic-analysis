import React, { useState, useEffect } from 'react';
import {
  Users as UsersIcon,
  UserPlus,
  Trash2,
  RefreshCw,
  Mail,
  UserCheck,
} from 'lucide-react';
import DataTable from '../components/DataTable';
import DetailModal from '../components/DetailModal';
import StatusBadge from '../components/StatusBadge';
import { userService } from '../services/userService';
import { useAuth } from '../context/AuthContext';

export default function Users() {
  const { user: currentUser } = useAuth();
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [formData, setFormData] = useState({
    username: '',
    role: 'Security Analyst',
    full_name: '',
    email: '',
  });
  const [formError, setFormError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const fetchUsers = async () => {
    setLoading(true);
    try {
      const data = await userService.getUsers();
      setUsers(data);
    } catch (err) {
      console.error('Failed to load users:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const handleCreateUser = async (e) => {
    e.preventDefault();
    setFormError('');
    setIsSubmitting(true);
    try {
      const created = await userService.createUser(formData);
      setUsers((prev) => [...prev, created]);
      setIsModalOpen(false);
      setFormData({ username: '', role: 'Security Analyst', full_name: '', email: '' });
    } catch (err) {
      setFormError(err.message || 'Failed to create user account.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDeleteUser = async (userId) => {
    if (userId === currentUser?.user_id) {
      alert('Cannot delete currently active administrator session.');
      return;
    }
    if (window.confirm(`Are you sure you want to deactivate stakeholder ${userId}?`)) {
      await userService.deleteUser(userId);
      setUsers((prev) => prev.filter((u) => u.user_id !== userId));
    }
  };

  const columns = [
    {
      key: 'user_id',
      label: 'STAKEHOLDER ID',
      render: (row) => <span className="text-primary font-bold font-mono">{row.user_id}</span>,
    },
    {
      key: 'full_name',
      label: 'NAME & USERNAME',
      render: (row) => (
        <div className="space-y-0.5">
          <div className="text-secondary font-bold">{row.full_name}</div>
          <div className="text-muted text-xs font-mono">@{row.username}</div>
        </div>
      ),
    },
    {
      key: 'role',
      label: 'AUTHORIZATION ROLE',
      render: (row) => <StatusBadge value={row.role} type="role" size="small" />,
    },
    {
      key: 'email',
      label: 'CONTACT EMAIL',
      render: (row) => (
        <span className="text-muted text-xs flex items-center gap-1.5">
          <Mail className="w-3.5 h-3.5 text-muted" />
          <span>{row.email || '—'}</span>
        </span>
      ),
    },
    {
      key: 'created_at',
      label: 'PROVISIONED ON',
      render: (row) => (
        <span className="text-muted text-xs">
          {new Date(row.created_at).toLocaleDateString()}
        </span>
      ),
    },
    {
      key: 'actions',
      label: 'ACTIONS',
      sortable: false,
      render: (row) => (
        <button
          onClick={() => handleDeleteUser(row.user_id)}
          disabled={row.user_id === currentUser?.user_id}
          className="p-1.5 text-muted hover:text-error hover:bg-error/10 disabled:opacity-20 disabled:cursor-not-allowed rounded-md transition"
          title="Deactivate stakeholder"
        >
          <Trash2 className="w-4 h-4" />
        </button>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="p-6 md:p-8 rounded-md bg-white border border-border flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="text-xs text-primary font-bold uppercase tracking-wider mb-1">
            ACCESS CONTROL // STAKEHOLDER MANAGEMENT
          </div>
          <h1 className="text-3xl font-extrabold tracking-tight text-secondary">
            User Administration &amp; RBAC
          </h1>
          <p className="text-sm text-muted mt-1">
            Manage provisioned accounts for Network Administrators and Security Analysts.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setIsModalOpen(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-md bg-primary hover:bg-primary-hover active:bg-primary text-white font-bold text-xs transition"
          >
            <UserPlus className="w-4 h-4" />
            <span>Add Stakeholder</span>
          </button>
          <button
            onClick={fetchUsers}
            className="flex items-center gap-2 px-4 py-2 rounded-md bg-white hover:bg-subtle border border-border text-secondary font-bold text-xs transition"
          >
            <RefreshCw className={`w-4 h-4 text-muted ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Main Table */}
      <DataTable
        columns={columns}
        data={users}
        loading={loading}
        pageSize={10}
        searchPlaceholder="Filter by Name, Username, Role, or Email..."
      />

      {/* Add User Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-secondary/40 backdrop-blur-xs animate-fadeIn">
          <div className="bg-white border border-border rounded-md shadow-card w-full max-w-md p-6 space-y-4 animate-scaleUp">
            <div className="border-b border-border pb-3 flex items-center justify-between">
              <h3 className="text-base font-extrabold text-secondary">Provision New Stakeholder</h3>
              <button
                onClick={() => setIsModalOpen(false)}
                className="text-muted hover:text-secondary text-sm font-bold"
              >
                ✕
              </button>
            </div>

            {formError && (
              <div className="p-3 rounded-md bg-error/10 border border-error/20 text-xs text-error font-medium">
                {formError}
              </div>
            )}

            <form onSubmit={handleCreateUser} className="space-y-4 text-xs">
              <div>
                <label className="block font-bold text-secondary mb-1">Username</label>
                <input
                  type="text"
                  required
                  value={formData.username}
                  onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                  placeholder="e.g. s_analyst"
                  className="w-full px-3 py-2 border border-border rounded-md focus:outline-none focus:border-primary text-secondary"
                />
              </div>

              <div>
                <label className="block font-bold text-secondary mb-1">Full Name</label>
                <input
                  type="text"
                  required
                  value={formData.full_name}
                  onChange={(e) => setFormData({ ...formData, full_name: e.target.value })}
                  placeholder="e.g. Jordan Hayes"
                  className="w-full px-3 py-2 border border-border rounded-md focus:outline-none focus:border-primary text-secondary"
                />
              </div>

              <div>
                <label className="block font-bold text-secondary mb-1">Corporate Email</label>
                <input
                  type="email"
                  value={formData.email}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                  placeholder="e.g. j.hayes@corp.net"
                  className="w-full px-3 py-2 border border-border rounded-md focus:outline-none focus:border-primary text-secondary"
                />
              </div>

              <div>
                <label className="block font-bold text-secondary mb-1">Assigned Role</label>
                <select
                  value={formData.role}
                  onChange={(e) => setFormData({ ...formData, role: e.target.value })}
                  className="w-full px-3 py-2 border border-border rounded-md focus:outline-none focus:border-primary text-secondary"
                >
                  <option value="Security Analyst">Security Analyst</option>
                  <option value="Network Administrator">Network Administrator</option>
                </select>
              </div>

              <div className="pt-3 border-t border-border flex justify-end gap-2.5">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-4 py-2 border border-border rounded-md text-secondary font-bold hover:bg-subtle"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-5 py-2 bg-primary hover:bg-primary-hover text-white rounded-md font-bold disabled:opacity-40"
                >
                  {isSubmitting ? 'Provisioning...' : 'Create Account'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
