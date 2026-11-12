import React, { useState, useEffect } from 'react';
import {
  Users as UsersIcon,
  UserPlus,
  ShieldAlert,
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
      label: 'Stakeholder ID',
      render: (row) => <span className="text-cyan-400 font-bold">{row.user_id}</span>,
    },
    {
      key: 'full_name',
      label: 'Stakeholder Name',
      render: (row) => (
        <div className="space-y-0.5">
          <div className="text-white font-medium">{row.full_name || row.username}</div>
          <div className="text-[11px] text-slate-500 font-mono">@{row.username}</div>
        </div>
      ),
    },
    {
      key: 'role',
      label: 'Assigned Stakeholder Role',
      render: (row) => <StatusBadge value={row.role} type="role" size="small" />,
    },
    {
      key: 'email',
      label: 'Contact Email',
      render: (row) => <span className="text-slate-400 text-xs">{row.email || '—'}</span>,
    },
    {
      key: 'actions',
      label: 'Manage',
      sortable: false,
      render: (row) => (
        <button
          onClick={() => handleDeleteUser(row.user_id)}
          disabled={row.user_id === currentUser?.user_id}
          className="p-1.5 rounded hover:bg-rose-950/60 text-slate-500 hover:text-rose-400 disabled:opacity-30 disabled:hover:bg-transparent transition"
          title="Deactivate Stakeholder Account"
        >
          <Trash2 className="w-4 h-4" />
        </button>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            <span>Stakeholder User Management</span>
            <span className="text-xs px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-400 font-mono">
              ADMIN ONLY • USER ENTITY
            </span>
          </h1>
          <p className="text-xs text-slate-400">
            RBAC administration for Network Administrators and Security Analysts matching the approved ER diagram.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchUsers}
            className="p-2 rounded-lg bg-slate-900 border border-slate-700/80 text-slate-300 hover:text-cyan-400 transition"
            title="Refresh Users"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
          <button
            onClick={() => setIsModalOpen(true)}
            className="py-2 px-3.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold flex items-center gap-2 transition"
          >
            <UserPlus className="w-4 h-4" />
            <span>Add Stakeholder</span>
          </button>
        </div>
      </div>

      {/* Main DataTable */}
      <DataTable
        columns={columns}
        data={users}
        loading={loading}
        pageSize={10}
        searchPlaceholder="Search stakeholder by name, username, or role..."
        searchKeys={['user_id', 'username', 'full_name', 'email', 'role']}
      />

      {/* Create Stakeholder Modal */}
      {isModalOpen && (
        <DetailModal
          isOpen={isModalOpen}
          onClose={() => setIsModalOpen(false)}
          title="Register New Stakeholder"
          subtitle="Provision a Network Administrator or Security Analyst account"
          actions={
            <div className="flex items-center gap-3">
              <button
                type="button"
                onClick={() => setIsModalOpen(false)}
                className="py-2 px-4 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleCreateUser}
                disabled={isSubmitting}
                className="py-2 px-4 rounded bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center gap-1.5"
              >
                <UserCheck className="w-4 h-4" />
                <span>Save Stakeholder</span>
              </button>
            </div>
          }
        >
          <form onSubmit={handleCreateUser} className="space-y-4">
            {formError && (
              <div className="p-3 rounded bg-rose-950/60 border border-rose-800 text-xs text-rose-300">
                {formError}
              </div>
            )}

            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                Username Identifier *
              </label>
              <input
                type="text"
                required
                value={formData.username}
                onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                placeholder="e.g. jdoe"
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                Full Legal Name
              </label>
              <input
                type="text"
                value={formData.full_name}
                onChange={(e) => setFormData({ ...formData, full_name: e.target.value })}
                placeholder="e.g. Jane Doe"
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                Stakeholder Email
              </label>
              <input
                type="email"
                value={formData.email}
                onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                placeholder="e.g. jane.doe@soc.corp"
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                Assigned Stakeholder Role *
              </label>
              <select
                value={formData.role}
                onChange={(e) => setFormData({ ...formData, role: e.target.value })}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:border-cyan-500 font-sans"
              >
                <option value="Security Analyst">Security Analyst (Monitoring, Triage, Rules)</option>
                <option value="Network Administrator">Network Administrator (Full Administrative Privileges)</option>
              </select>
            </div>
          </form>
        </DetailModal>
      )}
    </div>
  );
}
