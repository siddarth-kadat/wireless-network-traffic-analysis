/**
 * User Service
 * 
 * Manages user accounts and roles for Network Administrators.
 * Interacts with backend /api/users endpoints, with fallback to local seed data.
 */
import { apiRequest, SEED_USERS } from './api';

let localUsers = [...SEED_USERS];

export const userService = {
  /**
   * Retrieve list of registered users
   */
  async getUsers() {
    const live = await apiRequest('/api/users');
    if (live && Array.isArray(live)) return live;
    return [...localUsers];
  },

  /**
   * Create a new user account (Admin only)
   */
  async createUser(userData) {
    if (!userData.username || !userData.role) {
      throw new Error('Username and role are required fields.');
    }

    const live = await apiRequest('/api/users', {
      method: 'POST',
      body: JSON.stringify(userData),
    });
    if (live && live.user_id) {
      localUsers.push(live);
      return live;
    }

    // High fidelity fallback user matching User entity
    const newUser = {
      user_id: `usr-${Math.random().toString(16).substring(2, 8)}`,
      username: userData.username.trim(),
      role: userData.role,
      full_name: userData.full_name || userData.username,
      email: userData.email || `${userData.username}@soc.corp`,
      created_at: new Date().toISOString(),
    };

    localUsers.push(newUser);
    return newUser;
  },

  /**
   * Delete or deactivate a user
   */
  async deleteUser(userId) {
    await apiRequest(`/api/users/${userId}`, { method: 'DELETE' });
    localUsers = localUsers.filter((u) => u.user_id !== userId);
    return true;
  },

  /**
   * Reset local state to seed
   */
  resetState() {
    localUsers = [...SEED_USERS];
  },
};
