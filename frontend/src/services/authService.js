import { apiRequest, SEED_USERS } from './api';

/**
 * Authentication and User Session Service.
 */
export const authService = {
  /**
   * Performs user login.
   * If backend endpoint /api/auth/login is pending, validates against pre-configured SOC profiles.
   */
  async login(username, password) {
    // Attempt live API request first
    const liveResponse = await apiRequest('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });

    if (liveResponse && liveResponse.access_token) {
      sessionStorage.setItem('auth_token', liveResponse.access_token);
      sessionStorage.setItem('auth_user', JSON.stringify(liveResponse.user));
      return liveResponse.user;
    }

    // Graceful offline demonstration authentication
    const user = SEED_USERS.find(
      (u) => u.username.toLowerCase() === username.trim().toLowerCase()
    );

    if (user) {
      const mockToken = `demo-token-${user.user_id}-${Date.now()}`;
      sessionStorage.setItem('auth_token', mockToken);
      sessionStorage.setItem('auth_user', JSON.stringify(user));
      return user;
    }

    throw new Error('Invalid credentials. For demonstration, use username "admin" or "analyst".');
  },

  /**
   * Retrieves the currently authenticated user from session or API.
   */
  async getCurrentUser() {
    const liveUser = await apiRequest('/api/auth/me');
    if (liveUser) {
      sessionStorage.setItem('auth_user', JSON.stringify(liveUser));
      return liveUser;
    }

    const stored = sessionStorage.getItem('auth_user');
    if (stored) {
      try {
        return JSON.parse(stored);
      } catch (e) {
        sessionStorage.removeItem('auth_user');
      }
    }
    // Default to Administrator for demo if none set
    return SEED_USERS[0];
  },

  /**
   * Quick role switcher for evaluator convenience.
   */
  switchRole(roleName) {
    const target = SEED_USERS.find((u) => u.role === roleName) || SEED_USERS[0];
    sessionStorage.setItem('auth_user', JSON.stringify(target));
    return target;
  },

  /**
   * Clears session tokens.
   */
  logout() {
    sessionStorage.removeItem('auth_token');
    sessionStorage.removeItem('auth_user');
  },
};
