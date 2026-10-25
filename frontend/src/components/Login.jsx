import React, { useState } from 'react';
import { Shield, Lock, User, AlertCircle } from 'lucide-react';
import { login } from '../api';

const Login = ({ setAuthenticated }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleLogin = async (e) => {
    e.preventDefault();
    if (!username || !password) {
      setError('Please provide both username and password.');
      return;
    }
    setError('');
    setIsLoading(true);
    try {
      await login(username, password);
      setAuthenticated(true);
    } catch (err) {
      const detail = err.response?.data?.detail || err.message || 'Invalid username or password';
      setError(detail);
      setIsLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', padding: 'var(--space-4)' }}>
      <div className="panel" style={{ width: '100%', maxWidth: '400px', padding: 'var(--space-8)' }}>
        <div style={{ textAlign: 'center', marginBottom: 'var(--space-6)' }}>
          <div style={{ display: 'inline-flex', padding: 'var(--space-3)', background: 'var(--accent-subtle)', borderRadius: 'var(--radius)', marginBottom: 'var(--space-3)' }}>
            <Shield size={32} color="var(--accent-light)" />
          </div>
          <h1 style={{ margin: '0 0 var(--space-1) 0', fontSize: 'var(--text-lg)', fontWeight: '700' }}>
            World Monitor
          </h1>
          <div style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-sm)' }}>
            Security Assessment Platform
          </div>
        </div>

        {error && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', background: 'rgba(239, 68, 68, 0.15)', border: '1px solid rgba(239, 68, 68, 0.3)', color: '#fca5a5', padding: 'var(--space-3)', borderRadius: 'var(--radius)', fontSize: 'var(--text-sm)', marginBottom: 'var(--space-4)' }}>
            <AlertCircle size={16} />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          <div>
            <label htmlFor="username-input" style={{ display: 'block', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', marginBottom: 'var(--space-1)' }}>
              Username
            </label>
            <div style={{ position: 'relative' }}>
              <User size={16} color="var(--text-tertiary)" style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)' }} />
              <input
                id="username-input"
                type="text"
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter username"
                className="filter-input"
                style={{ width: '100%', paddingLeft: '36px' }}
                required
              />
            </div>
          </div>

          <div>
            <label htmlFor="password-input" style={{ display: 'block', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', marginBottom: 'var(--space-1)' }}>
              Password
            </label>
            <div style={{ position: 'relative' }}>
              <Lock size={16} color="var(--text-tertiary)" style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)' }} />
              <input
                id="password-input"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter password"
                className="filter-input"
                style={{ width: '100%', paddingLeft: '36px' }}
                required
              />
            </div>
          </div>

          <button
            type="submit"
            className="btn"
            style={{ width: '100%', justifyContent: 'center', marginTop: 'var(--space-2)' }}
            disabled={isLoading}
          >
            {isLoading ? 'Authenticating...' : 'Sign In'}
          </button>
        </form>

        <div style={{ marginTop: 'var(--space-6)', padding: 'var(--space-3)', background: 'var(--bg-subtle)', border: '1px solid var(--border-panel)', borderRadius: 'var(--radius)', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', textAlign: 'left' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-2)' }}>
            <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>Access Credentials:</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <button
                type="button"
                id="autofill-admin123-btn"
                onClick={() => {
                  setUsername('admin');
                  setPassword('admin123');
                }}
                style={{ background: 'transparent', border: 'none', color: 'var(--accent-light)', cursor: 'pointer', fontSize: 'var(--text-sm)', textDecoration: 'underline', padding: 0 }}
              >
                Autofill (admin123)
              </button>
              <span style={{ color: 'var(--text-tertiary)' }}>•</span>
              <button
                type="button"
                id="autofill-secure-btn"
                onClick={() => {
                  setUsername('admin');
                  setPassword('SecureAdminPassword2026!');
                }}
                style={{ background: 'transparent', border: 'none', color: 'var(--accent-light)', cursor: 'pointer', fontSize: 'var(--text-sm)', textDecoration: 'underline', padding: 0 }}
              >
                Autofill (New)
              </button>
            </div>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', fontFamily: 'var(--font-mono)' }}>
            <div>Username: <strong style={{ color: 'var(--accent-light)' }}>admin</strong></div>
            <div>Password: <strong style={{ color: 'var(--accent-light)' }}>admin123</strong> <span style={{ color: 'var(--text-tertiary)' }}>(or SecureAdminPassword2026!)</span></div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;
