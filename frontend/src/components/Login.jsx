import React, { useState } from 'react';
import { Shield, Lock, User } from 'lucide-react';
import { login } from '../api';

const Login = ({ setAuthenticated }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleLogin = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      const response = await login(username, password);
      localStorage.setItem('token', response.access_token);
      setAuthenticated(true);
    } catch (err) {
      setError('Invalid username or password');
      setIsLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', padding: '1rem' }}>
      <div className="glass-panel" style={{ width: '100%', maxWidth: '420px', padding: '3rem 2rem', textAlign: 'center' }}>
        <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '1.5rem' }}>
          <div style={{ background: 'rgba(59, 130, 246, 0.1)', padding: '1rem', borderRadius: '50%', boxShadow: 'var(--shadow-glow)' }}>
            <Shield size={48} color="#60a5fa" />
          </div>
        </div>
        
        <h1 style={{ margin: '0 0 0.5rem 0', fontSize: '1.75rem', fontWeight: '700', background: 'linear-gradient(135deg, #f3f4f6 0%, #9ca3af 100%)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
          World Monitor
        </h1>
        <p style={{ color: 'var(--text-muted)', margin: '0 0 2.5rem 0' }}>Security Assessment Platform</p>
        
        <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {error && (
            <div style={{ background: 'rgba(239, 68, 68, 0.15)', border: '1px solid rgba(239, 68, 68, 0.3)', color: '#fca5a5', padding: '0.75rem', borderRadius: '8px', fontSize: '0.875rem' }}>
              {error}
            </div>
          )}
          
          <div style={{ position: 'relative' }}>
            <User size={20} color="var(--text-muted)" style={{ position: 'absolute', left: '1rem', top: '50%', transform: 'translateY(-50%)' }} />
            <input 
              type="text" 
              placeholder="Username"
              value={username} 
              onChange={(e) => setUsername(e.target.value)} 
              style={{ boxSizing: 'border-box', width: '100%', padding: '0.875rem 1rem 0.875rem 3rem', borderRadius: '8px', border: '1px solid var(--border-color)', background: 'rgba(0,0,0,0.2)', color: 'white', fontSize: '1rem', outline: 'none', transition: 'border-color 0.2s, box-shadow 0.2s' }}
              onFocus={(e) => { e.target.style.borderColor = '#3b82f6'; e.target.style.boxShadow = '0 0 0 2px rgba(59,130,246,0.2)'; }}
              onBlur={(e) => { e.target.style.borderColor = 'var(--border-color)'; e.target.style.boxShadow = 'none'; }}
            />
          </div>
          
          <div style={{ position: 'relative' }}>
            <Lock size={20} color="var(--text-muted)" style={{ position: 'absolute', left: '1rem', top: '50%', transform: 'translateY(-50%)' }} />
            <input 
              type="password" 
              placeholder="Password"
              value={password} 
              onChange={(e) => setPassword(e.target.value)} 
              style={{ boxSizing: 'border-box', width: '100%', padding: '0.875rem 1rem 0.875rem 3rem', borderRadius: '8px', border: '1px solid var(--border-color)', background: 'rgba(0,0,0,0.2)', color: 'white', fontSize: '1rem', outline: 'none', transition: 'border-color 0.2s, box-shadow 0.2s' }}
              onFocus={(e) => { e.target.style.borderColor = '#3b82f6'; e.target.style.boxShadow = '0 0 0 2px rgba(59,130,246,0.2)'; }}
              onBlur={(e) => { e.target.style.borderColor = 'var(--border-color)'; e.target.style.boxShadow = 'none'; }}
            />
          </div>
          
          <button type="submit" className="btn" style={{ width: '100%', justifyContent: 'center', marginTop: '0.5rem', padding: '0.875rem' }} disabled={isLoading}>
            {isLoading ? 'Authenticating...' : 'Sign In securely'}
          </button>
        </form>
        
        <div style={{ marginTop: '2rem', color: '#64748b', fontSize: '0.875rem' }}>
          Demo Credentials: <b>admin</b> / <b>admin123</b>
        </div>
      </div>
    </div>
  );
};

export default Login;
