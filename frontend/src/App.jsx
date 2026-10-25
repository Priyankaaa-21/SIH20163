import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, Navigate, useLocation } from 'react-router-dom';
import Dashboard from './components/Dashboard';
import VulnerabilityDetails from './components/VulnerabilityDetails';
import AuditLog from './components/AuditLog';
import Login from './components/Login';
import { Shield, LogOut, User } from 'lucide-react';
import './index.css';

function NavigationHeader({ handleLogout, userRole, username }) {
  const location = useLocation();

  return (
    <header className="app-header">
      <Link to="/" className="app-brand">
        <Shield size={24} color="var(--accent-light)" />
        <h1>World Monitor Security Assessment</h1>
      </Link>

      <div className="app-nav">
        <Link 
          to="/" 
          className={`nav-link ${location.pathname === '/' ? 'active' : ''}`}
        >
          Dashboard
        </Link>

        {userRole === 'admin' && (
          <Link 
            to="/audit" 
            className={`nav-link ${location.pathname === '/audit' ? 'active' : ''}`}
          >
            Audit Log
          </Link>
        )}

        <div className="user-chip">
          <User size={14} />
          <span>{username || 'operator'} (<strong>{userRole || 'user'}</strong>)</span>
        </div>

        <button 
          onClick={handleLogout} 
          className="btn btn-secondary" 
          style={{ minHeight: '32px', padding: '4px 10px' }}
          title="Sign out of security assessment platform"
        >
          <LogOut size={14} /> Logout
        </button>
      </div>
    </header>
  );
}

function App() {
  const [authenticated, setAuthenticated] = useState(!!localStorage.getItem('token'));
  const [userRole, setUserRole] = useState(localStorage.getItem('role') || 'user');
  const [username, setUsername] = useState(localStorage.getItem('username') || 'admin');

  useEffect(() => {
    const handleStorageChange = () => {
      setAuthenticated(!!localStorage.getItem('token'));
      setUserRole(localStorage.getItem('role') || 'user');
      setUsername(localStorage.getItem('username') || 'admin');
    };

    window.addEventListener('auth:logout', handleStorageChange);
    return () => {
      window.removeEventListener('auth:logout', handleStorageChange);
    };
  }, []);

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    localStorage.removeItem('role');
    setAuthenticated(false);
  };

  const handleLoginSuccess = () => {
    setAuthenticated(true);
    setUserRole(localStorage.getItem('role') || 'user');
    setUsername(localStorage.getItem('username') || 'admin');
  };

  if (!authenticated) {
    return <Login setAuthenticated={handleLoginSuccess} />;
  }

  return (
    <Router>
      <div className="app-layout">
        <NavigationHeader 
          handleLogout={handleLogout} 
          userRole={userRole} 
          username={username} 
        />
        
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/finding/:id" element={<VulnerabilityDetails />} />
          <Route 
            path="/audit" 
            element={userRole === 'admin' ? <AuditLog /> : <Navigate to="/" replace />} 
          />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
