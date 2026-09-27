import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, Navigate } from 'react-router-dom';
import Dashboard from './components/Dashboard';
import VulnerabilityDetails from './components/VulnerabilityDetails';
import Login from './components/Login';
import { Shield, LogOut } from 'lucide-react';
import './index.css';

function App() {
  const [authenticated, setAuthenticated] = useState(!!localStorage.getItem('token'));

  const handleLogout = () => {
    localStorage.removeItem('token');
    setAuthenticated(false);
  };

  if (!authenticated) {
    return <Login setAuthenticated={setAuthenticated} />;
  }

  return (
    <Router>
      <div className="app-container">
        <header className="header">
          <Link to="/" style={{ display: 'flex', alignItems: 'center', gap: '1rem', textDecoration: 'none' }}>
            <Shield size={32} color="#60a5fa" />
            <h1>World Monitor Security Assessment</h1>
          </Link>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <div className="badge" style={{ background: 'rgba(59, 130, 246, 0.2)', color: '#60a5fa' }}>
              SIH 26163 - NTRO
            </div>
            <button onClick={handleLogout} style={{ background: 'transparent', border: '1px solid #475569', color: '#cbd5e1', padding: '0.5rem', borderRadius: '4px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <LogOut size={16} /> Logout
            </button>
          </div>
        </header>
        
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/finding/:id" element={<VulnerabilityDetails />} />
          <Route path="*" element={<Navigate to="/" />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
