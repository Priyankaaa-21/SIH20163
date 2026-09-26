import React from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import Dashboard from './components/Dashboard';
import VulnerabilityDetails from './components/VulnerabilityDetails';
import { Shield } from 'lucide-react';
import './index.css';

function App() {
  return (
    <Router>
      <div className="app-container">
        <header className="header">
          <Link to="/" style={{ display: 'flex', alignItems: 'center', gap: '1rem', textDecoration: 'none' }}>
            <Shield size={32} color="#60a5fa" />
            <h1>World Monitor Security Assessment</h1>
          </Link>
          <div className="badge" style={{ background: 'rgba(59, 130, 246, 0.2)', color: '#60a5fa' }}>
            SIH 26163 - NTRO
          </div>
        </header>
        
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/finding/:id" element={<VulnerabilityDetails />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
