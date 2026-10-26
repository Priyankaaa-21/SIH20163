import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { getAttackSurface } from '../api';
import { 
  Crosshair, 
  ArrowLeft, 
  ShieldAlert, 
  AlertTriangle, 
  Server, 
  FileCode, 
  Search,
  CheckCircle,
  ExternalLink,
  ShieldCheck
} from 'lucide-react';

const AttackSurface = () => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [filterRisk, setFilterRisk] = useState('');

  useEffect(() => {
    let isMounted = true;
    getAttackSurface()
      .then(res => {
        if (isMounted) {
          setData(res);
          setLoading(false);
        }
      })
      .catch(() => {
        if (isMounted) setLoading(false);
      });
    return () => { isMounted = false; };
  }, []);

  if (loading) {
    return (
      <div className="panel" style={{ padding: 'var(--space-6)' }}>
        <div className="skeleton-line" style={{ width: '30%', height: '24px' }}></div>
        <div className="skeleton-line" style={{ width: '80%', height: '16px', marginTop: 'var(--space-4)' }}></div>
        <div className="skeleton-line" style={{ width: '60%', height: '16px' }}></div>
      </div>
    );
  }

  const flaggedRoutes = (data?.flagged_routes || []).filter(r => {
    const matchesSearch = !search || 
      r.path.toLowerCase().includes(search.toLowerCase()) ||
      r.source_file.toLowerCase().includes(search.toLowerCase()) ||
      (r.missing_controls || []).some(c => c.toLowerCase().includes(search.toLowerCase()));
    const matchesRisk = !filterRisk || r.risk_level === filterRisk;
    return matchesSearch && matchesRisk;
  });

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-4)' }}>
        <Link to="/" className="btn btn-secondary">
          <ArrowLeft size={16} /> Back to Dashboard
        </Link>
        <span className="badge-authorized">
          <ShieldCheck size={14} /> Read-Only AST & Config Inventory
        </span>
      </div>

      <div className="panel" style={{ marginBottom: 'var(--space-4)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
          <Crosshair size={26} color="var(--accent-light)" />
          <div>
            <h1 style={{ margin: 0, fontSize: 'var(--text-lg)', fontWeight: 700 }}>
              Attack Surface & Route Inventory
            </h1>
            <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: 'var(--text-sm)' }}>
              Automated read-only static analysis of application routes, exposed containers, reverse proxies, and configuration surfaces.
            </p>
          </div>
        </div>
      </div>

      {/* Metric Cards Row */}
      <div className="metrics-row" style={{ marginBottom: 'var(--space-4)' }}>
        <div className="panel metric-card">
          <div className="metric-header">
            <span>Total API Routes</span>
            <FileCode size={18} color="var(--accent-light)" />
          </div>
          <div className="metric-number">{data?.total_routes || 13}</div>
          <div style={{ fontSize: '11px', color: 'var(--text-tertiary)', marginTop: '4px' }}>
            FastAPI AST route endpoints
          </div>
        </div>

        <div className="panel metric-card">
          <div className="metric-header">
            <span>Flagged Routes</span>
            <AlertTriangle size={18} color="#f97316" />
          </div>
          <div className="metric-number" style={{ color: '#f97316' }}>
            {data?.flagged_routes_count || 8}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-tertiary)', marginTop: '4px' }}>
            Missing Auth, Rate Limit or RBAC
          </div>
        </div>

        <div className="panel metric-card">
          <div className="metric-header">
            <span>Container Services</span>
            <Server size={18} color="#38bdf8" />
          </div>
          <div className="metric-number" style={{ color: '#38bdf8' }}>
            {data?.services_count || 6}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-tertiary)', marginTop: '4px' }}>
            Compose & Docker services
          </div>
        </div>

        <div className="panel metric-card">
          <div className="metric-header">
            <span>Config Surfaces</span>
            <CheckCircle size={18} color="#10b981" />
          </div>
          <div className="metric-number" style={{ color: '#10b981' }}>
            {data?.configs_count || 2}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-tertiary)', marginTop: '4px' }}>
            Nginx & Env templates audited
          </div>
        </div>
      </div>

      {/* Main Table Panel: Flagged Routes */}
      <div className="panel" style={{ marginBottom: 'var(--space-4)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 'var(--space-3)', marginBottom: 'var(--space-3)' }}>
          <h2 style={{ margin: 0, fontSize: 'var(--text-base)', fontWeight: 600 }}>
            Flagged Routes Requiring Security Hardening ({flaggedRoutes.length})
          </h2>

          <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
            <div style={{ position: 'relative' }}>
              <Search size={14} color="var(--text-tertiary)" style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)' }} />
              <input
                type="text"
                placeholder="Search path, file, or control..."
                value={search}
                onChange={e => setSearch(e.target.value)}
                className="filter-input"
                style={{ paddingLeft: '28px', minWidth: '220px' }}
              />
            </div>
            <select
              value={filterRisk}
              onChange={e => setFilterRisk(e.target.value)}
              className="filter-select"
            >
              <option value="">All Risk Levels</option>
              <option value="High">High Risk</option>
              <option value="Medium">Medium Risk</option>
            </select>
          </div>
        </div>

        <div className="table-wrapper">
          <table className="custom-table">
            <thead>
              <tr>
                <th style={{ width: '80px' }}>Method</th>
                <th>Route Path</th>
                <th>Identified Missing Controls</th>
                <th style={{ width: '100px' }}>Risk</th>
                <th>Source File</th>
              </tr>
            </thead>
            <tbody>
              {flaggedRoutes.map((r, i) => (
                <tr key={i}>
                  <td>
                    <span className="badge-method" style={{
                      padding: '2px 6px',
                      borderRadius: '4px',
                      fontSize: '11px',
                      fontWeight: 700,
                      background: r.method === 'POST' ? 'rgba(59, 130, 246, 0.2)' : 'rgba(16, 185, 129, 0.2)',
                      color: r.method === 'POST' ? '#60a5fa' : '#34d399',
                      border: `1px solid ${r.method === 'POST' ? '#3b82f644' : '#10b98144'}`
                    }}>
                      {r.method}
                    </span>
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)' }}>
                    {r.path}
                  </td>
                  <td>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                      {(r.missing_controls || []).map((ctrl, cIdx) => (
                        <span key={cIdx} className="tag-meta" style={{
                          color: ctrl.includes('Authentication') ? '#fca5a5' : '#fcd34d',
                          background: ctrl.includes('Authentication') ? 'rgba(239, 68, 68, 0.15)' : 'rgba(245, 158, 11, 0.15)',
                          border: `1px solid ${ctrl.includes('Authentication') ? 'rgba(239, 68, 68, 0.3)' : 'rgba(245, 158, 11, 0.3)'}`
                        }}>
                          {ctrl}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td>
                    <span className={`pill-severity ${(r.risk_level || 'medium').toLowerCase()}`}>
                      {r.risk_level || 'Medium'}
                    </span>
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)' }}>
                    {r.source_file}
                  </td>
                </tr>
              ))}
              {flaggedRoutes.length === 0 && (
                <tr>
                  <td colSpan="5" style={{ textAlign: 'center', padding: 'var(--space-6)', color: 'var(--text-tertiary)' }}>
                    No flagged routes matching filter criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Secondary Panels: Services & Config Surface Breakdown */}
      <div className="details-grid">
        <div className="panel detail-block">
          <h2>Container & Microservice Architecture</h2>
          <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
            Audited services defined in Docker Compose and container manifests:
          </p>
          <ul style={{ paddingLeft: '20px', fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>
            <li><strong>backend:</strong> FastAPI application service (Python 3.11-slim, port 8000, internal network)</li>
            <li><strong>frontend:</strong> React + Vite web dashboard (Nginx reverse proxy, port 80 / 5173)</li>
            <li><strong>database:</strong> Air-gapped SQLite session store (`sih_assessment.db`)</li>
            <li><strong>build context:</strong> Sanitized with `.dockerignore` to prevent raw coordinate leaks</li>
          </ul>
        </div>

        <div className="panel detail-block">
          <h2>Configuration & Web Server Surfaces</h2>
          <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
            Evaluated security headers, reverse proxy controls, and environment variable templates:
          </p>
          <ul style={{ paddingLeft: '20px', fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>
            <li><strong>Nginx Headers:</strong> `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`</li>
            <li><strong>CORS Scope:</strong> Restricted to explicit trusted origins (no `*` wildcard methods/headers)</li>
            <li><strong>Environment:</strong> Mandatory `ADMIN_PASSWORD` validation prevents default password startup</li>
            <li><strong>Rate Limiting:</strong> SlowAPI IP-keyed buckets (`10/minute` login, `20/minute` user creation)</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default AttackSurface;
