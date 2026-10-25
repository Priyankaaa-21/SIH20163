import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { getAuditLogs } from '../api';
import { ShieldCheck, ArrowLeft, RefreshCw, AlertCircle } from 'lucide-react';

const AuditLog = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchLogs = () => {
    setLoading(true);
    setError(null);
    getAuditLogs()
      .then(data => {
        setLogs(Array.isArray(data) ? data : []);
        setLoading(false);
      })
      .catch(err => {
        setError(err.response?.data?.detail || 'Failed to retrieve audit log entries. Admin authorization required.');
        setLoading(false);
      });
  };

  useEffect(() => {
    let isMounted = true;
    getAuditLogs()
      .then(data => {
        if (isMounted) {
          setLogs(Array.isArray(data) ? data : []);
          setLoading(false);
        }
      })
      .catch(err => {
        if (isMounted) {
          setError(err.response?.data?.detail || 'Failed to retrieve audit log entries. Admin authorization required.');
          setLoading(false);
        }
      });
    return () => { isMounted = false; };
  }, []);

  const getActionBadge = (action) => {
    if (action.includes('SUCCESS') || action.includes('CREATED')) {
      return <span className="pill-status remediated">{action}</span>;
    }
    if (action.includes('FAIL') || action.includes('LOCKED')) {
      return <span className="pill-status confirmed">{action}</span>;
    }
    return <span className="pill-status">{action}</span>;
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-4)' }}>
        <Link to="/" className="btn btn-secondary">
          <ArrowLeft size={16} /> Back to Dashboard
        </Link>
        <button onClick={fetchLogs} className="btn btn-secondary" disabled={loading}>
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Refresh Logs
        </button>
      </div>

      <div className="panel table-card">
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-4)' }}>
          <ShieldCheck size={20} color="var(--accent-light)" />
          <h2 style={{ margin: 0, fontSize: 'var(--text-base)', fontWeight: 600 }}>
            Security Audit Trail (Admin Restricted)
          </h2>
        </div>

        {loading && (
          <div style={{ padding: 'var(--space-6)' }}>
            <div className="skeleton-line" style={{ width: '100%' }}></div>
            <div className="skeleton-line" style={{ width: '90%' }}></div>
            <div className="skeleton-line" style={{ width: '95%' }}></div>
          </div>
        )}

        {error && (
          <div className="state-box" style={{ color: '#fca5a5' }}>
            <AlertCircle size={24} />
            <div>{error}</div>
            <button onClick={fetchLogs} className="btn btn-secondary">Retry</button>
          </div>
        )}

        {!loading && !error && (
          <div className="table-responsive">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Action</th>
                  <th>User</th>
                  <th>IP Address</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log) => (
                  <tr key={log.id}>
                    <td style={{ whiteSpace: 'nowrap', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td>{getActionBadge(log.action)}</td>
                    <td style={{ fontWeight: 500 }}>{log.username || 'System'}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-tertiary)' }}>
                      {log.ip_address || '127.0.0.1'}
                    </td>
                    <td style={{ color: 'var(--text-secondary)' }}>{log.details}</td>
                  </tr>
                ))}
                {logs.length === 0 && (
                  <tr>
                    <td colSpan="5" style={{ textAlign: 'center', padding: 'var(--space-8)', color: 'var(--text-tertiary)' }}>
                      No audit events recorded yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default AuditLog;
