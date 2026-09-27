import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { getFindings } from '../api';
import { ShieldAlert, CheckCircle, Search, AlertTriangle, Eye } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import MapWidget from './MapWidget';

const severityColors = {
  High: '#f97316',
  Medium: '#eab308',
  Critical: '#ef4444',
  Low: '#22c55e'
};

const Dashboard = () => {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getFindings().then(data => {
      setFindings(data);
      setLoading(false);
    });
  }, []);

  if (loading) return <div style={{ textAlign: 'center', padding: '4rem' }}>Loading findings...</div>;

  const getSeverityBadge = (severity) => {
    const s = severity.toLowerCase();
    return <span className={`badge ${s}`}>{severity}</span>;
  };

  const chartData = [
    { name: 'Critical', value: findings.filter(f => f.severity === 'Critical').length },
    { name: 'High', value: findings.filter(f => f.severity === 'High').length },
    { name: 'Medium', value: findings.filter(f => f.severity === 'Medium').length },
    { name: 'Low', value: findings.filter(f => f.severity === 'Low').length }
  ];

  return (
    <div>
      <div className="grid-metrics">
        <div className="glass-panel metric-card">
          <ShieldAlert color="#fca5a5" size={24} style={{ marginBottom: '1rem' }} />
          <div className="metric-title">Total Findings</div>
          <div className="metric-value">{findings.length}</div>
        </div>
        <div className="glass-panel metric-card">
          <AlertTriangle color="#fcd34d" size={24} style={{ marginBottom: '1rem' }} />
          <div className="metric-title">High & Critical</div>
          <div className="metric-value">{findings.filter(f => ['High', 'Critical'].includes(f.severity)).length}</div>
        </div>
        <div className="glass-panel metric-card">
          <CheckCircle color="#86efac" size={24} style={{ marginBottom: '1rem' }} />
          <div className="metric-title">Needs Validation</div>
          <div className="metric-value">{findings.filter(f => f.status === 'Needs Validation' || f.status === 'Potential').length}</div>
        </div>
        <div className="glass-panel metric-card">
          <Search color="#60a5fa" size={24} style={{ marginBottom: '1rem' }} />
          <div className="metric-title">Confirmed</div>
          <div className="metric-value">{findings.filter(f => f.status === 'Confirmed').length}</div>
        </div>
      </div>

      <MapWidget />

      <div className="grid-charts">
        <div className="glass-panel">
          <h3 style={{ marginTop: 0, marginBottom: '1.5rem', color: 'var(--text-muted)' }}>Vulnerabilities List</h3>
          <table>
            <thead>
              <tr>
                <th>Title</th>
                <th>Category</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {findings.map(finding => (
                <tr key={finding.id}>
                  <td style={{ fontWeight: 500 }}>{finding.title}</td>
                  <td>{finding.category}</td>
                  <td>{getSeverityBadge(finding.severity)}</td>
                  <td>{finding.status}</td>
                  <td>
                    <Link to={`/finding/${finding.id}`}>
                      <button className="btn" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <Eye size={16} /> View Evidence
                      </button>
                    </Link>
                  </td>
                </tr>
              ))}
              {findings.length === 0 && (
                <tr>
                  <td colSpan="5" style={{ textAlign: 'center', color: 'var(--text-muted)' }}>
                    No findings detected. Run the scanner backend.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        
        <div className="glass-panel">
          <h3 style={{ marginTop: 0, marginBottom: '1.5rem', color: 'var(--text-muted)' }}>Severity Distribution</h3>
          <div style={{ height: '300px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData}>
                <XAxis dataKey="name" stroke="var(--text-muted)" />
                <YAxis stroke="var(--text-muted)" allowDecimals={false} />
                <Tooltip cursor={{ fill: 'rgba(255,255,255,0.05)' }} contentStyle={{ backgroundColor: '#1e293b', border: 'none', borderRadius: '8px' }} />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {chartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={severityColors[entry.name]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
