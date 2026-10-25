import React, { useEffect, useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { getFindings } from '../api';
import { 
  ShieldAlert, 
  CheckCircle, 
  Search, 
  AlertTriangle, 
  ArrowUpDown, 
  Download, 
  Printer, 
  RotateCcw, 
  ChevronLeft, 
  ChevronRight,
  AlertCircle
} from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import MapWidget from './MapWidget';

const severityColors = {
  Critical: '#ef4444',
  High: '#f97316',
  Medium: '#eab308',
  Low: '#10b981',
  Informational: '#3b82f6'
};

const Dashboard = () => {
  const navigate = useNavigate();
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filter & Query States
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [sortField, setSortField] = useState('id');
  const [sortOrder, setSortOrder] = useState('asc');

  // Pagination
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 10;

  const fetchFindingsData = React.useCallback(() => {
    getFindings({
      q: searchQuery || undefined,
      severity: severityFilter || undefined,
      status: statusFilter || undefined,
      category: categoryFilter || undefined,
      sort: sortField,
      order: sortOrder,
      limit: 200
    })
      .then(data => {
        setFindings(Array.isArray(data) ? data : []);
        setLoading(false);
        setCurrentPage(1);
      })
      .catch(err => {
        setError(err.response?.data?.detail || 'Failed to fetch security findings from API.');
        setLoading(false);
      });
  }, [searchQuery, severityFilter, statusFilter, categoryFilter, sortField, sortOrder]);

  useEffect(() => {
    let isMounted = true;
    getFindings({
      q: searchQuery || undefined,
      severity: severityFilter || undefined,
      status: statusFilter || undefined,
      category: categoryFilter || undefined,
      sort: sortField,
      order: sortOrder,
      limit: 200
    })
      .then(data => {
        if (isMounted) {
          setFindings(Array.isArray(data) ? data : []);
          setLoading(false);
          setCurrentPage(1);
        }
      })
      .catch(err => {
        if (isMounted) {
          setError(err.response?.data?.detail || 'Failed to fetch security findings from API.');
          setLoading(false);
        }
      });
    return () => { isMounted = false; };
  }, [searchQuery, severityFilter, statusFilter, categoryFilter, sortField, sortOrder]);

  // Handle Search on Enter or debounce
  const handleSearchKeyDown = (e) => {
    if (e.key === 'Enter') {
      fetchFindingsData();
    }
  };

  const handleResetFilters = () => {
    setSearchQuery('');
    setSeverityFilter('');
    setStatusFilter('');
    setCategoryFilter('');
    setSortField('id');
    setSortOrder('asc');
    getFindings({ limit: 200 })
      .then(data => {
        setFindings(Array.isArray(data) ? data : []);
        setLoading(false);
        setCurrentPage(1);
      })
      .catch(() => setError('Failed to reset findings.'));
  };

  const handleSort = (field) => {
    if (sortField === field) {
      setSortOrder(prev => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortOrder('asc');
    }
  };

  const handleExportJSON = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(findings, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `world_monitor_findings_${new Date().toISOString().split('T')[0]}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const handleExportPDF = () => {
    window.print();
  };

  // Metric Computations
  const totalCount = findings.length;
  const highCriticalCount = findings.filter(f => ['High', 'Critical'].includes(f.severity)).length;
  const remediatedCount = findings.filter(f => f.status === 'Remediated').length;
  const openCount = totalCount - remediatedCount;
  const remediationPercentage = totalCount > 0 ? Math.round((remediatedCount / totalCount) * 100) : 0;

  // Chart Data for Donut Chart
  const chartData = useMemo(() => {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    findings.forEach(f => {
      if (counts[f.severity] !== undefined) {
        counts[f.severity]++;
      }
    });
    return Object.entries(counts)
      .map(([name, value]) => ({ name, value }))
      .filter(item => item.value > 0);
  }, [findings]);

  // Dynamic Categories for Dropdown
  const uniqueCategories = useMemo(() => {
    const cats = new Set(findings.map(f => f.category).filter(Boolean));
    return Array.from(cats);
  }, [findings]);

  // Client Pagination for Table
  const totalPages = Math.max(1, Math.ceil(findings.length / pageSize));
  const paginatedFindings = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return findings.slice(start, start + pageSize);
  }, [findings, currentPage]);

  const getSeverityPill = (severity) => {
    const s = (severity || 'low').toLowerCase();
    return <span className={`pill-severity ${s}`}>{severity}</span>;
  };

  const getStatusPill = (status) => {
    const s = (status || 'detected').toLowerCase().replace(/\s+/g, '-');
    return <span className={`pill-status ${s}`}>{status}</span>;
  };

  return (
    <div>
      {/* Top Row: 4 Metric Cards of Equal Height */}
      <div className="metrics-row">
        <div className="panel metric-card">
          <div className="metric-header">
            <span>Total Findings</span>
            <ShieldAlert size={18} color="var(--accent-light)" />
          </div>
          <div className="metric-number">{totalCount}</div>
        </div>

        <div className="panel metric-card">
          <div className="metric-header">
            <span>High & Critical</span>
            <AlertTriangle size={18} color="#f97316" />
          </div>
          <div className="metric-number">{highCriticalCount}</div>
        </div>

        <div className="panel metric-card">
          <div className="metric-header">
            <span>Open & Confirmed</span>
            <AlertCircle size={18} color="#f59e0b" />
          </div>
          <div className="metric-number">{openCount}</div>
        </div>

        <div className="panel metric-card">
          <div className="metric-header">
            <span>Remediated</span>
            <CheckCircle size={18} color="#10b981" />
          </div>
          <div className="metric-number">{remediatedCount}</div>
        </div>
      </div>

      {/* Map Card */}
      <MapWidget />

      {/* Filter Bar */}
      <div className="filter-bar">
        <div className="filter-group">
          <label htmlFor="search-input" className="sr-only" style={{ display: 'none' }}>Search findings</label>
          <div style={{ position: 'relative' }}>
            <Search size={14} color="var(--text-tertiary)" style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)' }} />
            <input
              id="search-input"
              type="text"
              aria-label="Search findings by title, description, or component"
              placeholder="Search findings (Press Enter)..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyDown={handleSearchKeyDown}
              className="filter-input"
              style={{ paddingLeft: '32px' }}
            />
          </div>
        </div>

        <div className="filter-group">
          <label htmlFor="severity-select" style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>Severity:</label>
          <select
            id="severity-select"
            aria-label="Filter by severity"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="filter-select"
          >
            <option value="">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
        </div>

        <div className="filter-group">
          <label htmlFor="status-select" style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>Status:</label>
          <select
            id="status-select"
            aria-label="Filter by status"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="filter-select"
          >
            <option value="">All Statuses</option>
            <option value="Remediated">Remediated</option>
            <option value="Confirmed">Confirmed</option>
            <option value="Detected">Detected</option>
            <option value="Needs Validation">Needs Validation</option>
          </select>
        </div>

        {uniqueCategories.length > 0 && (
          <div className="filter-group">
            <label htmlFor="category-select" style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>Category:</label>
            <select
              id="category-select"
              aria-label="Filter by category"
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="filter-select"
            >
              <option value="">All Categories</option>
              {uniqueCategories.map((cat, i) => (
                <option key={i} value={cat}>{cat}</option>
              ))}
            </select>
          </div>
        )}

        <div style={{ marginLeft: 'auto', display: 'flex', gap: 'var(--space-2)' }}>
          <button onClick={handleResetFilters} className="btn btn-secondary" title="Reset all filters">
            <RotateCcw size={14} /> Reset
          </button>
          <button onClick={handleExportJSON} className="btn btn-secondary" title="Export findings as JSON">
            <Download size={14} /> JSON
          </button>
          <button onClick={handleExportPDF} className="btn btn-secondary" title="Export report via Print/PDF">
            <Printer size={14} /> PDF
          </button>
        </div>
      </div>

      {/* Main Grid: Findings Table (Left 2fr) and Severity/Progress Charts (Right 1fr) */}
      <div className="dashboard-grid">
        {/* Table Card */}
        <div className="panel table-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-3)' }}>
            <h2 style={{ margin: 0, fontSize: 'var(--text-base)', fontWeight: 600 }}>
              Vulnerabilities & Security Findings ({findings.length})
            </h2>
            <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-tertiary)' }}>
              Showing {paginatedFindings.length} of {findings.length}
            </span>
          </div>

          {loading && (
            <div style={{ padding: 'var(--space-6)' }}>
              <div className="skeleton-line" style={{ width: '100%' }}></div>
              <div className="skeleton-line" style={{ width: '90%' }}></div>
              <div className="skeleton-line" style={{ width: '95%' }}></div>
              <div className="skeleton-line" style={{ width: '85%' }}></div>
            </div>
          )}

          {error && (
            <div className="state-box" style={{ color: '#fca5a5' }}>
              <AlertCircle size={28} />
              <div>{error}</div>
              <button onClick={fetchFindingsData} className="btn btn-secondary">Retry</button>
            </div>
          )}

          {!loading && !error && (
            <>
              <div className="table-responsive">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th className="sortable" onClick={() => handleSort('title')}>
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                          Title <ArrowUpDown size={12} />
                        </span>
                      </th>
                      <th className="sortable" onClick={() => handleSort('category')}>
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                          Category <ArrowUpDown size={12} />
                        </span>
                      </th>
                      <th className="sortable" onClick={() => handleSort('severity')}>
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                          Severity <ArrowUpDown size={12} />
                        </span>
                      </th>
                      <th className="sortable" onClick={() => handleSort('status')}>
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                          Status <ArrowUpDown size={12} />
                        </span>
                      </th>
                      <th>Taxonomy (CWE / OWASP)</th>
                    </tr>
                  </thead>
                  <tbody>
                    {paginatedFindings.map(f => (
                      <tr 
                        key={f.id} 
                        className="clickable-row"
                        onClick={() => navigate(`/finding/${f.id}`)}
                        tabIndex={0}
                        onKeyDown={(e) => { if (e.key === 'Enter') navigate(`/finding/${f.id}`); }}
                      >
                        <td style={{ fontWeight: 500, color: 'var(--text-primary)' }}>
                          {f.title}
                        </td>
                        <td style={{ color: 'var(--text-secondary)' }}>
                          {f.category}
                        </td>
                        <td>
                          {getSeverityPill(f.severity)}
                        </td>
                        <td>
                          {getStatusPill(f.status)}
                        </td>
                        <td>
                          {f.cwe && <span className="tag-meta">{f.cwe.split(':')[0]}</span>}
                          {f.owasp && <span className="tag-meta">{f.owasp.split(' ')[0]}</span>}
                        </td>
                      </tr>
                    ))}
                    {paginatedFindings.length === 0 && (
                      <tr>
                        <td colSpan="5">
                          <div className="state-box">
                            <div>No findings matched the selected filters.</div>
                            <button onClick={handleResetFilters} className="btn btn-secondary">Clear Filters</button>
                          </div>
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>

              {/* Pagination Controls */}
              {totalPages > 1 && (
                <div className="pagination-bar">
                  <div>
                    Page {currentPage} of {totalPages}
                  </div>
                  <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
                    <button
                      className="btn btn-secondary"
                      onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                      disabled={currentPage === 1}
                      aria-label="Previous page"
                    >
                      <ChevronLeft size={14} /> Prev
                    </button>
                    <button
                      className="btn btn-secondary"
                      onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                      disabled={currentPage === totalPages}
                      aria-label="Next page"
                    >
                      Next <ChevronRight size={14} />
                    </button>
                  </div>
                </div>
              )}
            </>
          )}
        </div>

        {/* Right Column: Severity Donut & Remediation Progress Bar (Equal Height) */}
        <div className="panel charts-card">
          <div>
            <h2 style={{ margin: '0 0 var(--space-3) 0', fontSize: 'var(--text-base)', fontWeight: 600 }}>
              Severity Distribution
            </h2>
            <div style={{ height: '220px', width: '100%' }}>
              {chartData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={chartData}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      innerRadius={50}
                      outerRadius={75}
                      stroke="none"
                    >
                      {chartData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={severityColors[entry.name] || '#3b82f6'} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{ backgroundColor: '#111827', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px', color: '#f9fafb' }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="state-box" style={{ height: '100%' }}>No severity data</div>
              )}
            </div>

            {/* Severity Legend */}
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)', justifyContent: 'center', marginTop: 'var(--space-2)' }}>
              {chartData.map(item => (
                <div key={item.name} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
                  <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: severityColors[item.name] }}></div>
                  <span>{item.name}: <strong>{item.value}</strong></span>
                </div>
              ))}
            </div>
          </div>

          <div style={{ borderTop: '1px solid var(--border-panel)', paddingTop: 'var(--space-4)', marginTop: 'var(--space-4)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 'var(--text-sm)', marginBottom: 'var(--space-1)' }}>
              <span style={{ fontWeight: 600 }}>Remediation Progress</span>
              <span style={{ color: 'var(--color-remediated)', fontWeight: 700 }}>{remediationPercentage}%</span>
            </div>
            
            <div className="progress-track" aria-label="Remediation progress ratio">
              <div 
                className="progress-fill-remediated" 
                style={{ width: `${remediationPercentage}%` }} 
                title={`Remediated: ${remediatedCount}`}
              ></div>
              <div 
                className="progress-fill-open" 
                style={{ width: `${100 - remediationPercentage}%` }} 
                title={`Open/Confirmed: ${openCount}`}
              ></div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', marginTop: 'var(--space-1)' }}>
              <span>Remediated: <strong style={{ color: '#34d399' }}>{remediatedCount}</strong></span>
              <span>Open: <strong style={{ color: '#fb923c' }}>{openCount}</strong></span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
