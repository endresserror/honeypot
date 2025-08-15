import React, { useState, useEffect } from 'react';
import { logsApi } from '../services/api';
import { toast } from 'react-toastify';

const Logs = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [pagination, setPagination] = useState({});
  const [filters, setFilters] = useState({
    processed: '',
    method: '',
    source_ip: '',
    page: 1
  });

  useEffect(() => {
    fetchLogs();
  }, [filters]); // eslint-disable-line react-hooks/exhaustive-deps

  const fetchLogs = async () => {
    try {
      setLoading(true);
      setError('');
      
      const params = { ...filters };
      if (params.processed === '') delete params.processed;
      if (!params.method) delete params.method;
      if (!params.source_ip) delete params.source_ip;

      const response = await logsApi.getLogs(params);
      setLogs(response.data.logs || []);
      setPagination(response.data.pagination || {});
    } catch (err) {
      setError('Failed to load attack logs');
      console.error('Error fetching logs:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleFilterChange = (field, value) => {
    setFilters(prev => ({ ...prev, [field]: value, page: 1 }));
  };

  const handlePageChange = (newPage) => {
    setFilters(prev => ({ ...prev, page: newPage }));
  };

  const clearFilters = () => {
    setFilters({
      processed: '',
      method: '',
      source_ip: '',
      page: 1
    });
  };

  const handleAnalyzeLog = async (logId) => {
    try {
      const response = await logsApi.analyzeLog(logId);
      toast.success(`Analysis complete: ${response.data.signatures_generated} signatures generated`);
      fetchLogs(); // Refresh to show processed status
    } catch (err) {
      toast.error('Failed to analyze log: ' + (err.response?.data?.error || err.message));
    }
  };

  if (loading) {
    return (
      <div className="loading">
        <div className="loading-spinner"></div>
        <p>Loading attack logs...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="error">
        <h3>Error</h3>
        <p>{error}</p>
        <button className="btn btn-primary" onClick={fetchLogs}>
          Retry
        </button>
      </div>
    );
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '30px' }}>
        <h2>Attack Logs</h2>
        <button className="btn btn-secondary" onClick={fetchLogs}>
          Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="filters">
        <div className="filters-row">
          <div className="filter-group">
            <label className="form-label">Processing Status</label>
            <select
              className="form-control form-select"
              value={filters.processed}
              onChange={(e) => handleFilterChange('processed', e.target.value)}
            >
              <option value="">All Logs</option>
              <option value="false">Unprocessed</option>
              <option value="true">Processed</option>
            </select>
          </div>
          <div className="filter-group">
            <label className="form-label">HTTP Method</label>
            <select
              className="form-control form-select"
              value={filters.method}
              onChange={(e) => handleFilterChange('method', e.target.value)}
            >
              <option value="">All Methods</option>
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
              <option value="DELETE">DELETE</option>
              <option value="PATCH">PATCH</option>
            </select>
          </div>
          <div className="filter-group">
            <label className="form-label">Source IP</label>
            <input
              type="text"
              className="form-control"
              placeholder="Enter IP address"
              value={filters.source_ip}
              onChange={(e) => handleFilterChange('source_ip', e.target.value)}
            />
          </div>
          <div style={{ display: 'flex', alignItems: 'end' }}>
            <button className="btn btn-secondary" onClick={clearFilters}>
              Clear Filters
            </button>
          </div>
        </div>
      </div>

      {/* Results Summary */}
      <div style={{ marginBottom: '20px' }}>
        <p style={{ color: '#6c757d' }}>
          Showing {logs.length} log{logs.length !== 1 ? 's' : ''}
          {pagination.total && ` of ${pagination.total} total`}
          {Object.values(filters).some(v => v && v !== 1) && ' (filtered)'}
        </p>
      </div>

      {/* Logs Table */}
      {logs.length === 0 ? (
        <div className="card">
          <div className="card-body" style={{ textAlign: 'center', padding: '40px' }}>
            <h4>No Logs Found</h4>
            <p style={{ color: '#6c757d', marginBottom: '20px' }}>
              {Object.values(filters).some(v => v && v !== 1)
                ? 'No logs match the current filters.'
                : 'No attack logs available.'
              }
            </p>
            {Object.values(filters).some(v => v && v !== 1) && (
              <button className="btn btn-primary" onClick={clearFilters}>
                Clear Filters
              </button>
            )}
          </div>
        </div>
      ) : (
        <div className="card">
          <div className="card-header">
            Attack Logs ({pagination.total || logs.length})
          </div>
          <div className="card-body" style={{ padding: 0 }}>
            <div style={{ overflowX: 'auto' }}>
              <table className="table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Timestamp</th>
                    <th>Source IP</th>
                    <th>Method</th>
                    <th>URI</th>
                    <th>Status</th>
                    <th>Processed</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {logs.map((log) => (
                    <tr key={log.id}>
                      <td>
                        <code style={{ fontSize: '12px' }}>{log.id}</code>
                      </td>
                      <td>
                        <div style={{ fontSize: '12px' }}>
                          {new Date(log.timestamp).toLocaleDateString()}
                          <br />
                          {new Date(log.timestamp).toLocaleTimeString()}
                        </div>
                      </td>
                      <td>
                        <code>{log.sourceIp}</code>
                      </td>
                      <td>
                        <span className={`badge ${log.request.method === 'GET' ? 'badge-info' : 'badge-warning'}`}>
                          {log.request.method}
                        </span>
                      </td>
                      <td>
                        <div style={{ maxWidth: '300px', fontSize: '12px' }}>
                          <code style={{ 
                            wordBreak: 'break-all',
                            display: 'block',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap'
                          }}>
                            {log.request.uri}
                          </code>
                        </div>
                      </td>
                      <td>
                        <span className={`badge ${
                          log.response.statusCode >= 500 ? 'badge-danger' :
                          log.response.statusCode >= 400 ? 'badge-warning' :
                          log.response.statusCode >= 300 ? 'badge-info' :
                          'badge-success'
                        }`}>
                          {log.response.statusCode}
                        </span>
                      </td>
                      <td>
                        {log.processed ? (
                          <span className="badge badge-success">
                            Processed ({log.signaturesGenerated} sigs)
                          </span>
                        ) : (
                          <span className="badge badge-warning">
                            Pending
                          </span>
                        )}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: '5px' }}>
                          <button
                            className="btn btn-sm btn-primary"
                            onClick={() => {
                              // Could open a modal with log details
                              alert('Log details view - to be implemented');
                            }}
                          >
                            View
                          </button>
                          {!log.processed && (
                            <button
                              className="btn btn-sm btn-secondary"
                              onClick={() => handleAnalyzeLog(log.id)}
                            >
                              Analyze
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Pagination */}
      {pagination.pages > 1 && (
        <div style={{ display: 'flex', justifyContent: 'center', marginTop: '20px' }}>
          <div style={{ display: 'flex', gap: '5px' }}>
            <button
              className="btn btn-sm btn-secondary"
              disabled={!pagination.has_prev}
              onClick={() => handlePageChange(filters.page - 1)}
            >
              Previous
            </button>
            <span style={{ 
              padding: '6px 12px', 
              backgroundColor: '#f8f9fa', 
              border: '1px solid #dee2e6',
              borderRadius: '4px',
              fontSize: '14px'
            }}>
              Page {pagination.page} of {pagination.pages}
            </span>
            <button
              className="btn btn-sm btn-secondary"
              disabled={!pagination.has_next}
              onClick={() => handlePageChange(filters.page + 1)}
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default Logs;