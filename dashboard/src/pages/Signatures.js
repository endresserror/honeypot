import React, { useState, useEffect } from 'react';
import { signatureApi } from '../services/api';
import { toast } from 'react-toastify';

const Signatures = () => {
  const [signatures, setSignatures] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [filters, setFilters] = useState({
    attack_type: '',
    min_confidence: ''
  });

  useEffect(() => {
    fetchSignatures();
  }, [filters]); // eslint-disable-line react-hooks/exhaustive-deps

  const fetchSignatures = async () => {
    try {
      setLoading(true);
      setError('');
      
      // Build query parameters
      const params = {};
      if (filters.attack_type) params.attack_type = filters.attack_type;
      if (filters.min_confidence) params.min_confidence = parseFloat(filters.min_confidence);

      const response = await signatureApi.getSignatures(params);
      setSignatures(response.data.signatures || []);
    } catch (err) {
      setError('Failed to load signatures');
      console.error('Error fetching signatures:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleFilterChange = (field, value) => {
    setFilters(prev => ({ ...prev, [field]: value }));
  };

  const clearFilters = () => {
    setFilters({
      attack_type: '',
      min_confidence: ''
    });
  };

  const getAttackTypeBadgeColor = (attackType) => {
    const colors = {
      'SQL_INJECTION': 'danger',
      'XSS': 'warning',
      'LFI': 'info',
      'COMMAND_INJECTION': 'danger',
      'PATH_TRAVERSAL': 'secondary',
      'XXE': 'info',
      'SSRF': 'warning'
    };
    return colors[attackType] || 'secondary';
  };

  const getRiskLevelColor = (riskLevel) => {
    const colors = {
      'Critical': '#dc3545',
      'High': '#fd7e14',
      'Medium': '#ffc107',
      'Low': '#28a745'
    };
    return colors[riskLevel] || '#6c757d';
  };

  const exportSignatures = () => {
    const dataStr = JSON.stringify(signatures, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `signatures-${new Date().toISOString().split('T')[0]}.json`;
    link.click();
    URL.revokeObjectURL(url);
    toast.success('Signatures exported successfully');
  };

  if (loading) {
    return (
      <div className="loading">
        <div className="loading-spinner"></div>
        <p>Loading approved signatures...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="error">
        <h3>Error</h3>
        <p>{error}</p>
        <button className="btn btn-primary" onClick={fetchSignatures}>
          Retry
        </button>
      </div>
    );
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '30px' }}>
        <h2>Approved Signatures</h2>
        <div>
          <button className="btn btn-success" onClick={exportSignatures}>
            Export Signatures
          </button>
          <button className="btn btn-secondary" onClick={fetchSignatures} style={{ marginLeft: '10px' }}>
            Refresh
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="filters">
        <div className="filters-row">
          <div className="filter-group">
            <label className="form-label">Attack Type</label>
            <select
              className="form-control form-select"
              value={filters.attack_type}
              onChange={(e) => handleFilterChange('attack_type', e.target.value)}
            >
              <option value="">All Types</option>
              <option value="SQL_INJECTION">SQL Injection</option>
              <option value="XSS">Cross-Site Scripting</option>
              <option value="LFI">Local File Inclusion</option>
              <option value="COMMAND_INJECTION">Command Injection</option>
              <option value="PATH_TRAVERSAL">Path Traversal</option>
              <option value="XXE">XML External Entity</option>
              <option value="SSRF">Server-Side Request Forgery</option>
            </select>
          </div>
          <div className="filter-group">
            <label className="form-label">Minimum Confidence</label>
            <select
              className="form-control form-select"
              value={filters.min_confidence}
              onChange={(e) => handleFilterChange('min_confidence', e.target.value)}
            >
              <option value="">Any Confidence</option>
              <option value="0.9">90% and above</option>
              <option value="0.8">80% and above</option>
              <option value="0.7">70% and above</option>
              <option value="0.6">60% and above</option>
              <option value="0.5">50% and above</option>
            </select>
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
          Showing {signatures.length} signature{signatures.length !== 1 ? 's' : ''}
          {(filters.attack_type || filters.min_confidence) && ' (filtered)'}
        </p>
      </div>

      {/* Signatures Table */}
      {signatures.length === 0 ? (
        <div className="card">
          <div className="card-body" style={{ textAlign: 'center', padding: '40px' }}>
            <h4>No Signatures Found</h4>
            <p style={{ color: '#6c757d', marginBottom: '20px' }}>
              {(filters.attack_type || filters.min_confidence) 
                ? 'No signatures match the current filters.'
                : 'No approved signatures available.'
              }
            </p>
            {(filters.attack_type || filters.min_confidence) && (
              <button className="btn btn-primary" onClick={clearFilters}>
                Clear Filters
              </button>
            )}
          </div>
        </div>
      ) : (
        <div className="card">
          <div className="card-header">
            Approved Signatures ({signatures.length})
          </div>
          <div className="card-body" style={{ padding: 0 }}>
            <div style={{ overflowX: 'auto' }}>
              <table className="table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Name</th>
                    <th>Attack Type</th>
                    <th>Risk Level</th>
                    <th>Confidence</th>
                    <th>Usage Stats</th>
                    <th>Payload Preview</th>
                    <th>Last Used</th>
                  </tr>
                </thead>
                <tbody>
                  {signatures.map((signature) => (
                    <tr key={signature.signatureId}>
                      <td>
                        <code style={{ fontSize: '12px' }}>{signature.signatureId}</code>
                      </td>
                      <td>
                        <div style={{ maxWidth: '200px' }}>
                          <div style={{ fontWeight: '500', fontSize: '14px' }}>
                            {signature.name}
                          </div>
                          {signature.description && (
                            <div style={{ fontSize: '12px', color: '#6c757d', marginTop: '3px' }}>
                              {signature.description.substring(0, 60)}...
                            </div>
                          )}
                        </div>
                      </td>
                      <td>
                        <span className={`badge badge-${getAttackTypeBadgeColor(signature.attackType)}`}>
                          {signature.attackType.replace('_', ' ')}
                        </span>
                      </td>
                      <td>
                        <span 
                          style={{ 
                            color: getRiskLevelColor(signature.riskLevel), 
                            fontWeight: '600',
                            fontSize: '14px'
                          }}
                        >
                          {signature.riskLevel}
                        </span>
                      </td>
                      <td>
                        <div style={{ textAlign: 'center' }}>
                          <div style={{ fontWeight: '600' }}>
                            {(signature.confidenceScore * 100).toFixed(0)}%
                          </div>
                          <div style={{ 
                            width: '60px', 
                            height: '4px', 
                            backgroundColor: '#e9ecef', 
                            borderRadius: '2px',
                            margin: '3px 0'
                          }}>
                            <div 
                              style={{
                                width: `${signature.confidenceScore * 100}%`,
                                height: '100%',
                                backgroundColor: signature.confidenceScore > 0.7 ? '#28a745' : signature.confidenceScore > 0.5 ? '#ffc107' : '#dc3545',
                                borderRadius: '2px'
                              }}
                            />
                          </div>
                        </div>
                      </td>
                      <td>
                        <div style={{ fontSize: '12px' }}>
                          <div>Observed: {signature.observedCount}</div>
                          <div>Success: {signature.successCount || 0}</div>
                          {signature.falsePositiveCount > 0 && (
                            <div style={{ color: '#dc3545' }}>
                              FP: {signature.falsePositiveCount}
                            </div>
                          )}
                        </div>
                      </td>
                      <td>
                        <code style={{ 
                          fontSize: '12px', 
                          maxWidth: '150px', 
                          display: 'block',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap'
                        }}>
                          {signature.attackPattern?.payload || 'N/A'}
                        </code>
                      </td>
                      <td>
                        <div style={{ fontSize: '12px', color: '#6c757d' }}>
                          {signature.lastUsedAt 
                            ? new Date(signature.lastUsedAt).toLocaleDateString()
                            : 'Never'
                          }
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
    </div>
  );
};

export default Signatures;