import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { logsApi, signatureApi } from '../services/api';
import { formatDistanceToNow } from 'date-fns';

const RecentActivity = () => {
  const [recentLogs, setRecentLogs] = useState([]);
  const [recentSignatures, setRecentSignatures] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchRecentActivity();
  }, []);

  const fetchRecentActivity = async () => {
    try {
      setLoading(true);
      
      // Fetch recent logs and signatures in parallel
      const [logsResponse, signaturesResponse] = await Promise.all([
        logsApi.getLogs({ page: 1, per_page: 5 }),
        signatureApi.getPendingSignatures()
      ]);

      setRecentLogs(logsResponse.data.logs || []);
      setRecentSignatures((signaturesResponse.data.signatures || []).slice(0, 5));
    } catch (error) {
      console.error('Failed to fetch recent activity:', error);
    } finally {
      setLoading(false);
    }
  };

  const getAttackTypeBadgeColor = (attackType) => {
    const colors = {
      'SQL_INJECTION': 'danger',
      'XSS': 'warning',
      'LFI': 'info',
      'COMMAND_INJECTION': 'danger',
      'PATH_TRAVERSAL': 'secondary'
    };
    return colors[attackType] || 'secondary';
  };

  const getStatusBadgeColor = (status) => {
    const colors = {
      'pending_review': 'warning',
      'approved': 'success',
      'rejected': 'danger'
    };
    return colors[status] || 'secondary';
  };

  if (loading) {
    return (
      <div className="card" style={{ marginBottom: '30px' }}>
        <div className="card-header">Recent Activity</div>
        <div className="card-body">
          <div className="loading">
            <div className="loading-spinner"></div>
            <p>Loading recent activity...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginBottom: '30px' }}>
      {/* Recent Attack Logs */}
      <div className="card">
        <div className="card-header">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>Recent Attack Logs</span>
            <Link to="/logs" className="btn btn-sm btn-secondary">View All</Link>
          </div>
        </div>
        <div className="card-body">
          {recentLogs.length === 0 ? (
            <p style={{ color: '#6c757d', fontStyle: 'italic', textAlign: 'center', margin: '20px 0' }}>
              No recent logs available
            </p>
          ) : (
            <div>
              {recentLogs.map((log) => (
                <div key={log.id} style={{ 
                  padding: '10px 0', 
                  borderBottom: '1px solid #e9ecef',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center'
                }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontWeight: '500', fontSize: '14px', marginBottom: '5px' }}>
                      {log.request.method} {log.request.uri.substring(0, 50)}
                      {log.request.uri.length > 50 && '...'}
                    </div>
                    <div style={{ fontSize: '12px', color: '#6c757d' }}>
                      From: {log.sourceIp} • Status: {log.response.statusCode}
                    </div>
                  </div>
                  <div style={{ textAlign: 'right', marginLeft: '10px' }}>
                    <div style={{ fontSize: '12px', color: '#6c757d' }}>
                      {formatDistanceToNow(new Date(log.timestamp), { addSuffix: true })}
                    </div>
                    {!log.processed && (
                      <span className="badge badge-warning" style={{ fontSize: '10px', marginTop: '3px' }}>
                        Unprocessed
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Recent Signatures */}
      <div className="card">
        <div className="card-header">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>Pending Signatures</span>
            <Link to="/review" className="btn btn-sm btn-secondary">Review All</Link>
          </div>
        </div>
        <div className="card-body">
          {recentSignatures.length === 0 ? (
            <p style={{ color: '#6c757d', fontStyle: 'italic', textAlign: 'center', margin: '20px 0' }}>
              No pending signatures
            </p>
          ) : (
            <div>
              {recentSignatures.map((signature) => (
                <div key={signature.signatureId} style={{ 
                  padding: '10px 0', 
                  borderBottom: '1px solid #e9ecef',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center'
                }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontWeight: '500', fontSize: '14px', marginBottom: '5px' }}>
                      {signature.name}
                    </div>
                    <div style={{ fontSize: '12px', display: 'flex', gap: '10px', alignItems: 'center' }}>
                      <span className={`badge badge-${getAttackTypeBadgeColor(signature.attackType)}`}>
                        {signature.attackType.replace('_', ' ')}
                      </span>
                      <span>Confidence: {(signature.confidenceScore * 100).toFixed(0)}%</span>
                    </div>
                  </div>
                  <div style={{ textAlign: 'right', marginLeft: '10px' }}>
                    <div style={{ fontSize: '12px', color: '#6c757d' }}>
                      {formatDistanceToNow(new Date(signature.createdAt), { addSuffix: true })}
                    </div>
                    <span className={`badge badge-${getStatusBadgeColor(signature.status)}`} style={{ fontSize: '10px', marginTop: '3px' }}>
                      {signature.status.replace('_', ' ')}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default RecentActivity;