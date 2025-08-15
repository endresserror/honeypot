import React, { useState, useEffect } from 'react';
import { signatureApi } from '../services/api';
import { toast } from 'react-toastify';
import SignatureModal from '../components/SignatureModal';

const SignatureReview = () => {
  const [signatures, setSignatures] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selectedSignature, setSelectedSignature] = useState(null);
  const [showModal, setShowModal] = useState(false);
  const [processing, setProcessing] = useState({});
  const [adminUsername, setAdminUsername] = useState(localStorage.getItem('adminUsername') || '');

  useEffect(() => {
    fetchPendingSignatures();
  }, []);

  const fetchPendingSignatures = async () => {
    try {
      setLoading(true);
      setError('');
      const response = await signatureApi.getPendingSignatures();
      setSignatures(response.data.signatures || []);
    } catch (err) {
      setError('Failed to load pending signatures');
      console.error('Error fetching signatures:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleApprove = async (signatureId) => {
    if (!adminUsername.trim()) {
      toast.error('Please enter your admin username first');
      return;
    }

    try {
      setProcessing({ ...processing, [signatureId]: 'approving' });
      await signatureApi.approveSignature(signatureId, adminUsername);
      
      // Remove from list
      setSignatures(prev => prev.filter(sig => sig.signatureId !== signatureId));
      
      toast.success('Signature approved successfully');
      localStorage.setItem('adminUsername', adminUsername);
    } catch (err) {
      toast.error('Failed to approve signature: ' + (err.response?.data?.error || err.message));
    } finally {
      setProcessing({ ...processing, [signatureId]: null });
    }
  };

  const handleReject = async (signatureId, reason = '') => {
    if (!adminUsername.trim()) {
      toast.error('Please enter your admin username first');
      return;
    }

    try {
      setProcessing({ ...processing, [signatureId]: 'rejecting' });
      await signatureApi.rejectSignature(signatureId, adminUsername, reason);
      
      // Remove from list
      setSignatures(prev => prev.filter(sig => sig.signatureId !== signatureId));
      
      toast.success('Signature rejected');
      localStorage.setItem('adminUsername', adminUsername);
    } catch (err) {
      toast.error('Failed to reject signature: ' + (err.response?.data?.error || err.message));
    } finally {
      setProcessing({ ...processing, [signatureId]: null });
    }
  };

  const handleViewDetails = (signature) => {
    setSelectedSignature(signature);
    setShowModal(true);
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

  if (loading) {
    return (
      <div className="loading">
        <div className="loading-spinner"></div>
        <p>Loading pending signatures...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="error">
        <h3>Error</h3>
        <p>{error}</p>
        <button className="btn btn-primary" onClick={fetchPendingSignatures}>
          Retry
        </button>
      </div>
    );
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '30px' }}>
        <h2>Signature Review</h2>
        <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
          <div>
            <label htmlFor="adminUsername" style={{ fontSize: '14px', marginRight: '10px' }}>
              Admin Username:
            </label>
            <input
              id="adminUsername"
              type="text"
              value={adminUsername}
              onChange={(e) => setAdminUsername(e.target.value)}
              placeholder="Enter your username"
              style={{ padding: '8px 12px', borderRadius: '4px', border: '1px solid #ccc' }}
            />
          </div>
          <button className="btn btn-secondary" onClick={fetchPendingSignatures}>
            Refresh
          </button>
        </div>
      </div>

      {signatures.length === 0 ? (
        <div className="card">
          <div className="card-body" style={{ textAlign: 'center', padding: '40px' }}>
            <h4>No Pending Signatures</h4>
            <p style={{ color: '#6c757d', marginBottom: '20px' }}>
              All signatures have been reviewed. Check back later for new signatures to review.
            </p>
            <button className="btn btn-primary" onClick={fetchPendingSignatures}>
              Refresh
            </button>
          </div>
        </div>
      ) : (
        <div className="card">
          <div className="card-header">
            Pending Signatures ({signatures.length})
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
                    <th>Payload</th>
                    <th>Source</th>
                    <th>Actions</th>
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
                        {signature.sourceLog && (
                          <div style={{ fontSize: '12px' }}>
                            <div>IP: {signature.sourceLog.sourceIp}</div>
                            <div style={{ color: '#6c757d' }}>
                              {new Date(signature.sourceLog.timestamp).toLocaleDateString()}
                            </div>
                          </div>
                        )}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: '5px', flexWrap: 'wrap' }}>
                          <button
                            className="btn btn-sm btn-primary"
                            onClick={() => handleViewDetails(signature)}
                          >
                            Details
                          </button>
                          <button
                            className="btn btn-sm btn-success"
                            onClick={() => handleApprove(signature.signatureId)}
                            disabled={processing[signature.signatureId] === 'approving'}
                          >
                            {processing[signature.signatureId] === 'approving' ? 'Approving...' : 'Approve'}
                          </button>
                          <button
                            className="btn btn-sm btn-danger"
                            onClick={() => handleReject(signature.signatureId)}
                            disabled={processing[signature.signatureId] === 'rejecting'}
                          >
                            {processing[signature.signatureId] === 'rejecting' ? 'Rejecting...' : 'Reject'}
                          </button>
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

      {/* Signature Details Modal */}
      {showModal && selectedSignature && (
        <SignatureModal
          signature={selectedSignature}
          onClose={() => setShowModal(false)}
          onApprove={() => {
            handleApprove(selectedSignature.signatureId);
            setShowModal(false);
          }}
          onReject={(reason) => {
            handleReject(selectedSignature.signatureId, reason);
            setShowModal(false);
          }}
          adminUsername={adminUsername}
        />
      )}
    </div>
  );
};

export default SignatureReview;