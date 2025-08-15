import React, { useState } from 'react';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { tomorrow } from 'react-syntax-highlighter/dist/esm/styles/prism';

const SignatureModal = ({ signature, onClose, onApprove, onReject, adminUsername }) => {
  const [rejectReason, setRejectReason] = useState('');
  const [showRejectForm, setShowRejectForm] = useState(false);

  const handleReject = () => {
    onReject(rejectReason);
    setShowRejectForm(false);
    setRejectReason('');
  };

  const formatJson = (obj) => {
    return JSON.stringify(obj, null, 2);
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

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2 className="modal-title">Signature Details</h2>
          <button className="modal-close" onClick={onClose}>&times;</button>
        </div>

        <div className="modal-body">
          {/* Basic Information */}
          <div style={{ marginBottom: '25px' }}>
            <h3 style={{ fontSize: '18px', marginBottom: '15px', borderBottom: '1px solid #e9ecef', paddingBottom: '8px' }}>
              Basic Information
            </h3>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px' }}>
              <div>
                <strong>Signature ID:</strong> <code>{signature.signatureId}</code>
              </div>
              <div>
                <strong>Status:</strong> 
                <span className="badge badge-warning" style={{ marginLeft: '8px' }}>
                  {signature.status.replace('_', ' ')}
                </span>
              </div>
              <div>
                <strong>Attack Type:</strong> 
                <span className="badge badge-danger" style={{ marginLeft: '8px' }}>
                  {signature.attackType.replace('_', ' ')}
                </span>
              </div>
              <div>
                <strong>Risk Level:</strong> 
                <span style={{ 
                  color: getRiskLevelColor(signature.riskLevel), 
                  fontWeight: '600',
                  marginLeft: '8px'
                }}>
                  {signature.riskLevel}
                </span>
              </div>
              <div>
                <strong>Confidence Score:</strong> 
                <span style={{ marginLeft: '8px', fontWeight: '600' }}>
                  {(signature.confidenceScore * 100).toFixed(1)}%
                </span>
              </div>
              <div>
                <strong>Observed Count:</strong> {signature.observedCount}
              </div>
            </div>
          </div>

          {/* Name and Description */}
          <div style={{ marginBottom: '25px' }}>
            <h3 style={{ fontSize: '18px', marginBottom: '15px', borderBottom: '1px solid #e9ecef', paddingBottom: '8px' }}>
              Description
            </h3>
            <div style={{ marginBottom: '10px' }}>
              <strong>Name:</strong> {signature.name}
            </div>
            {signature.description && (
              <div>
                <strong>Description:</strong> {signature.description}
              </div>
            )}
          </div>

          {/* Attack Pattern */}
          <div style={{ marginBottom: '25px' }}>
            <h3 style={{ fontSize: '18px', marginBottom: '15px', borderBottom: '1px solid #e9ecef', paddingBottom: '8px' }}>
              Attack Pattern
            </h3>
            <SyntaxHighlighter 
              language="json" 
              style={tomorrow}
              customStyle={{ fontSize: '13px', borderRadius: '4px' }}
            >
              {formatJson(signature.attackPattern)}
            </SyntaxHighlighter>
          </div>

          {/* Verification Condition */}
          <div style={{ marginBottom: '25px' }}>
            <h3 style={{ fontSize: '18px', marginBottom: '15px', borderBottom: '1px solid #e9ecef', paddingBottom: '8px' }}>
              Verification Condition
            </h3>
            <SyntaxHighlighter 
              language="json" 
              style={tomorrow}
              customStyle={{ fontSize: '13px', borderRadius: '4px' }}
            >
              {formatJson(signature.verification)}
            </SyntaxHighlighter>
          </div>

          {/* Source Information */}
          {signature.sourceLog && (
            <div style={{ marginBottom: '25px' }}>
              <h3 style={{ fontSize: '18px', marginBottom: '15px', borderBottom: '1px solid #e9ecef', paddingBottom: '8px' }}>
                Source Log Information
              </h3>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px' }}>
                <div>
                  <strong>Source IP:</strong> {signature.sourceLog.sourceIp}
                </div>
                <div>
                  <strong>Timestamp:</strong> {new Date(signature.sourceLog.timestamp).toLocaleString()}
                </div>
                <div style={{ gridColumn: '1 / -1' }}>
                  <strong>Request URI:</strong>
                  <div style={{ 
                    backgroundColor: '#f8f9fa', 
                    border: '1px solid #e9ecef', 
                    borderRadius: '4px',
                    padding: '10px',
                    marginTop: '5px',
                    fontFamily: 'monospace',
                    fontSize: '13px',
                    wordBreak: 'break-all'
                  }}>
                    {signature.sourceLog.requestUri}
                  </div>
                </div>
                <div>
                  <strong>Response Status:</strong> {signature.sourceLog.responseStatusCode}
                </div>
              </div>
            </div>
          )}

          {/* Timestamps */}
          <div style={{ marginBottom: '25px' }}>
            <h3 style={{ fontSize: '18px', marginBottom: '15px', borderBottom: '1px solid #e9ecef', paddingBottom: '8px' }}>
              Timestamps
            </h3>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px' }}>
              <div>
                <strong>Created:</strong> {new Date(signature.createdAt).toLocaleString()}
              </div>
              {signature.lastUsedAt && (
                <div>
                  <strong>Last Used:</strong> {new Date(signature.lastUsedAt).toLocaleString()}
                </div>
              )}
            </div>
          </div>

          {/* Reject Form */}
          {showRejectForm && (
            <div style={{ 
              backgroundColor: '#f8f9fa', 
              border: '1px solid #e9ecef', 
              borderRadius: '4px',
              padding: '15px',
              marginBottom: '20px'
            }}>
              <h4 style={{ fontSize: '16px', marginBottom: '10px' }}>Rejection Reason</h4>
              <textarea
                value={rejectReason}
                onChange={(e) => setRejectReason(e.target.value)}
                placeholder="Please provide a reason for rejecting this signature..."
                style={{
                  width: '100%',
                  height: '80px',
                  padding: '8px',
                  border: '1px solid #ced4da',
                  borderRadius: '4px',
                  fontSize: '14px',
                  resize: 'vertical'
                }}
              />
              <div style={{ marginTop: '10px', display: 'flex', gap: '10px' }}>
                <button 
                  className="btn btn-sm btn-danger" 
                  onClick={handleReject}
                  disabled={!adminUsername.trim()}
                >
                  Confirm Rejection
                </button>
                <button 
                  className="btn btn-sm btn-secondary" 
                  onClick={() => setShowRejectForm(false)}
                >
                  Cancel
                </button>
              </div>
            </div>
          )}
        </div>

        <div className="modal-footer">
          {!showRejectForm && (
            <>
              <button 
                className="btn btn-success" 
                onClick={onApprove}
                disabled={!adminUsername.trim()}
              >
                Approve Signature
              </button>
              <button 
                className="btn btn-danger" 
                onClick={() => setShowRejectForm(true)}
                disabled={!adminUsername.trim()}
              >
                Reject Signature
              </button>
            </>
          )}
          <button className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
          {!adminUsername.trim() && (
            <div style={{ fontSize: '12px', color: '#dc3545', marginLeft: '10px' }}>
              Please enter admin username to approve/reject
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default SignatureModal;