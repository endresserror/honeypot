import React, { useState, useEffect } from 'react';
import { healthApi } from '../services/api';

const Header = () => {
  const [systemStatus, setSystemStatus] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchSystemStatus();
    // Refresh status every 30 seconds
    const interval = setInterval(fetchSystemStatus, 30000);
    return () => clearInterval(interval);
  }, []);

  const fetchSystemStatus = async () => {
    try {
      const response = await healthApi.getStatus();
      setSystemStatus(response.data);
    } catch (error) {
      console.error('Failed to fetch system status:', error);
      setSystemStatus({ status: 'error' });
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'operational':
        return '#28a745';
      case 'healthy':
        return '#28a745';
      case 'error':
      case 'unhealthy':
        return '#dc3545';
      default:
        return '#ffc107';
    }
  };

  return (
    <header className="header">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h1>Vulnerability Scanner Management</h1>
        <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
          {!loading && systemStatus && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span
                style={{
                  width: '12px',
                  height: '12px',
                  borderRadius: '50%',
                  backgroundColor: getStatusColor(systemStatus.status),
                  display: 'inline-block'
                }}
              ></span>
              <span style={{ fontSize: '14px' }}>
                System: {systemStatus.status || 'Unknown'}
              </span>
              {systemStatus.statistics && (
                <span style={{ fontSize: '12px', opacity: 0.8 }}>
                  ({systemStatus.statistics.signatures?.total || 0} signatures, {' '}
                  {systemStatus.statistics.signatures?.pendingReview || 0} pending)
                </span>
              )}
            </div>
          )}
          <div style={{ fontSize: '14px', opacity: 0.8 }}>
            {new Date().toLocaleDateString()} {new Date().toLocaleTimeString()}
          </div>
        </div>
      </div>
    </header>
  );
};

export default Header;