import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { signatureApi, logsApi, feedbackApi } from '../services/api';
import StatCard from '../components/StatCard';
import RecentActivity from '../components/RecentActivity';

const Dashboard = () => {
  const [stats, setStats] = useState({
    signatures: {},
    logs: {},
    feedback: {}
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      setError('');

      // Fetch all statistics in parallel
      const [sigStats, logStats, feedStats] = await Promise.all([
        signatureApi.getStatistics(),
        logsApi.getStatistics(),
        feedbackApi.getStatistics()
      ]);

      setStats({
        signatures: sigStats.data,
        logs: logStats.data,
        feedback: feedStats.data
      });
    } catch (err) {
      setError('Failed to load dashboard data');
      console.error('Dashboard error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateSignatures = async () => {
    try {
      setLoading(true);
      const response = await signatureApi.generateSignatures();
      
      // Refresh dashboard data after generation
      await fetchDashboardData();
      
      alert(`Successfully generated ${response.data.generated_count} new signatures`);
    } catch (err) {
      alert('Failed to generate signatures: ' + (err.response?.data?.error || err.message));
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="loading">
        <div className="loading-spinner"></div>
        <p>Loading dashboard...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="error">
        <h3>Error</h3>
        <p>{error}</p>
        <button className="btn btn-primary" onClick={fetchDashboardData}>
          Retry
        </button>
      </div>
    );
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '30px' }}>
        <h2>Dashboard Overview</h2>
        <div>
          <button 
            className="btn btn-primary" 
            onClick={handleGenerateSignatures}
            disabled={loading}
          >
            Generate Signatures
          </button>
          <button 
            className="btn btn-secondary" 
            onClick={fetchDashboardData}
            style={{ marginLeft: '10px' }}
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Statistics Grid */}
      <div className="stats-grid">
        <StatCard
          title="Total Signatures"
          value={stats.signatures.total_signatures || 0}
          subtitle={`${stats.signatures.approved || 0} approved`}
          color="#3498db"
          linkTo="/signatures"
        />
        
        <StatCard
          title="Pending Review"
          value={stats.signatures.pending_review || 0}
          subtitle="Awaiting approval"
          color="#f39c12"
          linkTo="/review"
        />
        
        <StatCard
          title="Attack Logs"
          value={stats.logs.total_logs || 0}
          subtitle={`${stats.logs.unprocessed_logs || 0} unprocessed`}
          color="#e74c3c"
          linkTo="/logs"
        />
        
        <StatCard
          title="Success Rate"
          value={`${stats.feedback.overall_success_rate || 0}%`}
          subtitle={`${stats.feedback.total_executions || 0} executions`}
          color="#27ae60"
          linkTo="/statistics"
        />
      </div>

      {/* Quick Actions */}
      <div className="card" style={{ marginBottom: '30px' }}>
        <div className="card-header">Quick Actions</div>
        <div className="card-body">
          <div style={{ display: 'flex', gap: '15px', flexWrap: 'wrap' }}>
            <Link to="/review" className="btn btn-primary">
              Review Pending Signatures ({stats.signatures.pending_review || 0})
            </Link>
            <Link to="/logs?processed=false" className="btn btn-secondary">
              Process Unprocessed Logs ({stats.logs.unprocessed_logs || 0})
            </Link>
            <Link to="/statistics" className="btn btn-success">
              View Detailed Statistics
            </Link>
          </div>
        </div>
      </div>

      {/* Recent Activity */}
      <RecentActivity />

      {/* System Health Summary */}
      <div className="card">
        <div className="card-header">System Health</div>
        <div className="card-body">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '20px' }}>
            <div>
              <h4 style={{ fontSize: '16px', marginBottom: '10px' }}>Signature Distribution</h4>
              {stats.signatures.attack_type_distribution && Object.entries(stats.signatures.attack_type_distribution).map(([type, count]) => (
                <div key={type} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '5px' }}>
                  <span style={{ fontSize: '14px' }}>{type}:</span>
                  <span style={{ fontSize: '14px', fontWeight: '600' }}>{count}</span>
                </div>
              ))}
            </div>
            
            <div>
              <h4 style={{ fontSize: '16px', marginBottom: '10px' }}>Top Source IPs</h4>
              {stats.logs.top_source_ips && stats.logs.top_source_ips.slice(0, 5).map((item, index) => (
                <div key={index} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '5px' }}>
                  <span style={{ fontSize: '14px' }}>{item.ip}:</span>
                  <span style={{ fontSize: '14px', fontWeight: '600' }}>{item.count}</span>
                </div>
              ))}
            </div>
            
            <div>
              <h4 style={{ fontSize: '16px', marginBottom: '10px' }}>Recent Activity</h4>
              <div style={{ fontSize: '14px', lineHeight: '1.6' }}>
                <p>Logs today: <strong>{stats.logs.logs_today || 0}</strong></p>
                <p>Logs this week: <strong>{stats.logs.logs_this_week || 0}</strong></p>
                <p>Recent executions: <strong>{stats.feedback.recent_executions || 0}</strong></p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;