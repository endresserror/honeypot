import React, { useState, useEffect } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { signatureApi, logsApi, feedbackApi } from '../services/api';

const Statistics = () => {
  const [stats, setStats] = useState({
    signatures: {},
    logs: {},
    feedback: {}
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchStatistics();
  }, []);

  const fetchStatistics = async () => {
    try {
      setLoading(true);
      setError('');

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
      setError('Failed to load statistics');
      console.error('Statistics error:', err);
    } finally {
      setLoading(false);
    }
  };

  const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884D8'];

  // Prepare data for charts
  const attackTypeData = stats.signatures.attack_type_distribution 
    ? Object.entries(stats.signatures.attack_type_distribution).map(([type, count]) => ({
        name: type.replace('_', ' '),
        value: count
      }))
    : [];

  const methodDistributionData = stats.logs.method_distribution
    ? stats.logs.method_distribution.map(item => ({
        name: item.method,
        count: item.count
      }))
    : [];

  const topSignaturesData = stats.feedback.top_signatures
    ? stats.feedback.top_signatures.slice(0, 10).map(sig => ({
        name: sig.signature_id,
        executions: sig.execution_count,
        success_rate: sig.success_rate
      }))
    : [];

  if (loading) {
    return (
      <div className="loading">
        <div className="loading-spinner"></div>
        <p>Loading statistics...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="error">
        <h3>Error</h3>
        <p>{error}</p>
        <button className="btn btn-primary" onClick={fetchStatistics}>
          Retry
        </button>
      </div>
    );
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '30px' }}>
        <h2>System Statistics</h2>
        <button className="btn btn-secondary" onClick={fetchStatistics}>
          Refresh
        </button>
      </div>

      {/* Summary Cards */}
      <div className="stats-grid" style={{ marginBottom: '40px' }}>
        <div className="stat-card">
          <div className="stat-value" style={{ color: '#3498db' }}>
            {stats.signatures.total_signatures || 0}
          </div>
          <div className="stat-label">Total Signatures</div>
          <div style={{ fontSize: '12px', color: '#6c757d', marginTop: '5px' }}>
            {stats.signatures.approved || 0} approved, {stats.signatures.pending_review || 0} pending
          </div>
        </div>
        
        <div className="stat-card">
          <div className="stat-value" style={{ color: '#e74c3c' }}>
            {stats.logs.total_logs || 0}
          </div>
          <div className="stat-label">Attack Logs</div>
          <div style={{ fontSize: '12px', color: '#6c757d', marginTop: '5px' }}>
            {stats.logs.logs_today || 0} today, {stats.logs.unprocessed_logs || 0} unprocessed
          </div>
        </div>
        
        <div className="stat-card">
          <div className="stat-value" style={{ color: '#27ae60' }}>
            {stats.feedback.overall_success_rate || 0}%
          </div>
          <div className="stat-label">Success Rate</div>
          <div style={{ fontSize: '12px', color: '#6c757d', marginTop: '5px' }}>
            {stats.feedback.successful_detections || 0} / {stats.feedback.total_executions || 0} executions
          </div>
        </div>
        
        <div className="stat-card">
          <div className="stat-value" style={{ color: '#f39c12' }}>
            {stats.feedback.recent_executions || 0}
          </div>
          <div className="stat-label">Recent Executions</div>
          <div style={{ fontSize: '12px', color: '#6c757d', marginTop: '5px' }}>
            Last 7 days
          </div>
        </div>
      </div>

      {/* Charts Row 1 */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginBottom: '30px' }}>
        {/* Attack Type Distribution */}
        <div className="card">
          <div className="card-header">Attack Type Distribution</div>
          <div className="card-body">
            {attackTypeData.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={attackTypeData}
                    cx="50%"
                    cy="50%"
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  >
                    {attackTypeData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ textAlign: 'center', padding: '50px', color: '#6c757d' }}>
                No data available
              </div>
            )}
          </div>
        </div>

        {/* HTTP Method Distribution */}
        <div className="card">
          <div className="card-header">HTTP Method Distribution</div>
          <div className="card-body">
            {methodDistributionData.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={methodDistributionData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis />
                  <Tooltip />
                  <Bar dataKey="count" fill="#3498db" />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ textAlign: 'center', padding: '50px', color: '#6c757d' }}>
                No data available
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Top Performing Signatures */}
      <div className="card" style={{ marginBottom: '30px' }}>
        <div className="card-header">Top Performing Signatures</div>
        <div className="card-body">
          {topSignaturesData.length > 0 ? (
            <ResponsiveContainer width="100%" height={400}>
              <BarChart data={topSignaturesData} layout="horizontal">
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis type="number" />
                <YAxis dataKey="name" type="category" width={80} />
                <Tooltip />
                <Bar dataKey="executions" fill="#27ae60" name="Executions" />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ textAlign: 'center', padding: '50px', color: '#6c757d' }}>
              No execution data available
            </div>
          )}
        </div>
      </div>

      {/* Top Source IPs */}
      <div className="card" style={{ marginBottom: '30px' }}>
        <div className="card-header">Top Attack Source IPs</div>
        <div className="card-body">
          {stats.logs.top_source_ips && stats.logs.top_source_ips.length > 0 ? (
            <div style={{ overflowX: 'auto' }}>
              <table className="table">
                <thead>
                  <tr>
                    <th>Rank</th>
                    <th>IP Address</th>
                    <th>Attack Count</th>
                    <th>Percentage</th>
                  </tr>
                </thead>
                <tbody>
                  {stats.logs.top_source_ips.slice(0, 10).map((item, index) => {
                    const percentage = ((item.count / stats.logs.total_logs) * 100).toFixed(1);
                    return (
                      <tr key={item.ip}>
                        <td>{index + 1}</td>
                        <td><code>{item.ip}</code></td>
                        <td>{item.count}</td>
                        <td>{percentage}%</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <div style={{ textAlign: 'center', padding: '50px', color: '#6c757d' }}>
              No source IP data available
            </div>
          )}
        </div>
      </div>

      {/* Scanner Instance Statistics */}
      {stats.feedback.scanner_instances && stats.feedback.scanner_instances.length > 0 && (
        <div className="card">
          <div className="card-header">Scanner Instance Activity</div>
          <div className="card-body">
            <div style={{ overflowX: 'auto' }}>
              <table className="table">
                <thead>
                  <tr>
                    <th>Instance ID</th>
                    <th>Executions</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {stats.feedback.scanner_instances.map((instance) => (
                    <tr key={instance.instance_id}>
                      <td><code>{instance.instance_id || 'Unknown'}</code></td>
                      <td>{instance.execution_count}</td>
                      <td>
                        <span className="badge badge-success">Active</span>
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

export default Statistics;