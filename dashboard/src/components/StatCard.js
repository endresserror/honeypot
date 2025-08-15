import React from 'react';
import { Link } from 'react-router-dom';

const StatCard = ({ title, value, subtitle, color, linkTo }) => {
  const CardContent = () => (
    <div className="stat-card" style={{ borderTop: `4px solid ${color}` }}>
      <div className="stat-value" style={{ color }}>{value}</div>
      <div className="stat-label">{title}</div>
      {subtitle && (
        <div style={{ fontSize: '12px', color: '#6c757d', marginTop: '5px' }}>
          {subtitle}
        </div>
      )}
    </div>
  );

  if (linkTo) {
    return (
      <Link to={linkTo} style={{ textDecoration: 'none', color: 'inherit' }}>
        <CardContent />
      </Link>
    );
  }

  return <CardContent />;
};

export default StatCard;