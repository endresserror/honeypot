import React from 'react';
import { NavLink } from 'react-router-dom';

const Sidebar = () => {
  const menuItems = [
    {
      path: '/',
      label: 'Dashboard',
      icon: '▸'
    },
    {
      path: '/review',
      label: 'Signature Review',
      icon: '●'
    },
    {
      path: '/signatures',
      label: 'Approved Signatures',
      icon: '■'
    },
    {
      path: '/logs',
      label: 'Attack Logs',
      icon: '◆'
    },
    {
      path: '/statistics',
      label: 'Statistics',
      icon: '▲'
    }
  ];

  return (
    <div className="sidebar">
      <div style={{ marginBottom: '30px' }}>
        <h3 style={{ color: '#ecf0f1', fontSize: '16px', marginBottom: '10px' }}>
          MCP Server Dashboard
        </h3>
        <p style={{ color: '#bdc3c7', fontSize: '12px', lineHeight: '1.4' }}>
          Manage vulnerability detection signatures and monitor honeypot activity
        </p>
      </div>

      <nav>
        <ul className="nav-menu">
          {menuItems.map((item) => (
            <li key={item.path} className="nav-item">
              <NavLink
                to={item.path}
                className={({ isActive }) =>
                  `nav-link ${isActive ? 'active' : ''}`
                }
                end={item.path === '/'}
              >
                <span style={{ marginRight: '10px' }}>{item.icon}</span>
                {item.label}
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>

      <div style={{ marginTop: 'auto', paddingTop: '20px', borderTop: '1px solid #34495e' }}>
        <div style={{ fontSize: '12px', color: '#bdc3c7' }}>
          <p style={{ marginBottom: '5px' }}>Version 1.0.0</p>
          <p>Research Tool</p>
        </div>
      </div>
    </div>
  );
};

export default Sidebar;