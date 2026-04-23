import { NavLink } from 'react-router-dom';

const NAV_ITEMS = [
  { path: '/',             icon: '◉', label: 'Risk Overview' },
  { path: '/assets',       icon: '⬡', label: 'Asset Explorer' },
  { path: '/zones',        icon: '◫', label: 'Zone Map' },
];

const NAV_SECONDARY = [
  { path: '/vulnerabilities', icon: '🛡', label: 'Vulnerabilities' },
  { path: '/compliance',      icon: '📊', label: 'Compliance Reports' },
];

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div className="logo-icon">C</div>
        <div>
          <h1>Claroty xDome</h1>
          <div className="logo-subtitle">OT Security Platform</div>
        </div>
      </div>

      <nav className="sidebar-nav">
        <div className="nav-section-title">Main</div>
        {NAV_ITEMS.map(item => (
          <NavLink
            key={item.path}
            to={item.path}
            end={item.path === '/'}
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            <span className="nav-icon">{item.icon}</span>
            {item.label}
          </NavLink>
        ))}

        <div className="nav-section-title">Intelligence</div>
        {NAV_SECONDARY.map(item => (
          <NavLink
            key={item.path}
            to={item.path}
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            <span className="nav-icon">{item.icon}</span>
            {item.label}
          </NavLink>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div style={{ marginBottom: 4, color: '#8892b0', fontSize: 11 }}>IEC 62443 · NIST 800-82</div>
        <div style={{ color: '#4a5578', fontSize: 10 }}>MITRE ATT&CK for ICS</div>
        <div style={{ marginTop: 12 }}>
          <NavLink to="/login" style={{ color: '#ff5a5a', fontSize: '12px', textDecoration: 'none' }}>Change User Role</NavLink>
        </div>
      </div>
    </aside>
  );
}
