import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, getRiskLevel, getRiskColor } from '../api/client';

export default function AssetExplorer() {
  const [assets, setAssets] = useState([]);
  const [sortBy, setSortBy] = useState('risk');
  const [filterZone, setFilterZone] = useState('');
  const [filterType, setFilterType] = useState('');
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [isDiscovering, setIsDiscovering] = useState(false);
  const navigate = useNavigate();
  const discoveryTimeoutRef = useRef(null);

  const handleStartStop = async () => {
    try {
      if (isDiscovering) {
        await api.stopDiscovery();
        setIsDiscovering(false);
        if (discoveryTimeoutRef.current) {
          clearTimeout(discoveryTimeoutRef.current);
          discoveryTimeoutRef.current = null;
        }
      } else {
        setIsDiscovering(true);
        const res = await api.startDiscovery();
        
        if (res.count === 0) {
          alert('No devices found in the database to discover.');
          setIsDiscovering(false);
        } else if (res.count > 0) {
          // SNMP Poller takes ~4 seconds per device (4 OIDs * 1 second sleep)
          const estimatedTimeMs = res.count * 4000 + 1000;
          discoveryTimeoutRef.current = setTimeout(() => {
            setIsDiscovering(false);
            discoveryTimeoutRef.current = null;
            // Refresh assets to show new firmware/hostnames
            api.getAssets(sortBy).then(data => {
              setAssets(data);
              alert(`Discovery complete! Successfully scanned ${res.count} assets.`);
            });
          }, estimatedTimeMs);
        }
      }
    } catch (e) {
      console.error(e);
      setIsDiscovering(false);
      if (discoveryTimeoutRef.current) {
        clearTimeout(discoveryTimeoutRef.current);
        discoveryTimeoutRef.current = null;
      }
    }
  };

  const handleReset = async () => {
    if (window.confirm('Are you sure you want to reset the dashboard and clear all data?')) {
      try {
        await api.clearDiscovery();
        setAssets([]);
        setIsDiscovering(false);
        if (discoveryTimeoutRef.current) {
          clearTimeout(discoveryTimeoutRef.current);
          discoveryTimeoutRef.current = null;
        }
      } catch (e) {
        console.error(e);
      }
    }
  };

  useEffect(() => {
    return () => {
      if (discoveryTimeoutRef.current) {
        clearTimeout(discoveryTimeoutRef.current);
      }
    };
  }, []);

  useEffect(() => {
    api.getAssets(sortBy).then(data => {
      setAssets(data);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [sortBy]);



  const filtered = assets.filter(a => {
    if (filterZone && a.zone_name !== filterZone) return false;
    if (filterType && a.device_type !== filterType) return false;
    if (search) {
      const q = search.toLowerCase();
      return a.ip.includes(q) || a.vendor.toLowerCase().includes(q) ||
             a.hostname.toLowerCase().includes(q) || a.device_type.toLowerCase().includes(q);
    }
    return true;
  });

  const zones = [...new Set(assets.map(a => a.zone_name).filter(Boolean))];
  const types = [...new Set(assets.map(a => a.device_type).filter(Boolean))];

  return (
    <div>
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2>Asset Explorer</h2>
          <div className="page-subtitle">All discovered OT/IT assets with risk assessment</div>
        </div>
        <div style={{ display: 'flex', gap: '12px' }}>
          <button 
            onClick={handleStartStop}
            style={{
              background: isDiscovering ? '#3a4468' : 'var(--success, #30d158)',
              color: '#fff', padding: '8px 16px', borderRadius: '8px', border: 'none',
              cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '8px',
              fontWeight: 500, fontSize: '14px'
            }}
          >
            <span style={{ fontSize: '18px' }}>{isDiscovering ? '⏹' : '▶'}</span>
            {isDiscovering ? 'Stop Discovery' : 'Start Discovery'}
          </button>
          <button 
            onClick={handleReset}
            style={{
              background: 'var(--danger, #ff2d55)', color: '#fff', padding: '8px 16px',
              borderRadius: '8px', border: 'none', cursor: 'pointer', display: 'flex',
              alignItems: 'center', gap: '8px', fontWeight: 500, fontSize: '14px'
            }}
          >
            <span style={{ fontSize: '18px' }}>🗑</span>
            Delete All Assets
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="card" style={{ marginBottom: 20, padding: '16px 20px' }}>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          <input
            type="text"
            placeholder="Search IP, vendor, hostname..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{
              flex: 1, minWidth: 200, padding: '8px 14px', borderRadius: 8,
              border: '1px solid var(--border-subtle)', background: 'var(--bg-elevated)',
              color: 'var(--text-primary)', fontSize: 13, outline: 'none',
            }}
          />
          <select value={filterZone} onChange={e => setFilterZone(e.target.value)}
            style={{
              padding: '8px 14px', borderRadius: 8, border: '1px solid var(--border-subtle)',
              background: 'var(--bg-elevated)', color: 'var(--text-primary)', fontSize: 13,
            }}>
            <option value="">All Zones</option>
            {zones.map(z => <option key={z} value={z}>{z}</option>)}
          </select>
          <select value={filterType} onChange={e => setFilterType(e.target.value)}
            style={{
              padding: '8px 14px', borderRadius: 8, border: '1px solid var(--border-subtle)',
              background: 'var(--bg-elevated)', color: 'var(--text-primary)', fontSize: 13,
            }}>
            <option value="">All Types</option>
            {types.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
          <div style={{ fontSize: 12, color: '#4a5578' }}>{filtered.length} assets</div>
        </div>
      </div>

      {/* Table */}
      <div className="card animate-fade-in">
        {loading ? (
          <div className="skeleton" style={{ height: 400 }} />
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th onClick={() => setSortBy('ip')}>IP Address</th>
                <th>Vendor</th>
                <th>Type</th>
                <th>Purdue Level</th>
                <th>Zone</th>
                <th>Protocol Security</th>
                <th>Protocols</th>
                <th>OS Fingerprint</th>
                <th>Firmware Version</th>
                <th>CVEs</th>
                <th onClick={() => setSortBy('risk')}>Risk Score ↕</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(asset => (
                <tr key={asset.id} onClick={() => navigate(`/assets/${asset.id}`)}>
                  <td>
                    <div style={{ fontWeight: 600, fontFamily: "'JetBrains Mono', monospace", fontSize: 13 }}>{asset.ip}</div>
                    <div style={{ fontSize: 11, color: '#4a5578' }}>{asset.hostname}</div>
                  </td>
                  <td>
                    <div className="vendor-cell">
                      <div className="vendor-dot" style={{ background: getRiskColor(asset.current_risk_score) }} />
                      {asset.vendor}
                    </div>
                  </td>
                  <td style={{ textTransform: 'uppercase', fontSize: 11, letterSpacing: 0.5, color: '#8892b0' }}>{asset.device_type}</td>
                  <td style={{ fontFamily: "'JetBrains Mono', monospace", fontWeight: 600, color: '#00d4ff' }}>L{asset.purdue_level != null ? asset.purdue_level : 3}</td>
                  <td style={{ color: '#8892b0' }}>{asset.zone_name}</td>
                  <td>
                    <span className={`tag tag-${asset.protocol_security}`}>{asset.protocol_security}</span>
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                      {asset.protocols ? asset.protocols.split(',').slice(0, 3).map(p => (
                        <span key={p} className="tag tag-secure" style={{ fontSize: 10, padding: '2px 6px', textTransform: 'uppercase' }}>{p.trim()}</span>
                      )) : <span className="tag tag-unknown">none</span>}
                      {asset.protocols && asset.protocols.split(',').length > 3 && (
                        <span className="tag tag-mixed" style={{ fontSize: 10, padding: '2px 6px' }}>+{asset.protocols.split(',').length - 3}</span>
                      )}
                    </div>
                  </td>
                  <td>
                    {asset.os_type && asset.os_type !== 'unknown' ? (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                        <span style={{ textTransform: 'capitalize', fontSize: 12, fontWeight: 500 }}>{asset.os_type}</span>
                        <div style={{ fontSize: 10, fontFamily: "'JetBrains Mono', monospace", color: (asset.os_confidence || 0) >= 0.70 ? '#30d158' : (asset.os_confidence || 0) >= 0.50 ? '#ffaa00' : '#ff2d55' }}>
                          {((asset.os_confidence || 0) * 100).toFixed(1)}% Conf
                        </div>
                      </div>
                    ) : (
                      <span style={{ color: '#4a5578' }}>—</span>
                    )}
                  </td>
                  <td>
                    <div style={{ fontSize: 11, color: '#8892b0' }}>{asset.firmware || '—'}</div>
                  </td>
                  <td style={{ fontFamily: "'JetBrains Mono', monospace", fontWeight: 600 }}>{asset.vulnerability_count}</td>
                  <td>
                    <span className={`risk-badge ${getRiskLevel(asset.current_risk_score)}`}>
                      {asset.current_risk_score.toFixed(1)}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
