import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, getRiskColor } from '../api/client';

const LEVEL_COLORS = {
  0: { bg: 'rgba(255,45,85,0.1)',  border: 'rgba(255,45,85,0.3)',  text: '#ff2d55', label: 'SL-0' },
  1: { bg: 'rgba(255,107,53,0.1)', border: 'rgba(255,107,53,0.3)', text: '#ff6b35', label: 'SL-1' },
  2: { bg: 'rgba(255,170,0,0.1)',  border: 'rgba(255,170,0,0.3)',  text: '#ffaa00', label: 'SL-2' },
  3: { bg: 'rgba(59,130,246,0.1)', border: 'rgba(59,130,246,0.3)', text: '#3b82f6', label: 'SL-3' },
  4: { bg: 'rgba(48,209,88,0.1)',  border: 'rgba(48,209,88,0.3)',  text: '#30d158', label: 'SL-4' },
};

export default function ZoneView() {
  const [zones, setZones] = useState([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    api.getZones().then(data => {
      setZones(data);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  if (loading) {
    return <div><div className="skeleton" style={{ height: 400 }} /></div>;
  }

  return (
    <div>
      <div className="page-header">
        <h2>IEC 62443 Zone Map</h2>
        <div className="page-subtitle">Virtual Zones organized by Purdue Model Security Levels</div>
      </div>

      <div className="zone-map stagger">
        {zones.map(zone => {
          const lc = LEVEL_COLORS[zone.iec_level] || LEVEL_COLORS[2];
          return (
            <div key={zone.id} className="zone-tier animate-fade-in" onClick={() => navigate(`/assets?zone=${zone.name}`)}>
              <div className="zone-tier-info">
                <div className="zone-level-badge" style={{ background: lc.bg, border: `1px solid ${lc.border}`, color: lc.text }}>
                  {lc.label}
                </div>
                <div>
                  <div className="zone-tier-name">{zone.name}</div>
                  <div className="zone-tier-desc">{zone.description}</div>
                  <div style={{ marginTop: 6, display: 'flex', gap: 8 }}>
                    <span className="tag" style={{ background: 'rgba(0,212,255,0.06)', color: '#00d4ff', border: '1px solid rgba(0,212,255,0.15)', fontSize: 10 }}>
                      VLAN {zone.vlan_id}
                    </span>
                    <span className="tag" style={{ background: 'rgba(139,92,246,0.06)', color: '#8b5cf6', border: '1px solid rgba(139,92,246,0.15)', fontSize: 10 }}>
                      {zone.ip_range}
                    </span>
                  </div>
                </div>
              </div>
              <div className="zone-tier-stats">
                <div className="zone-stat">
                  <div className="zone-stat-value" style={{ color: lc.text }}>{zone.asset_count}</div>
                  <div className="zone-stat-label">Assets</div>
                </div>
                <div className="zone-stat">
                  <div className="zone-stat-value" style={{ color: getRiskColor(zone.avg_risk) }}>{zone.avg_risk.toFixed(1)}</div>
                  <div className="zone-stat-label">Avg Risk</div>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Zone Legend */}
      <div className="card" style={{ marginTop: 24 }}>
        <div className="card-header"><div className="card-title">IEC 62443 Purdue Model Reference</div></div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
          {[
            { level: 0, name: 'Safety', desc: 'Safety Instrumented Systems (SIS)', weight: '1.0' },
            { level: 1, name: 'Process', desc: 'PLCs, RTUs, Field Devices', weight: '1.0' },
            { level: 2, name: 'Supervisory', desc: 'HMIs, SCADA, Data Acquisition', weight: '0.6' },
            { level: 3, name: 'DMZ', desc: 'Historians, EWS, Network Infra', weight: '0.4' },
            { level: 4, name: 'Enterprise', desc: 'Office IT, ERP, Email', weight: '0.2' },
          ].map(l => {
            const lc = LEVEL_COLORS[l.level];
            return (
              <div key={l.level} style={{ padding: 12, background: lc.bg, borderRadius: 8, border: `1px solid ${lc.border}`, textAlign: 'center' }}>
                <div style={{ fontWeight: 700, color: lc.text, fontSize: 13 }}>Level {l.level}</div>
                <div style={{ fontWeight: 600, color: '#f0f4ff', fontSize: 12, marginTop: 4 }}>{l.name}</div>
                <div style={{ fontSize: 10, color: '#8892b0', marginTop: 4 }}>{l.desc}</div>
                <div style={{ marginTop: 8, fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: lc.text }}>
                  Impact Weight: {l.weight}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
