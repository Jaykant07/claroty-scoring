import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, getRiskLevel, getRiskColor, formatTime } from '../api/client';

/* ── KPI Card ──────────────────────────────────────────────────────────────── */
function KpiCard({ label, value, detail, color }) {
  return (
    <div className="kpi-card animate-fade-in" style={{ '--kpi-color': color }}>
      <div className="kpi-label">{label}</div>
      <div className="kpi-value" style={{ color }}>{value}</div>
      {detail && <div className="kpi-detail">{detail}</div>}
    </div>
  );
}

/* ── Heatmap ───────────────────────────────────────────────────────────────── */
function RiskHeatmap({ data }) {
  // Group by zone
  const zones = {};
  data.forEach(cell => {
    if (!zones[cell.zone_name]) zones[cell.zone_name] = { iec_level: cell.iec_level, cells: {} };
    zones[cell.zone_name].cells[cell.severity] = cell;
  });

  const severities = ['critical', 'high', 'medium', 'low'];
  const sortedZones = Object.entries(zones).sort((a, b) => a[1].iec_level - b[1].iec_level);

  return (
    <div className="heatmap-grid">
      <div className="heatmap-header">
        <span>Zone / Level</span>
        {severities.map(s => <span key={s}>{s}</span>)}
      </div>
      {sortedZones.map(([name, { cells }]) => (
        <div className="heatmap-row" key={name}>
          <div className="heatmap-label">{name}</div>
          {severities.map(sev => {
            const cell = cells[sev];
            const count = cell?.count || 0;
            return (
              <div
                key={sev}
                className={`heatmap-cell ${count > 0 ? sev : 'empty'}`}
                title={count > 0 ? `${count} assets (avg: ${cell.avg_score})` : 'No assets'}
              >
                {count > 0 ? count : '·'}
              </div>
            );
          })}
        </div>
      ))}
    </div>
  );
}

/* ── Risk Distribution Ring ────────────────────────────────────────────────── */
function RiskRing({ summary }) {
  const total = summary.total_assets || 1;
  const segments = [
    { label: 'Critical', count: summary.critical_risk_count, color: '#ff2d55' },
    { label: 'High',     count: summary.high_risk_count,     color: '#ff6b35' },
    { label: 'Medium',   count: summary.medium_risk_count,   color: '#ffaa00' },
    { label: 'Low',      count: summary.low_risk_count,      color: '#30d158' },
  ];

  let offset = 0;
  const circumference = 2 * Math.PI * 60;

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 32 }}>
      <div className="risk-gauge">
        <svg width="160" height="160" viewBox="0 0 160 160">
          <circle cx="80" cy="80" r="60" fill="none" stroke="rgba(136,146,176,0.08)" strokeWidth="14" />
          {segments.map((seg, i) => {
            const pct = seg.count / total;
            const dashLen = circumference * pct;
            const dashOffset = -offset;
            offset += dashLen;
            return (
              <circle
                key={i}
                cx="80" cy="80" r="60"
                fill="none"
                stroke={seg.color}
                strokeWidth="14"
                strokeDasharray={`${dashLen} ${circumference - dashLen}`}
                strokeDashoffset={dashOffset}
                strokeLinecap="round"
                style={{ transition: 'stroke-dasharray 1s ease' }}
              />
            );
          })}
        </svg>
        <div className="risk-gauge-value">
          <div className="risk-gauge-number" style={{ color: getRiskColor(summary.average_risk_score) }}>
            {Math.round(summary.average_risk_score)}
          </div>
          <div className="risk-gauge-label">Avg Risk</div>
        </div>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {segments.map((seg, i) => (
          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ width: 10, height: 10, borderRadius: 3, background: seg.color }} />
            <span style={{ fontSize: 12, color: '#8892b0', width: 60 }}>{seg.label}</span>
            <span style={{ fontSize: 14, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", color: seg.color }}>{seg.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ── Activity Feed ─────────────────────────────────────────────────────────── */
function ActivityFeed({ events }) {
  return (
    <div className="activity-feed">
      {events.map((event, i) => (
        <div key={i} className={`activity-item ${event.severity}`}>
          <div className={`activity-dot ${event.severity}`} />
          <div style={{ flex: 1 }}>
            <div className="activity-text">{event.message}</div>
          </div>
          <div className="activity-time">{formatTime(event.timestamp)}</div>
        </div>
      ))}
      {events.length === 0 && (
        <div style={{ padding: 20, textAlign: 'center', color: '#4a5578', fontSize: 13 }}>
          No recent activity
        </div>
      )}
    </div>
  );
}

/* ── Top Risk Assets ───────────────────────────────────────────────────────── */
function TopRiskAssets({ assets }) {
  const navigate = useNavigate();
  const top = assets.slice(0, 8);

  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>Asset</th>
          <th>Vendor</th>
          <th>Zone</th>
          <th>Risk Score</th>
        </tr>
      </thead>
      <tbody>
        {top.map(asset => (
          <tr key={asset.id} onClick={() => navigate(`/assets/${asset.id}`)}>
            <td>
              <div style={{ fontWeight: 600 }}>{asset.ip}</div>
              <div style={{ fontSize: 11, color: '#4a5578' }}>{asset.device_type}</div>
            </td>
            <td>
              <div className="vendor-cell">
                <div className="vendor-dot" style={{ background: getRiskColor(asset.current_risk_score) }} />
                {asset.vendor}
              </div>
            </td>
            <td style={{ color: '#8892b0' }}>{asset.zone_name}</td>
            <td>
              <span className={`risk-badge ${getRiskLevel(asset.current_risk_score)}`}>
                {asset.current_risk_score.toFixed(1)}
              </span>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/* ── Main Dashboard Page ───────────────────────────────────────────────────── */
export default function Dashboard() {
  const [summary, setSummary] = useState(null);
  const [heatmap, setHeatmap] = useState([]);
  const [activity, setActivity] = useState([]);
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      api.getSummary(),
      api.getHeatmap(),
      api.getActivity(20),
      api.getAssets('risk'),
    ]).then(([s, h, a, as]) => {
      setSummary(s);
      setHeatmap(h);
      setActivity(a);
      setAssets(as);
      setLoading(false);
    }).catch(err => {
      console.error('Dashboard load error:', err);
      setLoading(false);
    });

    // Auto-refresh every 60s
    const timer = setInterval(() => {
      api.getSummary().then(setSummary).catch(() => {});
      api.getActivity(20).then(setActivity).catch(() => {});
    }, 60000);
    return () => clearInterval(timer);
  }, []);

  if (loading || !summary) {
    return (
      <div>
        <div className="page-header">
          <h2>Risk Overview</h2>
          <div className="page-subtitle">Claroty OT Security — Real-time Risk Dashboard</div>
        </div>
        <div className="kpi-grid stagger">
          {[1, 2, 3, 4, 5].map(i => (
            <div key={i} className="kpi-card"><div className="skeleton" style={{ height: 60 }} /></div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="page-header">
        <h2>Risk Overview</h2>
        <div className="page-subtitle">IEC 62443-Compliant OT Risk Assessment — {summary.total_assets} Assets Monitored</div>
      </div>

      {/* KPI Row */}
      <div className="kpi-grid stagger">
        <KpiCard label="Total Assets" value={summary.total_assets} detail="Across all IEC 62443 zones" color="var(--accent-cyan)" />
        <KpiCard label="Critical Risk" value={summary.critical_risk_count} detail="Score ≥ 75" color="var(--risk-critical)" />
        <KpiCard label="Active Anomalies" value={summary.active_anomalies} detail="Transformer-detected threats" color="var(--risk-high)" />
        <KpiCard label="Total CVEs" value={summary.total_vulnerabilities} detail="NVD + EPSS enriched" color="var(--accent-purple)" />
        <KpiCard label="EOL Assets" value={summary.eol_assets} detail="End-of-Life firmware" color="var(--risk-medium)" />
      </div>

      {/* Main Grid */}
      <div className="grid-2col" style={{ marginBottom: 24 }}>
        {/* Heatmap */}
        <div className="card animate-fade-in">
          <div className="card-header">
            <div className="card-title">Risk Heatmap — Zone × Severity</div>
          </div>
          <RiskHeatmap data={heatmap} />
        </div>

        {/* Risk Distribution */}
        <div className="card animate-fade-in">
          <div className="card-header">
            <div className="card-title">Risk Distribution</div>
          </div>
          <div style={{ display: 'flex', justifyContent: 'center', padding: '20px 0' }}>
            <RiskRing summary={summary} />
          </div>
          <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: 16, marginTop: 16, display: 'flex', justifyContent: 'space-around' }}>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: 11, color: '#4a5578', textTransform: 'uppercase', letterSpacing: 1 }}>Cross-Zone Events</div>
              <div style={{ fontSize: 22, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", color: '#ffaa00' }}>{summary.cross_zone_events}</div>
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: 11, color: '#4a5578', textTransform: 'uppercase', letterSpacing: 1 }}>Avg Risk Score</div>
              <div style={{ fontSize: 22, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", color: getRiskColor(summary.average_risk_score) }}>{summary.average_risk_score.toFixed(1)}</div>
            </div>
          </div>
        </div>
      </div>

      {/* Bottom Grid */}
      <div className="grid-2col">
        {/* Top Risk Assets */}
        <div className="card animate-fade-in">
          <div className="card-header">
            <div className="card-title">Highest Risk Assets</div>
          </div>
          <TopRiskAssets assets={assets} />
        </div>

        {/* Activity Feed */}
        <div className="card animate-fade-in">
          <div className="card-header">
            <div className="card-title">Live Activity Feed</div>
            <div style={{ fontSize: 11, color: '#4a5578' }}>Auto-refresh 60s</div>
          </div>
          <ActivityFeed events={activity} />
        </div>
      </div>
    </div>
  );
}
