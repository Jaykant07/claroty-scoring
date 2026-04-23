import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { api, getRiskLevel, getRiskColor } from '../api/client';

/* ── Risk Gauge ────────────────────────────────────────────────────────────── */
function RiskGauge({ score }) {
  const color = getRiskColor(score);
  const level = getRiskLevel(score);
  const circumference = 2 * Math.PI * 60;
  const dashLen = (score / 100) * circumference;

  return (
    <div className="risk-gauge">
      <svg width="160" height="160" viewBox="0 0 160 160">
        <circle cx="80" cy="80" r="60" fill="none" stroke="rgba(136,146,176,0.08)" strokeWidth="12" />
        <circle
          cx="80" cy="80" r="60" fill="none"
          stroke={color} strokeWidth="12"
          strokeDasharray={`${dashLen} ${circumference - dashLen}`}
          strokeLinecap="round"
          style={{ transition: 'stroke-dasharray 1s ease' }}
        />
      </svg>
      <div className="risk-gauge-value">
        <div className="risk-gauge-number" style={{ color }}>{score.toFixed(1)}</div>
        <div className="risk-gauge-label">{level}</div>
      </div>
    </div>
  );
}

/* ── Breakdown Bar ─────────────────────────────────────────────────────────── */
function BreakdownBar({ label, value, maxValue = 1, color }) {
  const pct = Math.min((value / maxValue) * 100, 100);
  return (
    <div className="breakdown-item">
      <div className="breakdown-header">
        <span className="breakdown-label">{label}</span>
        <span className="breakdown-value" style={{ color }}>{(value * 100).toFixed(1)}%</span>
      </div>
      <div className="breakdown-bar">
        <div className="breakdown-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
    </div>
  );
}

/* ── Sparkline ─────────────────────────────────────────────────────────────── */
function Sparkline({ data, width = 300, height = 60 }) {
  if (!data || data.length < 2) return null;
  const scores = data.map(d => d.final_score);
  const min = Math.min(...scores);
  const max = Math.max(...scores) || 1;
  const range = max - min || 1;

  const points = scores.map((s, i) => {
    const x = (i / (scores.length - 1)) * width;
    const y = height - ((s - min) / range) * (height - 10) - 5;
    return `${x},${y}`;
  }).join(' ');

  const lastScore = scores[scores.length - 1];
  const color = getRiskColor(lastScore);

  return (
    <svg width={width} height={height} style={{ overflow: 'visible' }}>
      <defs>
        <linearGradient id="spark-grad" x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.3" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <polyline fill="none" stroke={color} strokeWidth="2" points={points} />
      <polygon
        fill="url(#spark-grad)"
        points={`0,${height} ${points} ${width},${height}`}
      />
    </svg>
  );
}

/* ── Main Asset Detail Page ────────────────────────────────────────────────── */
export default function AssetDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [asset, setAsset] = useState(null);
  const [loading, setLoading] = useState(true);
  const role = localStorage.getItem("claroty_role") || "operator";

  useEffect(() => {
    api.getAssetDetail(id).then(data => {
      setAsset(data);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [id]);

  if (loading || !asset) {
    return <div><div className="skeleton" style={{ height: 600 }} /></div>;
  }

  const bd = asset.risk_breakdown;

  return (
    <div>
      <button className="back-button" onClick={() => navigate(-1)}>← Back</button>

      {/* Header */}
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <h2>{asset.ip}</h2>
          <span className={`risk-badge ${getRiskLevel(asset.current_risk_score)}`}>
            {asset.current_risk_score.toFixed(1)}
          </span>
          {asset.eol_status && <span className="tag tag-eol">EOL</span>}
        </div>
        <div className="page-subtitle">{asset.vendor} · {asset.device_type.toUpperCase()} · {asset.zone_name} (IEC Level {asset.iec_level})</div>
        
        {asset.device_type === "plc" && (
          <div style={{ marginTop: 12, padding: "10px", background: "#161b22", borderRadius: "8px", border: "1px solid #30363d", display: "inline-block" }}>
            <span style={{color: "#8b949e", marginRight: "10px", fontSize: "12px", textTransform: "uppercase"}}>Controller Mode</span>
            <select disabled={role !== "admin"} style={{ background: "#0d1117", color: "#c9d1d9", border: "1px solid #30363d", padding: "4px 8px", borderRadius: "4px" }}>
              <option value="run">Run</option>
              <option value="program">Program</option>
              <option value="remote_run">Remote Run</option>
            </select>
            {role !== "admin" && <span style={{marginLeft: "10px", fontSize: "11px", color: "#ff5a5a"}}>Admin privileges required</span>}
          </div>
        )}
      </div>

      {/* Device Info + Risk Gauge */}
      <div className="grid-2col" style={{ marginBottom: 24 }}>
        <div className="card animate-fade-in">
          <div className="card-header"><div className="card-title">Device Profile</div></div>
          <div className="detail-grid">
            <div className="detail-item"><div className="detail-label">IP Address</div><div className="detail-value">{asset.ip}</div></div>
            <div className="detail-item"><div className="detail-label">MAC Address</div><div className="detail-value">{asset.mac}</div></div>
            <div className="detail-item"><div className="detail-label">Hostname</div><div className="detail-value">{asset.hostname}</div></div>
            <div className="detail-item"><div className="detail-label">Vendor</div><div className="detail-value">{asset.vendor}</div></div>
            <div className="detail-item"><div className="detail-label">OS Type</div><div className="detail-value" style={{ textTransform: 'capitalize' }}>{asset.os_type && asset.os_type !== 'unknown' ? asset.os_type : '—'}</div></div>
            <div className="detail-item">
              <div className="detail-label">Fingerprint Match</div>
              <div className="detail-value" style={{ color: (asset.os_confidence || 0) >= 0.7 ? '#30d158' : (asset.os_confidence || 0) >= 0.5 ? '#ffaa00' : 'inherit' }}>
                {asset.os_confidence ? (asset.os_confidence * 100).toFixed(1) + '%' : '—'}
              </div>
            </div>
            <div className="detail-item"><div className="detail-label">Firmware</div><div className="detail-value" style={{ fontSize: 11 }}>{asset.firmware}</div></div>
            <div className="detail-item"><div className="detail-label">CPE</div><div className="detail-value" style={{ fontSize: 10 }}>{asset.cpe}</div></div>
            <div className="detail-item"><div className="detail-label">Serial</div><div className="detail-value">{asset.serial}</div></div>
            <div className="detail-item">
              <div className="detail-label">Protocols</div>
              <div className="detail-value" style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                {asset.protocols ? asset.protocols.split(',').map(p => (
                  <span key={p} className="tag tag-secure" style={{ fontSize: 10, padding: '2px 6px' }}>{p.trim()}</span>
                )) : <span className="tag tag-unknown">none</span>}
              </div>
            </div>
            {asset.cpu_load != null && <div className="detail-item"><div className="detail-label">CPU Load</div><div className="detail-value">{asset.cpu_load}%</div></div>}
            {asset.memory_pct != null && <div className="detail-item"><div className="detail-label">Memory</div><div className="detail-value">{asset.memory_pct}%</div></div>}
          </div>
        </div>

        <div className="card animate-fade-in">
          <div className="card-header"><div className="card-title">Risk Score Breakdown</div></div>
          {bd ? (
            <div>
              <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 20 }}>
                <RiskGauge score={bd.final_score} />
              </div>
              <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: 16 }}>
                <div style={{ fontSize: 11, color: '#4a5578', marginBottom: 12, fontWeight: 600, letterSpacing: 1, textTransform: 'uppercase' }}>Formula Dimensions</div>
                <BreakdownBar label="Vulnerability (V) [CVSS × KEV]" value={bd.vulnerability / 10} maxValue={1} color="#ff2d55" />
                <BreakdownBar label="Accessibility (A) [Network Exposure]" value={bd.accessibility / 1} maxValue={1} color="#ff6b35" />
                <BreakdownBar label="Infection (I) [Exposed Services]" value={bd.infection / 100} maxValue={1} color="#eab308" />
                <BreakdownBar label="Threat (T) [Active Anomalies]" value={bd.threat / 100} maxValue={1} color="#ef4444" />
                <BreakdownBar label="Criticality (C) [Override/Category]" value={bd.criticality / 10} maxValue={1} color="#8b5cf6" />
              </div>
              <div style={{ marginTop: 16, padding: '12px 16px', background: 'rgba(0,212,255,0.04)', borderRadius: 8, fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: '#8892b0' }}>
                <div style={{ marginBottom: 4 }}>
                  <span style={{ color: '#8b5cf6' }}>C</span> × [ (
                  <span style={{ color: '#ff2d55' }}>V</span> × <span style={{ color: '#ff6b35' }}>A</span> ) + (
                  <span style={{ color: '#eab308' }}>I</span> + <span style={{ color: '#ef4444' }}>T</span> ) ] / 10
                </div>
                R_raw = {bd.criticality.toFixed(1)} × [ ({bd.vulnerability.toFixed(2)} × {bd.accessibility.toFixed(2)}) + ({bd.infection.toFixed(1)} + {bd.threat.toFixed(1)}) ] / 10
                <br />
                <strong style={{ color: getRiskColor(bd.final_score), display: 'block', marginTop: 8 }}>Risk = min(100.0, R_raw) = {bd.final_score.toFixed(1)}</strong>
              </div>
            </div>
          ) : (
            <div className="empty-state"><p>No risk data available yet</p></div>
          )}
        </div>
      </div>

      {/* Risk History */}
      {asset.risk_history?.length > 0 && (
        <div className="card animate-fade-in" style={{ marginBottom: 24 }}>
          <div className="card-header"><div className="card-title">Risk Score Trend</div></div>
          <Sparkline data={asset.risk_history} width={700} height={80} />
        </div>
      )}

      {/* Vulnerabilities + Anomalies */}
      <div className="grid-2col" style={{ marginBottom: 24 }}>
        <div className="card animate-fade-in">
          <div className="card-header">
            <div className="card-title">Vulnerabilities ({asset.vulnerabilities?.length || 0})</div>
          </div>
          {asset.vulnerabilities?.length > 0 ? (
            <table className="data-table">
              <thead>
                <tr><th>CVE ID</th><th>CVSS</th><th>EPSS</th><th>Severity</th><th>KEV</th></tr>
              </thead>
              <tbody>
                {asset.vulnerabilities.map(v => (
                  <tr key={v.id}>
                    <td style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, fontWeight: 600 }}>{v.cve_id}</td>
                    <td><span className={`risk-badge ${getRiskLevel(v.cvss_score * 10)}`}>{v.cvss_score.toFixed(1)}</span></td>
                    <td style={{ fontFamily: "'JetBrains Mono', monospace" }}>{(v.epss_score * 100).toFixed(1)}%</td>
                    <td style={{ textTransform: 'uppercase', fontSize: 11 }}>{v.severity}</td>
                    <td>{v.is_kev ? <span className="tag tag-kev">KEV</span> : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="empty-state"><p>No CVEs associated with this asset</p></div>
          )}
        </div>

        <div className="card animate-fade-in">
          <div className="card-header">
            <div className="card-title">Anomalies ({asset.anomalies?.length || 0})</div>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {asset.anomalies?.map(a => (
              <div key={a.id} className={`anomaly-card ${a.threat_score >= 0.7 ? 'critical' : a.threat_score >= 0.4 ? 'high' : 'medium'}`}>
                <div className="anomaly-header">
                  <span className="anomaly-attack-id">{a.attack_id}</span>
                  <span className="anomaly-type">{a.anomaly_type.replace(/_/g, ' ')}</span>
                  {a.mitre_tactic && (
                    <span style={{ fontSize: 11, padding: '2px 8px', background: 'rgba(0,212,255,0.1)', color: '#00d4ff', borderRadius: 12, border: '1px solid rgba(0,212,255,0.2)' }}>
                      Tactic: {a.mitre_tactic}
                    </span>
                  )}
                </div>
                <div className="anomaly-desc">{a.description}</div>
                <div className="anomaly-meta">
                  <span>ATT&CK: {a.attack_name}</span>
                  <span>Score: {(a.threat_score * 100).toFixed(0)}%</span>
                </div>
              </div>
            ))}
            {(!asset.anomalies || asset.anomalies.length === 0) && (
              <div className="empty-state"><p>No active anomalies</p></div>
            )}
          </div>
        </div>
      </div>

      {/* Compensating Controls */}
      {asset.compensating_controls?.length > 0 && (
        <div className="card animate-fade-in">
          <div className="card-header"><div className="card-title">Compensating Controls (IEC 62443 Conduits)</div></div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {asset.compensating_controls.map(c => (
              <div key={c.id} style={{ display: 'flex', alignItems: 'center', gap: 16, padding: '10px 14px', background: 'rgba(48,209,88,0.04)', borderRadius: 8, border: '1px solid rgba(48,209,88,0.1)' }}>
                <span style={{ fontSize: 20 }}>🛡</span>
                <div style={{ flex: 1 }}>
                  <div style={{ fontWeight: 600, fontSize: 13, color: '#30d158', textTransform: 'uppercase' }}>{c.control_type}</div>
                  <div style={{ fontSize: 12, color: '#8892b0' }}>{c.description}</div>
                </div>
                <span style={{ fontFamily: "'JetBrains Mono', monospace", fontWeight: 700, color: '#30d158' }}>−{(c.reduction_pct * 100).toFixed(0)}%</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
