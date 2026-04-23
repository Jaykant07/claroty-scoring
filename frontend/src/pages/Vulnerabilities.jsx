import { useState, useEffect } from 'react';
import { api, getRiskLevel } from '../api/client';

export default function Vulnerabilities() {
  const [vulns, setVulns] = useState([]);
  const [filterSev, setFilterSev] = useState('');
  const [loading, setLoading] = useState(true);
  const [intelStatus, setIntelStatus] = useState(null);

  useEffect(() => {
    api.getVulnerabilities(filterSev || undefined).then(data => {
      setVulns(data);
      setLoading(false);
    }).catch(() => setLoading(false));

    fetch('http://localhost:8000/api/intelligence-status')
      .then(res => res.json())
      .then(data => setIntelStatus(data))
      .catch(console.error);
  }, [filterSev]);

  const formatDate = (isoStr) => {
    if (!isoStr) return 'Never';
    return new Date(isoStr).toLocaleString();
  };

  const sevs = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

  return (
    <div>
      <style>{`
        @keyframes flash-red {
          0% { background-color: transparent; }
          50% { background-color: rgba(255, 45, 85, 0.15); box-shadow: inset 0 0 10px rgba(255, 45, 85, 0.3); }
          100% { background-color: transparent; }
        }
        .flashing-red-row td {
          animation: flash-red 2.5s infinite;
        }
        .threat-candidate {
          background: #ff2d55;
          color: #fff;
          border: none;
          box-shadow: 0 0 8px rgba(255,45,85,0.5);
          animation: text-pulse 1.5s infinite;
        }
        @keyframes text-pulse {
          0% { opacity: 0.8; }
          50% { opacity: 1; transform: scale(1.02); }
          100% { opacity: 0.8; }
        }
      `}</style>
      <div className="page-header">
        <h2>Vulnerability Intelligence</h2>
        <div className="page-subtitle">NVD + EPSS enriched vulnerability tracking across all OT assets</div>
        {intelStatus && (
          <div style={{ marginTop: 12, display: 'inline-flex', gap: 16, fontSize: 12, color: '#8892b0', background: 'rgba(0, 212, 255, 0.05)', border: '1px solid rgba(0, 212, 255, 0.2)', padding: '6px 12px', borderRadius: 6 }}>
            <span><strong style={{color: '#00d4ff'}}>EPSS Intelligence:</strong> {formatDate(intelStatus.epss_last_updated)}</span>
            <span><strong style={{color: '#00d4ff'}}>CISA KEV:</strong> {formatDate(intelStatus.cisa_last_updated)}</span>
          </div>
        )}
      </div>

      {/* Filter */}
      <div style={{ marginBottom: 16, display: 'flex', gap: 8 }}>
        <button
          onClick={() => setFilterSev('')}
          style={{
            padding: '6px 16px', borderRadius: 20, fontSize: 12, fontWeight: 600, cursor: 'pointer',
            background: !filterSev ? 'rgba(0,212,255,0.1)' : 'transparent',
            border: `1px solid ${!filterSev ? 'rgba(0,212,255,0.3)' : 'var(--border-subtle)'}`,
            color: !filterSev ? '#00d4ff' : '#8892b0',
          }}
        >All ({vulns.length})</button>
        {sevs.map(s => (
          <button
            key={s}
            onClick={() => { setLoading(true); setFilterSev(s); }}
            style={{
              padding: '6px 16px', borderRadius: 20, fontSize: 12, fontWeight: 600, cursor: 'pointer',
              background: filterSev === s ? 'rgba(0,212,255,0.1)' : 'transparent',
              border: `1px solid ${filterSev === s ? 'rgba(0,212,255,0.3)' : 'var(--border-subtle)'}`,
              color: filterSev === s ? '#00d4ff' : '#8892b0',
            }}
          >{s}</button>
        ))}
      </div>

      <div className="card animate-fade-in">
        {loading ? (
          <div className="skeleton" style={{ height: 300 }} />
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>CVE ID</th>
                <th>CVSS Score</th>
                <th>EPSS Percentile</th>
                <th>Severity</th>
                <th>CWE</th>
                <th>KEV</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              {vulns.map(v => (
                <tr key={v.id} className={v.epss_percentile > 0.95 ? 'flashing-red-row' : ''}>
                  <td style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, fontWeight: 700, color: '#00d4ff' }}>
                    <a href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`} target="_blank" rel="noopener noreferrer">
                      {v.cve_id}
                    </a>
                  </td>
                  <td>
                    <span className={`risk-badge ${getRiskLevel(v.cvss_score * 10)}`}>
                      {v.cvss_score.toFixed(1)}
                    </span>
                  </td>
                  <td style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      {(v.epss_percentile * 100).toFixed(1)}%
                      {v.epss_percentile > 0.95 && <span className="threat-candidate" style={{ fontSize: 9, padding: '2px 6px', borderRadius: 4, fontWeight: 700, letterSpacing: 0.5 }}>ACTIVE THREAT CANDIDATE</span>}
                    </div>
                  </td>
                  <td>
                    <span className={`risk-badge ${v.severity === 'CRITICAL' ? 'critical' : v.severity === 'HIGH' ? 'high' : v.severity === 'MEDIUM' ? 'medium' : 'low'}`}>
                      {v.severity}
                    </span>
                  </td>
                  <td style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: '#8892b0' }}>{v.cwe_id}</td>
                  <td>{v.is_kev ? <span className="tag tag-kev">KEV</span> : '—'}</td>
                  <td style={{ maxWidth: 300 }}>{v.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
