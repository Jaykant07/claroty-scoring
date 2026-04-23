const API_BASE = 'http://localhost:8000/api';

async function fetchJSON(path) {
  const res = await fetch(`${API_BASE}${path}`);
  if (!res.ok) throw new Error(`API ${res.status}: ${path}`);
  return res.json();
}

export const api = {
  // Dashboard
  getSummary:      () => fetchJSON('/dashboard/summary'),
  getHeatmap:      () => fetchJSON('/dashboard/heatmap'),
  getActivity:     (limit = 30) => fetchJSON(`/dashboard/activity?limit=${limit}`),

  // Assets
  getAssets:       (sortBy = 'risk') => fetchJSON(`/assets?sort_by=${sortBy}`),
  getAssetDetail:  (id) => fetchJSON(`/assets/${id}`),
  getRiskHistory:  (id, limit = 100) => fetchJSON(`/assets/${id}/risk-history?limit=${limit}`),

  // Zones
  getZones:        () => fetchJSON('/zones'),
  getZoneAssets:   (id) => fetchJSON(`/zones/${id}/assets`),

  // Vulnerabilities & Anomalies
  getVulnerabilities: (severity) => fetchJSON(`/vulnerabilities${severity ? `?severity=${severity}` : ''}`),
  getAnomalies:    (activeOnly = true) => fetchJSON(`/anomalies?active_only=${activeOnly}`),

  // Traffic & Syslog
  getCrossZoneTraffic: (limit = 50) => fetchJSON(`/traffic/cross-zone?limit=${limit}`),
  getSyslogEvents: (limit = 50) => fetchJSON(`/syslog/events?limit=${limit}`),

  // Health
  getHealth:       () => fetchJSON('/health'),

  // Discovery
  startDiscovery:  () => fetch(`${API_BASE}/discovery/start`, { method: 'POST' }).then(res => res.json()),
  stopDiscovery:   () => fetch(`${API_BASE}/discovery/stop`, { method: 'POST' }).then(res => res.json()),
  clearDiscovery:  () => fetch(`${API_BASE}/discovery/clear`, { method: 'DELETE' }).then(res => res.json()),
};

export function getRiskLevel(score) {
  if (score >= 75) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 25) return 'medium';
  return 'low';
}

export function getRiskColor(score) {
  if (score >= 75) return '#ff2d55';
  if (score >= 50) return '#ff6b35';
  if (score >= 25) return '#ffaa00';
  return '#30d158';
}

export function formatTime(isoString) {
  if (!isoString) return '—';
  const d = new Date(isoString);
  const now = new Date();
  const diffMs = now - d;
  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 1) return 'just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffHours / 24);
  return `${diffDays}d ago`;
}
