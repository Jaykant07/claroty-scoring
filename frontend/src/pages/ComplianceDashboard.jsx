import React, { useEffect, useState } from "react";
import "./ComplianceDashboard.css";

export default function ComplianceDashboard() {
  const [metrics, setMetrics] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("http://localhost:8000/api/compliance/metrics")
      .then((res) => res.json())
      .then((data) => {
        setMetrics(data.metrics || []);
        setLoading(false);
      })
      .catch((err) => console.error("Compliance metrics error:", err));
  }, []);

  const downloadPDF = () => {
    window.open("http://localhost:8000/api/compliance/pdf", "_blank");
  };

  if (loading) return <div>Loading Compliance Metrics...</div>;

  return (
    <div className="compliance-dashboard">
      <div className="header-row">
        <h2>IEC 62443 Compliance Matrix</h2>
        <button className="download-btn" onClick={downloadPDF}>
          Download Executive Summary (PDF)
        </button>
      </div>

      <div className="card matrix-card">
        <table className="compliance-table">
          <thead>
            <tr>
              <th>Zone Name</th>
              <th>Target Level (SL-T)</th>
              <th>Achieved Level (SL-A)</th>
              <th>Gap</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {metrics.map((m, idx) => (
              <tr key={idx}>
                <td>{m.zone}</td>
                <td>{m.sl_t}</td>
                <td>{m.sl_a}</td>
                <td style={{ color: m.gap > 0 ? "#ff5a5a" : "#4af9a3", fontWeight: "bold" }}>
                  {m.gap}
                </td>
                <td>
                  {m.gap > 0 ? (
                    <span className="badge fail">Non-Compliant</span>
                  ) : (
                    <span className="badge pass">Compliant</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
