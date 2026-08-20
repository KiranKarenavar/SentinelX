import { useEffect, useState } from "react";
import {
  AlertTriangle,
  Bug,
  Database,
  Activity,
  ShieldAlert,
  Server,
  RefreshCw,
  CheckCircle,
} from "lucide-react";

import { getDashboardSummary } from "../services/api";

function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
}) {
  return (
    <div className="dashboard-stat-card">
      <div className="stat-icon">
        <Icon size={22} />
      </div>

      <div className="stat-content">
        <div className="stat-title">{title}</div>
        <div className="stat-value">{value}</div>
        <div className="stat-subtitle">{subtitle}</div>
      </div>
    </div>
  );
}

function SeverityBadge({ severity }) {
  return (
    <span
      className={`severity-badge ${
        severity ? severity.toLowerCase() : "low"
      }`}
    >
      {severity || "LOW"}
    </span>
  );
}

function StatusBadge({ status }) {
  return (
    <span
      className={`status-badge ${
        status ? status.toLowerCase() : "open"
      }`}
    >
      {status || "OPEN"}
    </span>
  );
}

export default function Dashboard() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadDashboard = async () => {
    try {
      setLoading(true);
      setError("");

      const result = await getDashboardSummary();

      setData(result);
    } catch (err) {
      console.error("Dashboard error:", err);

      setError(
        err?.response?.data?.detail ||
          "Unable to connect to SentinelX backend."
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDashboard();

    const interval = setInterval(() => {
      loadDashboard();
    }, 30000);

    return () => clearInterval(interval);
  }, []);

  if (loading && !data) {
    return (
      <div className="dashboard-page">
        <div className="dashboard-loading">
          <RefreshCw className="spin" size={30} />
          <h2>Loading SentinelX SOC...</h2>
          <p>Connecting to SentinelX backend</p>
        </div>
      </div>
    );
  }

  if (error && !data) {
    return (
      <div className="dashboard-page">
        <div className="dashboard-error">
          <AlertTriangle size={40} />

          <h2>Dashboard Connection Failed</h2>

          <p>{error}</p>

          <button onClick={loadDashboard}>
            <RefreshCw size={18} />
            Retry
          </button>
        </div>
      </div>
    );
  }

  const incidents = data?.incidents || {};
  const severity = data?.severity || {};
  const threatIntel = data?.threat_intelligence || {};
  const honeypot = data?.honeypot || {};
  const recentIncidents = data?.recent_incidents || [];

  return (
    <div className="dashboard-page">

      {/* HEADER */}

      <div className="dashboard-header">

        <div>
          <div className="dashboard-title-row">
            <h1>SentinelX SOC Dashboard</h1>

            <span className="system-online">
              <span className="online-dot"></span>
              SYSTEM ONLINE
            </span>
          </div>

          <p>
            Security Operations Center overview and real-time
            threat monitoring
          </p>
        </div>

        <button
          className="refresh-button"
          onClick={loadDashboard}
          disabled={loading}
        >
          <RefreshCw
            size={18}
            className={loading ? "spin" : ""}
          />
          Refresh
        </button>

      </div>

      {/* STAT CARDS */}

      <div className="dashboard-stat-grid">

        <StatCard
          title="Total Incidents"
          value={incidents.total ?? 0}
          subtitle="All recorded incidents"
          icon={AlertTriangle}
        />

        <StatCard
          title="Critical Threats"
          value={severity.critical ?? 0}
          subtitle="Require immediate action"
          icon={ShieldAlert}
        />

        <StatCard
          title="High Severity"
          value={severity.high ?? 0}
          subtitle="High priority threats"
          icon={Bug}
        />

        <StatCard
          title="Open Incidents"
          value={incidents.open ?? 0}
          subtitle="Awaiting investigation"
          icon={Activity}
        />

      </div>

      {/* SECOND ROW */}

      <div className="dashboard-stat-grid">

        <StatCard
          title="Threat Intelligence"
          value={threatIntel.total_iocs ?? 0}
          subtitle="Total IOCs collected"
          icon={Database}
        />

        <StatCard
          title="Malicious IOCs"
          value={threatIntel.malicious_iocs ?? 0}
          subtitle="High-risk indicators"
          icon={ShieldAlert}
        />

        <StatCard
          title="Honeypot Events"
          value={honeypot.total_events ?? 0}
          subtitle="Captured attack activity"
          icon={Server}
        />

        <StatCard
          title="Resolved"
          value={incidents.resolved ?? 0}
          subtitle="Successfully closed"
          icon={CheckCircle}
        />

      </div>

      {/* MAIN GRID */}

      <div className="dashboard-main-grid">

        {/* INCIDENT STATUS */}

        <div className="dashboard-panel">

          <div className="panel-header">
            <div>
              <h2>Incident Status</h2>
              <p>Current incident workflow</p>
            </div>

            <Activity size={20} />
          </div>

          <div className="incident-status-list">

            <div className="status-row">
              <span>Open</span>
              <strong>{incidents.open ?? 0}</strong>
            </div>

            <div className="status-row">
              <span>Investigating</span>
              <strong>{incidents.investigating ?? 0}</strong>
            </div>

            <div className="status-row">
              <span>Containment</span>
              <strong>{incidents.containment ?? 0}</strong>
            </div>

            <div className="status-row">
              <span>Resolved</span>
              <strong>{incidents.resolved ?? 0}</strong>
            </div>

          </div>

        </div>

        {/* SEVERITY */}

        <div className="dashboard-panel">

          <div className="panel-header">
            <div>
              <h2>Threat Severity</h2>
              <p>Incident severity distribution</p>
            </div>

            <ShieldAlert size={20} />
          </div>

          <div className="severity-list">

            <div className="severity-row">
              <span className="severity-name critical">
                Critical
              </span>

              <div className="severity-bar">
                <div
                  className="severity-fill critical"
                  style={{
                    width: `${Math.min(
                      (severity.critical || 0) * 20,
                      100
                    )}%`,
                  }}
                ></div>
              </div>

              <strong>{severity.critical ?? 0}</strong>
            </div>

            <div className="severity-row">
              <span className="severity-name high">
                High
              </span>

              <div className="severity-bar">
                <div
                  className="severity-fill high"
                  style={{
                    width: `${Math.min(
                      (severity.high || 0) * 20,
                      100
                    )}%`,
                  }}
                ></div>
              </div>

              <strong>{severity.high ?? 0}</strong>
            </div>

            <div className="severity-row">
              <span className="severity-name medium">
                Medium
              </span>

              <div className="severity-bar">
                <div
                  className="severity-fill medium"
                  style={{
                    width: `${Math.min(
                      (severity.medium || 0) * 20,
                      100
                    )}%`,
                  }}
                ></div>
              </div>

              <strong>{severity.medium ?? 0}</strong>
            </div>

            <div className="severity-row">
              <span className="severity-name low">
                Low
              </span>

              <div className="severity-bar">
                <div
                  className="severity-fill low"
                  style={{
                    width: `${Math.min(
                      (severity.low || 0) * 20,
                      100
                    )}%`,
                  }}
                ></div>
              </div>

              <strong>{severity.low ?? 0}</strong>
            </div>

          </div>

        </div>

      </div>

      {/* RECENT INCIDENTS */}

      <div className="dashboard-panel recent-panel">

        <div className="panel-header">

          <div>
            <h2>Recent Security Incidents</h2>
            <p>Latest events detected by SentinelX</p>
          </div>

          <AlertTriangle size={20} />

        </div>

        {recentIncidents.length === 0 ? (

          <div className="empty-state">
            <CheckCircle size={35} />
            <h3>No incidents found</h3>
            <p>
              SentinelX has not recorded any incidents yet.
            </p>
          </div>

        ) : (

          <div className="incident-table-wrapper">

            <table className="incident-table">

              <thead>
                <tr>
                  <th>Incident ID</th>
                  <th>Title</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>IOC</th>
                  <th>MITRE</th>
                  <th>Created</th>
                </tr>
              </thead>

              <tbody>

                {recentIncidents.map((incident) => (

                  <tr key={incident.id}>

                    <td>
                      <strong>
                        {incident.incident_id}
                      </strong>
                    </td>

                    <td>
                      {incident.title}
                    </td>

                    <td>
                      <SeverityBadge
                        severity={incident.severity}
                      />
                    </td>

                    <td>
                      <StatusBadge
                        status={incident.status}
                      />
                    </td>

                    <td className="ioc-cell">
                      {incident.ioc || "-"}
                    </td>

                    <td>
                      {incident.mitre_technique || "-"}
                    </td>

                    <td>
                      {incident.created_at
                        ? new Date(
                            incident.created_at
                          ).toLocaleString()
                        : "-"}
                    </td>

                  </tr>

                ))}

              </tbody>

            </table>

          </div>

        )}

      </div>

      {/* FOOTER */}

      <div className="dashboard-footer">

        <span>
          SentinelX SOC Platform v1.0.0
        </span>

        <span>
          Auto-refresh: 30 seconds
        </span>

      </div>

    </div>
  );
}
