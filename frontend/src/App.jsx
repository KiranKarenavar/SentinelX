import { useEffect, useState } from "react";
import "./index.css";

const API = "http://10.81.171.233:8000";

function App() {
  const [health, setHealth] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [honeypotEvents, setHoneypotEvents] = useState([]);
  const [mlResult, setMlResult] = useState(null);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState("");

  async function loadDashboard() {
    setLoading(true);
    setMessage("");

    try {
      const healthResponse = await fetch(`${API}/`);

      if (!healthResponse.ok) {
        throw new Error("Backend unavailable");
      }

      const healthData = await healthResponse.json();
      setHealth(healthData);

      const incidentsResponse =
        await fetch(`${API}/incidents`);

      if (incidentsResponse.ok) {
        const incidentData =
          await incidentsResponse.json();

        setIncidents(
          Array.isArray(incidentData)
            ? incidentData
            : incidentData.incidents || []
        );
      }

      const honeypotResponse =
        await fetch(
          `${API}/honeypot/events?limit=20`
        );

      if (honeypotResponse.ok) {
        const honeypotData =
          await honeypotResponse.json();

        setHoneypotEvents(
          Array.isArray(honeypotData)
            ? honeypotData
            : honeypotData.events || []
        );
      }
    } catch (error) {
      console.error(error);
      setMessage(
        "Unable to connect to SentinelX backend."
      );
    }

    setLoading(false);
  }

  async function testML() {
    setMessage("");

    try {
      const response = await fetch(
        `${API}/ml/predict`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            connection_count: 40,
            failed_logins: 20,
            suspicious_port: 1,
            known_bad_ip: 1,
            encoded_command: 1,
            privilege_escalation: 1,
          }),
        }
      );

      if (!response.ok) {
        throw new Error("ML request failed");
      }

      const data = await response.json();

      setMlResult(data);
    } catch (error) {
      console.error(error);

      setMessage(
        "ML detection request failed."
      );
    }
  }

  async function updateIncident(
    incidentId,
    status
  ) {
    try {
      const response = await fetch(
        `${API}/incidents/${incidentId}/status`,
        {
          method: "PATCH",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            status,
          }),
        }
      );

      if (!response.ok) {
        throw new Error(
          "Incident update failed"
        );
      }

      await loadDashboard();
    } catch (error) {
      console.error(error);

      setMessage(
        "Unable to update incident."
      );
    }
  }

  useEffect(() => {
    loadDashboard();

    const interval = setInterval(
      loadDashboard,
      10000
    );

    return () => clearInterval(interval);
  }, []);

  const criticalCount =
    incidents.filter(
      (incident) =>
        String(
          incident.severity || ""
        ).toUpperCase() === "CRITICAL"
    ).length;

  const highCount =
    incidents.filter(
      (incident) =>
        String(
          incident.severity || ""
        ).toUpperCase() === "HIGH"
    ).length;

  const mediumCount =
    incidents.filter(
      (incident) =>
        String(
          incident.severity || ""
        ).toUpperCase() === "MEDIUM"
    ).length;

  const openCount =
    incidents.filter(
      (incident) =>
        String(
          incident.status || ""
        ).toUpperCase() === "OPEN"
    ).length;

  return (
    <div className="dashboard">

      <header className="topbar">

        <div>
          <h1>SentinelX</h1>

          <p>
            AI-Powered Cyber Threat Intelligence
            & SOC Platform
          </p>
        </div>

        <div className="system-status">

          <span className="status-dot"></span>

          {health?.status === "running"
            ? "SYSTEM ONLINE"
            : "SYSTEM OFFLINE"}

        </div>

      </header>


      {message && (
        <div className="message">
          {message}
        </div>
      )}


      <main>

        {/* ================================================= */}
        {/* OVERVIEW */}
        {/* ================================================= */}

        <section className="overview">

          <div className="card">
            <h3>System</h3>

            <div className="metric">
              {health?.status === "running"
                ? "ONLINE"
                : "OFFLINE"}
            </div>

            <p>SentinelX API</p>
          </div>


          <div className="card">
            <h3>Total Incidents</h3>

            <div className="metric">
              {incidents.length}
            </div>

            <p>Security incidents</p>
          </div>


          <div className="card">
            <h3>Open Incidents</h3>

            <div className="metric">
              {openCount}
            </div>

            <p>Require investigation</p>
          </div>


          <div className="card">
            <h3>Honeypot Events</h3>

            <div className="metric">
              {honeypotEvents.length}
            </div>

            <p>Recent attack activity</p>
          </div>

        </section>


        {/* ================================================= */}
        {/* SEVERITY */}
        {/* ================================================= */}

        <section className="severity-grid">

          <div className="severity-card critical">
            <span>CRITICAL</span>
            <strong>{criticalCount}</strong>
          </div>

          <div className="severity-card high">
            <span>HIGH</span>
            <strong>{highCount}</strong>
          </div>

          <div className="severity-card medium">
            <span>MEDIUM</span>
            <strong>{mediumCount}</strong>
          </div>

          <div className="severity-card info">
            <span>ML ENGINE</span>
            <strong>READY</strong>
          </div>

        </section>


        {/* ================================================= */}
        {/* INCIDENTS */}
        {/* ================================================= */}

        <section className="panel">

          <div className="panel-header">

            <div>
              <h2>Security Incidents</h2>

              <p>
                SentinelX incident response
              </p>
            </div>

            <button
              onClick={loadDashboard}
            >
              Refresh
            </button>

          </div>


          {loading ? (
            <p>Loading incidents...</p>
          ) : incidents.length === 0 ? (

            <div className="empty">
              No incidents found.
            </div>

          ) : (

            <div className="table-wrapper">

              <table>

                <thead>

                  <tr>
                    <th>ID</th>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Source IP</th>
                    <th>IOC</th>
                    <th>Action</th>
                  </tr>

                </thead>


                <tbody>

                  {incidents.map(
                    (incident) => (

                      <tr key={incident.id}>

                        <td>
                          {incident.incident_id}
                        </td>

                        <td>
                          {incident.title}
                        </td>

                        <td>

                          <span
                            className={
                              `badge ${String(
                                incident.severity ||
                                  "INFO"
                              ).toLowerCase()}`
                            }
                          >
                            {incident.severity ||
                              "INFO"}
                          </span>

                        </td>

                        <td>
                          {incident.status}
                        </td>

                        <td>
                          {incident.source_ip ||
                            "-"}
                        </td>

                        <td>
                          {incident.ioc || "-"}
                        </td>

                        <td>

                          <select
                            value={
                              incident.status
                            }
                            onChange={(event) =>
                              updateIncident(
                                incident.incident_id,
                                event.target.value
                              )
                            }
                          >

                            <option value="OPEN">
                              OPEN
                            </option>

                            <option value="INVESTIGATING">
                              INVESTIGATING
                            </option>

                            <option value="CONTAINMENT">
                              CONTAINMENT
                            </option>

                            <option value="RESOLVED">
                              RESOLVED
                            </option>

                          </select>

                        </td>

                      </tr>

                    )
                  )}

                </tbody>

              </table>

            </div>

          )}

        </section>


        {/* ================================================= */}
        {/* HONEYPOT */}
        {/* ================================================= */}

        <section className="panel">

          <div className="panel-header">

            <div>
              <h2>Honeypot Activity</h2>

              <p>
                Recent attack events
              </p>
            </div>

            <button
              onClick={loadDashboard}
            >
              Refresh
            </button>

          </div>


          {honeypotEvents.length === 0 ? (

            <div className="empty">
              No honeypot events found.
            </div>

          ) : (

            <div className="table-wrapper">

              <table>

                <thead>

                  <tr>
                    <th>ID</th>
                    <th>Source IP</th>
                    <th>Destination</th>
                    <th>Event</th>
                    <th>Severity</th>
                  </tr>

                </thead>


                <tbody>

                  {honeypotEvents.map(
                    (event) => (

                      <tr key={event.id}>

                        <td>
                          {event.id}
                        </td>

                        <td>
                          {event.source_ip ||
                            "-"}
                        </td>

                        <td>

                          {event.destination_ip ||
                            "-"}

                          {event.destination_port
                            ? `:${event.destination_port}`
                            : ""}

                        </td>

                        <td>
                          {event.event_type ||
                            "-"}
                        </td>

                        <td>

                          <span
                            className={
                              `badge ${String(
                                event.severity ||
                                  "INFO"
                              ).toLowerCase()}`
                            }
                          >
                            {event.severity ||
                              "INFO"}
                          </span>

                        </td>

                      </tr>

                    )
                  )}

                </tbody>

              </table>

            </div>

          )}

        </section>


        {/* ================================================= */}
        {/* MACHINE LEARNING */}
        {/* ================================================= */}

        <section className="panel">

          <div className="panel-header">

            <div>
              <h2>ML Threat Detection</h2>

              <p>
                Random Forest threat classifier
              </p>
            </div>

            <button
              onClick={testML}
            >
              Run Detection
            </button>

          </div>


          {!mlResult ? (

            <div className="empty">

              Click{" "}
              <strong>
                Run Detection
              </strong>{" "}
              to test SentinelX ML.

            </div>

          ) : (

            <div className="ml-dashboard">

              <div className="ml-main">

                <span>
                  Prediction
                </span>

                <strong
                  className={
                    String(
                      mlResult.prediction
                    ).toLowerCase()
                  }
                >
                  {mlResult.prediction}
                </strong>

              </div>


              <div className="ml-stat">

                <span>
                  Confidence
                </span>

                <strong>
                  {(
                    mlResult.confidence *
                    100
                  ).toFixed(2)}
                  %
                </strong>

              </div>


              <div className="ml-stat">

                <span>
                  Malicious Probability
                </span>

                <strong>
                  {(
                    (mlResult.probabilities
                      ?.MALICIOUS || 0) *
                    100
                  ).toFixed(2)}
                  %
                </strong>

              </div>


              <div className="ml-stat">

                <span>
                  Suspicious Probability
                </span>

                <strong>
                  {(
                    (mlResult.probabilities
                      ?.SUSPICIOUS || 0) *
                    100
                  ).toFixed(2)}
                  %
                </strong>

              </div>

            </div>

          )}

        </section>


        {/* ================================================= */}
        {/* ML FEATURES */}
        {/* ================================================= */}

        {mlResult && (
          <section className="panel">

            <div className="panel-header">

              <div>
                <h2>
                  Detection Features
                </h2>

                <p>
                  Features used by the ML engine
                </p>
              </div>

            </div>


            <div className="feature-grid">

              {Object.entries(
                mlResult.features || {}
              ).map(
                ([name, value]) => (

                  <div
                    className="feature-card"
                    key={name}
                  >

                    <span>
                      {name.replace(
                        /_/g,
                        " "
                      )}
                    </span>

                    <strong>
                      {value}
                    </strong>

                  </div>

                )
              )}

            </div>

          </section>
        )}

      </main>


      <footer>
        SentinelX v1.0.0
        {" • "}
        AI SOC Platform
      </footer>

    </div>
  );
}

export default App;
