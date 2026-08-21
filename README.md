# SentinelX

## AI-Powered SOC, Threat Intelligence and Cyber Threat Detection Platform

SentinelX is an integrated cybersecurity platform designed to centralize **threat intelligence, security monitoring, detection, investigation, threat hunting, and incident response**.

The platform combines multiple cybersecurity capabilities into a unified SOC-oriented workflow, including **Threat Intelligence, Wazuh and Sysmon monitoring, IOC enrichment, risk scoring, detection and correlation, threat hunting, phishing investigation, honeypot analysis, machine learning-based threat detection, an AI SOC Agent, incident response, and centralized dashboard visualization**.

> **Collect → Normalize → Enrich → Detect → Correlate → Investigate → Respond**

---

## Table of Contents

- [Features](#features)
- [Project Highlights](#project-highlights)
- [Architecture](#architecture)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Core Workflow](#core-workflow)
- [Modules](#modules)
- [API Documentation](#api-documentation)
- [Testing](#testing)
- [Documentation](#documentation)
- [Screenshots](#screenshots)
- [Security](#security)
- [Project Status](#project-status)
- [Future Improvements](#future-improvements)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)
- [Author](#author)

---

## Features

- Threat Intelligence Aggregation
- IOC Enrichment and Risk Scoring
- Wazuh and Sysmon Integration
- Detection and Correlation Engine
- Threat Hunting
- Phishing Email Investigation
- Honeypot Integration
- Machine Learning Threat Detection
- AI SOC Agent
- SOC Dashboard
- Incident Response and Reporting
- Security Testing and Attack Simulation

## Project Highlights

| Capability | Description |
|---|---|
| Threat Intelligence | Aggregates and enriches security indicators |
| IOC Analysis | Normalizes, deduplicates, scores, and stores IOCs |
| Endpoint Monitoring | Integrates Wazuh and Sysmon telemetry |
| Detection | Identifies suspicious security events |
| Correlation | Connects related events and indicators |
| Threat Hunting | Supports proactive investigation |
| Phishing Analysis | Extracts and analyzes suspicious email indicators |
| Honeypot | Collects and analyzes attacker interaction data |
| Machine Learning | Supports threat classification and anomaly detection |
| AI SOC Agent | Assists analysts with investigation and response guidance |
| Dashboard | Provides centralized SOC visibility |
| Incident Response | Supports investigation, tracking, and reporting |

## Architecture

```text
                         +----------------------+
                         | Threat Intelligence  |
                         | OTX / ThreatFox /    |
                         | AbuseIPDB / VT       |
                         +----------+-----------+
                                    |
                                    v
+-------------+             +----------------------+
| Sysmon      |             |     SentinelX        |
| Windows     +-----------> |   Backend / API      |
+-------------+             +----------+-----------+
                                    |
                                    v
+-------------+             +----------------------+
| Wazuh Agent | ----------> | Detection Engine     |
+-------------+             | IOC Enrichment      |
                            | Correlation Engine   |
                            +----------+-----------+
                                       |
              +------------------------+------------------------+
              |                        |                        |
              v                        v                        v
      +---------------+        +---------------+       +---------------+
      | Threat Hunting|        | ML Detection  |       | Phishing      |
      +---------------+        +---------------+       | Investigation |
                                                       +---------------+
                                                               |
              +------------------------+------------------------+
              |                        |                        |
              v                        v                        v
       +---------------+        +---------------+       +---------------+
       | Honeypot      |        | AI SOC Agent  |       | Incident      |
       | Integration   |        | Investigation |       | Response      |
       +---------------+        +---------------+       +---------------+
                                    |
                                    v
                           +------------------+
                           | SOC Dashboard    |
                           +------------------+
```

## Technology Stack

**Backend**
- Python
- FastAPI
- PostgreSQL
- SQLAlchemy
- Pydantic

**Security and Monitoring**
- Wazuh
- Sysmon

**Threat Intelligence**
- AlienVault OTX
- ThreatFox
- AbuseIPDB
- VirusTotal

**Machine Learning**
- Scikit-learn
- Isolation Forest
- Joblib

**Frontend**
- React
- Vite
- JavaScript
- CSS

**Development and Infrastructure**
- Git
- GitHub
- Ubuntu/Linux
- Windows
- Virtual Machines

## Project Structure

```text
SentinelX/
│
├── backend/
│   ├── ai_agent/
│   ├── app/
│   ├── detection/
│   ├── honeypot/
│   ├── hunt/
│   ├── ml/
│   ├── phishing/
│   ├── threat_intelligence/
│   ├── wazuh/
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   ├── public/
│   └── package.json
│
├── data/
│   └── honeypot/
│
├── docs/
│   ├── api/
│   ├── architecture/
│   ├── project/
│   ├── screenshots/
│   └── testing/
│
├── .gitignore
├── README.md
└── LICENSE
```

## Prerequisites

Before running SentinelX, install:

- Python 3.10 or later
- PostgreSQL
- Node.js and npm
- Git
- Wazuh
- Windows endpoint with Sysmon

**Optional:**
- Docker
- VirtualBox or VMware
- Kali Linux for authorized security testing

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/KiranKarenavar/SentinelX.git
cd SentinelX
```

### 2. Backend Setup

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Configuration

Create the environment configuration file:

```bash
cp .env.example .env
```

Configure your database credentials and API keys.

Example:

```env
DATABASE_URL=postgresql://USER:PASSWORD@HOST:PORT/DATABASE

OTX_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
VIRUSTOTAL_API_KEY=your_key
THREATFOX_API_KEY=your_key
```

### 4. Database Setup

Create and configure the SentinelX PostgreSQL database.

```bash
createdb sentinelx
```

### 5. Run the Backend

```bash
cd backend
source venv/bin/activate
python main.py
```

Depending on your FastAPI configuration, you may also run:

```bash
uvicorn app.main:app --reload
```

The backend API will typically be available at:

```text
http://127.0.0.1:8000
```

Interactive API documentation:

```text
http://127.0.0.1:8000/docs
```

### 6. Frontend Setup

Open another terminal:

```bash
cd frontend
npm install
npm run dev
```

The Vite development server will display the frontend URL in the terminal.

## Core Workflow

```text
Security Event
      |
      v
Wazuh / Sysmon / Honeypot / Phishing
      |
      v
SentinelX Ingestion
      |
      v
IOC Extraction
      |
      v
Threat Intelligence Enrichment
      |
      v
Risk Scoring and Correlation
      |
      +------------+-------------+
      |            |             |
      v            v             v
Threat Hunting  ML Detection  AI SOC Agent
      |            |             |
      +------------+-------------+
                   |
                   v
          Incident Creation
                   |
                   v
             SOC Dashboard
                   |
                   v
        Incident Response Report
```

## Modules

### Threat Intelligence

Aggregates threat intelligence from:

- AlienVault OTX
- ThreatFox
- AbuseIPDB
- VirusTotal

The threat intelligence workflow is:

```text
Collect → Normalize → Deduplicate → Enrich → Score → Store
```

### IOC Enrichment and Risk Scoring

SentinelX supports investigation and enrichment of:

- IP addresses
- Domains
- URLs
- File hashes

Indicators are enriched using available threat intelligence data and assigned risk scores to help prioritize investigation.

### Wazuh and Sysmon Integration

Sysmon captures detailed Windows endpoint activity, including:

- Process creation
- Network connections
- File activity
- Registry activity

Wazuh collects and analyzes endpoint security information.

```text
Windows Endpoint
       |
       v
     Sysmon
       |
       v
  Wazuh Agent
       |
       v
 Wazuh Manager
       |
       v
   SentinelX
```

### Detection and Correlation Engine

The Detection Engine processes security events and threat intelligence.

```text
Security Event
      |
      v
Normalization
      |
      v
IOC Matching
      |
      v
Threat Intelligence
      |
      v
Risk Analysis
      |
      v
Correlation
      |
      v
Security Alert
```

### Threat Hunting

The Threat Hunting module supports proactive investigation of:

- IP addresses
- Domains
- URLs
- File hashes
- Endpoint events
- Suspicious behavior

Typical workflow:

```text
Hypothesis → Search → Investigation → Correlation → Validation → Report
```

### Phishing Investigation

The phishing investigation module analyzes suspicious emails and extracts indicators such as:

- Sender information
- Email subject
- URLs
- Domains
- IP addresses
- Attachments
- File hashes

Extracted indicators can be enriched with threat intelligence to support classification and investigation.

### Honeypot Integration

The honeypot module collects and analyzes attacker interaction data, including:

- Source IP addresses
- Connection attempts
- Commands or actions
- Timestamps
- Attack patterns
- Extracted indicators

The collected data can be sent to the SentinelX detection and investigation workflow.

### Machine Learning Threat Detection

The Machine Learning module supports:

- Threat classification
- Anomaly detection
- Suspicious activity prioritization
- Threat prediction

Machine learning results are intended to complement threat intelligence, detection rules, correlation, and analyst investigation.

### AI SOC Agent

The AI SOC Agent assists security analysts with:

- Alert summarization
- IOC investigation
- Threat explanation
- Investigation guidance
- Response recommendations
- Incident summaries

The AI SOC Agent is designed to support human analysts and improve investigation efficiency.

### SOC Dashboard

The centralized SOC Dashboard provides visibility into:

- Security alerts
- IOCs
- Threat intelligence
- Risk scores
- Detection results
- Threat hunting
- Phishing investigations
- Honeypot events
- Machine learning predictions
- Incidents

### Incident Response

SentinelX supports the following incident response lifecycle:

```text
Detection
    |
    v
Triage
    |
    v
Investigation
    |
    v
Containment
    |
    v
Eradication
    |
    v
Recovery
    |
    v
Lessons Learned
```

The platform supports investigation, evidence collection, incident tracking, response guidance, and reporting.

## API Documentation

FastAPI provides interactive API documentation when the backend is running:

```text
http://127.0.0.1:8000/docs
```

Additional API documentation is available in:

```text
docs/api/
```

## Testing

SentinelX was tested using module-level testing, integration testing, and simulated security events.

Testing includes:

- Threat Intelligence Enrichment
- IOC Detection
- IOC Normalization
- IOC Storage
- Risk Scoring
- Detection Correlation
- Wazuh Integration
- Sysmon Event Processing
- Threat Hunting
- Phishing Analysis
- Honeypot Event Ingestion
- Machine Learning Predictions
- AI SOC Investigation
- Incident Generation
- Dashboard Functionality

Detailed testing documentation is available in:

```text
docs/testing/
```

## Documentation

Project documentation is organized as follows:

```text
docs/
├── api/              # API documentation
├── architecture/     # System architecture and design
├── project/          # Project report and presentation
├── screenshots/      # Application screenshots
└── testing/          # Testing documentation and results
```

The `docs/project/` directory contains:

- `PROJECT_REPORT.md`
- Project Report in DOCX format
- Project Report in PDF format
- Project Presentation in PPTX format
- Project Presentation in PDF format

## Screenshots

Application screenshots are stored in:

```text
docs/screenshots/
```

Recommended screenshots include:

- SentinelX Dashboard
- Threat Intelligence Results
- IOC Enrichment
- Risk Scoring
- Wazuh and Sysmon Events
- Detection Results
- Threat Hunting
- Phishing Investigation
- Honeypot Events
- ML Predictions
- AI SOC Agent
- Incident Response

## Security

Sensitive information is excluded from the repository using `.gitignore`.


## Project Status

| Phase | Component | Status |
|---|---|---|
| Phase 0 | Planning and Lab Setup | Complete |
| Phase 1 | Backend and PostgreSQL | Complete |
| Phase 2 | Threat Intelligence Aggregator | Complete |
| Phase 3 | IOC Enrichment and Risk Scoring | Complete |
| Phase 4 | Wazuh and Sysmon Integration | Complete |
| Phase 5 | Detection and Correlation Engine | Complete |
| Phase 6 | Threat Hunting | Complete |
| Phase 7 | Phishing Investigation | Complete |
| Phase 8 | Honeypot Integration | Complete |
| Phase 9 | ML Threat Detection | Complete |
| Phase 10 | AI SOC Agent | Complete |
| Phase 11 | SOC Dashboard | Complete |
| Phase 12 | Incident Response and Reporting | Complete |
| Phase 13 | Testing and Attack Simulations | Complete |

## Future Improvements

- Docker and Docker Compose deployment
- Automated CI/CD pipeline
- Advanced threat correlation
- Real-time alert notifications
- Role-Based Access Control
- User authentication and authorization
- Advanced machine learning models
- Improved anomaly detection
- MITRE ATT&CK mapping
- SOAR integration
- Automated incident response playbooks
- Cloud deployment
- Multi-tenant SOC architecture
- Real-time security analytics
- Additional threat intelligence sources

## Contributing

Contributions, suggestions, and improvements are welcome.

1. Fork the repository.
2. Create a feature branch.
3. Make your changes.
4. Test your changes.
5. Submit a pull request.

```bash
git checkout -b feature/new-feature
```

## License

This project is released under the license included in the `LICENSE` file.

## Disclaimer

SentinelX is developed for educational, research, and authorized cybersecurity testing purposes only.

Do not use this project against systems, networks, applications, or accounts without proper authorization.

