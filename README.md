# SentinelX

## AI-Powered SOC, Threat Intelligence and Cyber Threat Detection Platform

SentinelX is an integrated cybersecurity platform designed to centralize threat intelligence, security monitoring, detection, investigation, and incident response.

The platform integrates multiple cybersecurity capabilities including Threat Intelligence, Wazuh and Sysmon monitoring, IOC enrichment, threat hunting, phishing investigation, honeypot analysis, machine learning-based threat detection, an AI SOC Agent, and incident response reporting.

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
| Windows     +-----------> |  Backend / API       |
+-------------+             +----------+-----------+
                                    |
                                    v
+-------------+             +----------------------+
| Wazuh Agent  +----------->| Detection Engine     |
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

Technology Stack
Backend
Python
FastAPI
PostgreSQL
SQLAlchemy
Pydantic
Security and Monitoring
Wazuh
Sysmon
Threat Intelligence APIs
ThreatFox
AbuseIPDB
AlienVault OTX
VirusTotal
Machine Learning
Scikit-learn
Isolation Forest
Joblib
Frontend
React
Vite
JavaScript
CSS
Project Structure
SentinelX/
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
│   ├── main.py
│   ├── database.py
│   ├── models.py
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
└── README.md
Installation
1. Clone the repository
git clone https://github.com/YOUR_USERNAME/SentinelX.git
cd SentinelX
2. Backend Setup
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

Create your environment configuration:

cp .env.example .env

Configure the required database credentials and API keys.

3. Run the Backend
cd backend
source venv/bin/activate
python main.py
4. Frontend Setup
cd frontend
npm install
npm run dev
Core Workflow
Security Event
      |
      v
Wazuh / Sysmon / Honeypot
      |
      v
SentinelX Detection Engine
      |
      v
IOC Extraction and Enrichment
      |
      +------> Threat Intelligence APIs
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
Testing

SentinelX was tested using simulated security events and attack scenarios to validate:

Threat Intelligence enrichment
IOC detection
Risk scoring
Detection correlation
Threat hunting
Phishing analysis
Honeypot event ingestion
Machine learning predictions
AI SOC investigation
Incident generation
SOC dashboard visualization
Security

Sensitive information such as API keys, passwords, tokens, virtual environments, dependencies, build files, and local environment configuration are excluded from the repository using .gitignore.

Never commit your .env file.

Project Status
Phase	Component	Status
Phase 0	Planning and Lab Setup	Complete
Phase 1	Backend and PostgreSQL	Complete
Phase 2	Threat Intelligence Aggregator	Complete
Phase 3	IOC Enrichment and Risk Scoring	Complete
Phase 4	Wazuh and Sysmon Integration	Complete
Phase 5	Detection and Correlation Engine	Complete
Phase 6	Threat Hunting	Complete
Phase 7	Phishing Investigation	Complete
Phase 8	Honeypot Integration	Complete
Phase 9	ML Threat Detection	Complete
Phase 10	AI SOC Agent	Complete
Phase 11	SOC Dashboard	Complete
Phase 12	Incident Response and Reporting	Complete
Phase 13	Testing and Attack Simulations	Complete
Phase 14	Documentation and Deployment	In Progress
Future Improvements
Docker and Docker Compose deployment
Automated CI/CD pipeline
Advanced threat correlation
Real-time alert notifications
Role-Based Access Control
Advanced ML models
Automated incident response playbooks

