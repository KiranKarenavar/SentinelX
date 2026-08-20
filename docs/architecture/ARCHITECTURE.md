# SentinelX Architecture

## High-Level Architecture

```text
                         ┌──────────────────────────┐
                         │      Security Sources    │
                         │                          │
                         │  Sysmon │ Wazuh │ Cowrie │
                         │  Phishing Emails         │
                         └────────────┬─────────────┘
                                      │
                                      ▼
                         ┌──────────────────────────┐
                         │      SentinelX Backend   │
                         │        FastAPI            │
                         └────────────┬─────────────┘
                                      │
                 ┌────────────────────┼────────────────────┐
                 │                    │                    │
                 ▼                    ▼                    ▼
        ┌────────────────┐   ┌────────────────┐   ┌────────────────┐
        │ Threat         │   │ Detection &    │   │ Threat         │
        │ Intelligence   │   │ Correlation    │   │ Hunting        │
        └───────┬────────┘   └───────┬────────┘   └───────┬────────┘
                │                    │                    │
                ▼                    ▼                    ▼
        ┌────────────────┐   ┌────────────────┐   ┌────────────────┐
        │ IOC Enrichment │   │ Risk & Severity│   │ Investigation  │
        │ & Scoring      │   │ Analysis       │   │ Queries        │
        └───────┬────────┘   └───────┬────────┘   └────────────────┘
                │                    │
                └──────────┬─────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │ Machine Learning │
                  │ Threat Detection │
                  └────────┬─────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │   AI SOC Agent   │
                  │ Investigation &  │
                  │ Analysis         │
                  └────────┬─────────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
              ▼            ▼            ▼
       ┌────────────┐ ┌────────────┐ ┌────────────┐
       │ Incidents  │ │ Dashboard  │ │ Reporting  │
       └─────┬──────┘ └────────────┘ └─────┬──────┘
             │                             │
             └──────────────┬──────────────┘
                            ▼
                    ┌───────────────┐
                    │   PostgreSQL  │
                    │    Database   │
                    └───────────────┘


## Threat Intelligence Sources

             ┌───────────────┐
             │     OTX       │
             └───────┬───────┘
                     │
             ┌───────▼───────┐
             │   ThreatFox   │
             └───────┬───────┘
                     │
             ┌───────▼───────┐
             │   AbuseIPDB   │
             └───────┬───────┘
                     │
             ┌───────▼───────┐
             │  VirusTotal   │
             └───────┬───────┘
                     │
                     ▼
            ┌─────────────────┐
            │ SentinelX TI    │
            │ Aggregator      │
            └─────────────────┘


## Security Event Pipeline

Endpoint / Honeypot
        │
        ▼
   Event Collection
        │
        ▼
 IOC Extraction
        │
        ▼
Threat Intelligence
        │
        ▼
 IOC Enrichment
        │
        ▼
 Risk Scoring
        │
        ▼
 Detection & Correlation
        │
        ▼
 ML Threat Detection
        │
        ▼
 AI SOC Investigation
        │
        ▼
 Incident Creation
        │
        ▼
 SOC Dashboard
        │
        ▼
 Incident Response


## Main Components

| Component           | Responsibility               |
| ------------------- | ---------------------------- |
| Wazuh               | Security event monitoring    |
| Sysmon              | Windows endpoint telemetry   |
| Cowrie              | SSH honeypot monitoring      |
| Threat Intelligence | External threat intelligence |
| IOC Enrichment      | IOC investigation            |
| Detection Engine    | Security detection           |
| Correlation Engine  | Connect related events       |
| Threat Hunting      | Proactive investigation      |
| ML Engine           | Machine learning detection   |
| AI SOC Agent        | AI-assisted investigation    |
| PostgreSQL          | Persistent storage           |
| React Dashboard     | SOC visualization            |
| Incident Response   | Investigation and reporting  |

