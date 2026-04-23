# Claroty OT Security Risk Scoring Platform

## Overview

This project is a full-stack platform for OT (Operational Technology) asset discovery, vulnerability correlation, risk scoring, and IEC 62443 compliance monitoring. It features a Python backend (FastAPI, SQLAlchemy) and a modern React frontend (Vite, React Router), with a focus on multi-vector risk analysis for industrial networks.

---

## Project Structure

- **backend/**: Python backend for asset discovery, risk scoring, vulnerability sync, and API.
  - `acquisition/`: Data ingestion (NetFlow, DPI, SNMP, syslog, project files, PCAP capture)
  - `api/`: FastAPI REST API, schemas, and route handlers
  - `engines/`: Core logic for risk, scoring, threat, vulnerability, and data management
  - `config.py`, `database.py`, `models.py`, `seed.py`, `state.py`: Core backend modules
- **frontend/**: React web UI for dashboards, asset explorer, compliance, and more
  - `src/pages/`: Main UI pages (Dashboard, Asset Explorer, Compliance, Vulnerabilities, Zones, Login)
  - `src/api/client.js`: API client for backend communication
- **data/**: Reference and cache files (CPE, NVD, EPSS, OUI, MITRE, etc.)
- **main.py**: Backend entry point (runs all engines and API)
- **requirements.txt**: Python dependencies
- **.env**: Environment variables for backend config

---

## Key Features

- **OT Asset Discovery**: Passive DPI, NetFlow, SNMP, project file ingestion, syslog
- **Vulnerability Correlation**: NVD/EPSS sync, CPE mapping, KEV awareness
- **Risk Scoring**: Multi-dimensional, IEC 62443 zone-aware, real-time updates
- **Compliance Dashboard**: IEC 62443 SL-T/SL-A matrix, PDF export
- **Modern Web UI**: React, Vite, real-time dashboards, asset drilldown
- **Simulation Mode**: Demo data and synthetic traffic for safe testing

---

## Getting Started

### 1. Prerequisites

- Python 3.10+
- Node.js 18+
- (Windows) [Npcap](https://nmap.org/npcap/) for packet capture (optional)

### 2. Backend Setup

1. Create and activate a Python virtual environment:
   ```sh
   python -m venv venv
   source venv/bin/activate  # or venv\Scripts\activate on Windows
   ```
2. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```
3. Configure `.env` as needed (see provided .env for defaults)
4. (Optional) Seed demo data:
   ```sh
   python -m backend.seed
   ```
5. Start the backend API:
   ```sh
   uvicorn backend.api.main:app --reload
   ```

### 3. Frontend Setup

1. Install dependencies:
   ```sh
   cd frontend
   npm install
   ```
2. Start the development server:
   ```sh
   npm run dev
   ```
3. Access the UI at [http://localhost:5173](http://localhost:5173)

---

## Testing & Development

- **Simulation Mode**: Enabled by default in `.env` for safe, demo-friendly operation
- **API Docs**: Visit [http://localhost:8000/docs](http://localhost:8000/docs) for OpenAPI/Swagger
- **Unit Tests**: (Add your tests in `test_db.py` or similar)

---

## What Collaborators Should Study

- **backend/models.py**: Database schema and relationships
- **backend/engines/**: Risk, scoring, threat, and vulnerability logic
- **backend/acquisition/**: Data ingestion and protocol handling
- **frontend/src/pages/**: Main UI logic and data flow
- **.env**: Configuration for local/dev/test environments
- **requirements.txt** & **package.json**: Dependency management

---

## How to Implement & Test Locally

1. Clone the repository and follow the setup steps above
2. Use simulation mode for safe, offline testing
3. Explore the UI, trigger asset discovery, view risk/compliance dashboards
4. Review and extend backend logic or frontend components as needed
5. For real packet capture/SNMP, adjust `.env` and ensure proper network permissions

---

## Notes

- For production, review security settings, use a real database, and disable simulation mode
- Contributions welcome! Please document major changes and add tests where possible

---

## License

MIT License (see LICENSE file)
