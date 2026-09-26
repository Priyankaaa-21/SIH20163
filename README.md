# SIH 26163: Security Assessment of the World Monitor Application

![SIH](https://img.shields.io/badge/Smart_India_Hackathon-2026-blue) ![Python](https://img.shields.io/badge/Python-FastAPI-green) ![React](https://img.shields.io/badge/React-Vite-61dafb)

This repository contains a complete, automated security assessment platform designed specifically for the **SIH 26163 Problem Statement** submitted by NTRO: *Security Assessment of the World Monitor Application*.

## Overview
This is not a generic vulnerability scanner. It is a highly specialized, evidence-driven security assessment platform built to analyze the provided "World Monitor" application data and codebase. It automatically identifies security weaknesses, maps out attack vectors, assesses risk using CVSS, and provides developer-focused remediation strategies.

### Core Features
- **Dataset Ingestion Engine**: Parses and normalizes specialized SIH datasets (like the IAEA Critical Infrastructure Database and OSINT channel configs).
- **Modular Security Engine**: Pluggable Python-based architecture for checking Authentication, Data Privacy, Input Validation, and more.
- **Evidence-Based Findings**: Every vulnerability includes raw extracted JSON/code evidence explaining *exactly* why it was flagged.
- **Professional SOC Dashboard**: A dark-mode, glassmorphism-themed React dashboard that allows analysts to review vulnerabilities, severities, and remediation steps.
- **Automated Reporting**: Generates a professional Markdown-based executive summary and technical report.

## Architecture

```text
SIH Dataset / World Monitor Resources
                ↓
        Data & Source Ingestion (dataset_ingestor.py)
                ↓
        Security Assessment Engine (security/base.py)
                ↓
 ┌──────────────┼─────────────────┐
 ↓              ↓                 ↓
Authentication  Data Privacy      API Security
Testing         Testing           Testing
                ↓
        Finding Detection & Evidence Collection
                ↓
       SQLite Relational Database (models.py)
                ↓
       FastAPI Backend API (main.py)
                ↓
       React + Vite Dashboard (Dashboard.jsx)
                ↓
      Detailed Security Report (report_generator.py)
```

## Getting Started

### 1. Backend Setup
Ensure you have Python 3 installed.
```bash
# Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install requirements
pip install -r backend/requirements.txt

# Run the automated scan (ingests data and populates DB)
python backend/run_scan.py

# Start the FastAPI backend server
uvicorn backend.main:app --host 0.0.0.0 --port 8000
```
*The API will be available at `http://localhost:8000`*

### 2. Frontend Setup
Ensure you have Node.js and npm installed.
```bash
cd frontend
npm install
npm run dev
```
*The dashboard will be available at `http://localhost:5173`*

### 3. Generate Reports
To automatically generate a professional security assessment report (`SECURITY_REPORT.md`):
```bash
source venv/bin/activate
python -m backend.report_generator
```

## Security & Ethics
This platform strictly adheres to the SIH ethical guidelines. It performs **static analysis and dataset introspection only**. There are no denial-of-service, data destruction, or active exploitation payloads included. Findings marked as `[Demo / Simulated]` are placeholders demonstrating platform capabilities where the full source code was not provided.
