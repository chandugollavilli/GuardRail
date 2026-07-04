# 🛡️ GuardRail AI

> High-Performance LLM DLP Proxy & Telemetry Dashboard

GuardRail AI is a lightweight reverse proxy that prevents sensitive information from being leaked to external LLMs.

---

## ✨ Features

- Detects 16 categories of sensitive data
- Automatic redaction
- Optional NVIDIA NIM validation
- Real-time telemetry dashboard
- Zero dependencies
- Interactive playground

---

## 🏗️ Architecture

```text
Employee Client
      │
      ▼
 GuardRail Proxy
      │
 ├── Scan Prompt
 ├── Detect Secrets
 ├── Redact
 ├── Log Telemetry
 └── Forward to LLM
      │
      ▼
 OpenAI / NVIDIA / Anthropic
```

---

## 🔍 Detection Categories

### API Keys
- AWS
- Azure
- GCP
- JWT
- Database URLs
- API Keys

### PII
- Emails
- Phone Numbers
- Credit Cards
- Aadhaar
- PAN
- IP Addresses

### Intellectual Property
- Private Keys
- Source Code

### Company Data
- Financial Information
- Internal Documents
- Trade Secrets

---

## 📂 Project Structure

```
GuardRail/
│
├── server.py
├── public/
│   ├── index.html
│   ├── styles.css
│   └── app.js
├── README.md
```

---

## 🚀 Installation

```bash
git clone https://github.com/chandugollavilli/GuardRail.git
cd GuardRail
python server.py
```

Open

http://localhost:5000

---

## 🧪 Demo

Use the Playground and try payloads containing

- AWS Keys
- JWT
- Credit Cards
- Emails
- Phone Numbers

GuardRail will redact them automatically.

---

## 📊 Dashboard

- Real-time metrics
- Detection logs
- SVG charts
- Rule configuration
- Audit history

---

## 📜 License

MIT
