<img width="1920" height="918" alt="image" src="https://github.com/user-attachments/assets/d80637cb-86cf-4caa-8acd-50f5d93cd000" />
<img width="1920" height="905" alt="image" src="https://github.com/user-attachments/assets/27fb0dc8-8780-4173-b779-a251c3b3442b" />







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

MIT License

Copyright (c) 2026 Chandu Gollavilli

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
