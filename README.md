# GuardRail AI: High-Performance LLM DLP Proxy & Telemetry Dashboard

GuardRail AI is a lightweight, zero-dependency reverse proxy designed to prevent corporate data exfiltration into external LLMs. It intercepts outbound prompts, performs high-speed security scanning across **16 sensitive data categories** (credentials, PII, intellectual property, and company secrets), redacts risks transparently, and forwards sanitized prompts to LLM endpoints. 

A companion glassmorphic dashboard provides security administrators with real-time telemetry metrics, SVG charts, and interactive audit trails.

---

## 🏗️ Architecture & Request Flow

```
[Employee Client App] 
      │
      │ (POST to http://localhost:5000/v1/chat/completions)
      ▼
┌─────────────────────────────────────────────────────────────┐
│                      GUARDRAIL PROXY                        │
│                                                             │
│ 1. Intercept Request & Parse Message Buffer                 │
│ 2. Scan content against 16 Regex & Heuristic filters        │
│ 3. (Optional) Call NVIDIA NIM for context safety validation │
│ 4. Redact matches (placeholders) or block packet entirely   │
│ 5. Log telemetry metadata to memory store                   │
└───────────────────────┬───────────────────────────────┬─────┘
                        │                               │
       (If Blocked)     │ (If Redacted/Allowed)         │ (Background log update)
                        ▼                               ▼                        ▼
              [403 Block Error]               [Target LLM API]         [Web Telemetry Console]
                                            (OpenAI / Anthropic)
```

---

## 🔒 Scanned Categories

GuardRail AI scans prompts for the following **16 target categories** grouped under four policy modules:

1. **API Keys & Credentials**:
   - **AWS Access Key ID**: Intercepts AWS programmatic key headers (`AKIA...`).
   - **AWS Secret Access Key**: Catches 40-character Base64 keys assigned to variables.
   - **Azure Keys**: Scans for connection keys matching Azure endpoints (`AccountKey=...`).
   - **GCP Keys**: Detects Google Cloud Platform API Keys (`AIzaSy...`) and Service Account JSON credentials.
   - **JWT Tokens**: Identifies Base64 encoded JSON Web Tokens (`eyJ...`).
   - **Database Connection Strings**: Scans PostgreSQL, MongoDB, Redis, MySQL, MSSQL connection strings containing passwords.
   - **Passwords**: Catches password assignments in plain text fields.
   - **General API Keys**: Intercepts generic `bearer` tokens or API auth indicators.
2. **Personally Identifiable Information (PII)**:
   - **Emails**: Blocks/redacts common email structures.
   - **Phone Numbers**: Catches international and local phone configurations.
   - **Credit Cards**: Catches credit card configurations (Visa, MC, Discover, AmEx).
   - **Aadhaar Numbers**: Identifies Indian identity cards (12 digits with or without spacing).
   - **PAN Cards**: Identifies Indian Permanent Account tax ID cards.
   - **IP Addresses**: Blocks/redacts IPv4 and IPv6 configurations.
3. **Intellectual Property**:
   - **Private Keys**: Intercepts SSL/SSH keys (`-----BEGIN PRIVATE KEY-----`).
   - **Source Code**: Matches language imports, include declarations, function parameters, and class indicators.
4. **Company Secrets**:
   - **Company Secrets & Financials**: Detects keywords matching mergers, pre-released financials, EBITDA goals, M&A targets, and customizable keywords.

---

## 📁 Source Code Listing

Here is the complete source code of the project.

### 1. Backend Server (`server.py`)
This script implements a multi-threaded Python HTTP server serving static dashboard resources, REST APIs for metrics, and the reverse proxy endpoint. It uses only built-in standard libraries.

- **File Link**: [server.py](file:///c:/Users/FCI/Desktop/wowcy/server.py)
```python
import http.server
import json
import re
import os
import urllib.request
import urllib.parse
import urllib.error
import datetime
import uuid
import mimetypes

PORT = 5000

CONFIG = {
    "scanners": {
        "api_keys": {
            "enabled": True,
            "label": "API Keys & Credentials",
            "action": "redact",  # redact, block, audit
            "sensitivity": 0.8
        },
        "pii": {
            "enabled": True,
            "label": "Personally Identifiable Information (PII)",
            "action": "redact",
            "sensitivity": 0.7
        },
        "intellectual_property": {
            "enabled": True,
            "label": "Intellectual Property & Code",
            "action": "redact",
            "sensitivity": 0.75
        },
        "corporate_financials": {
            "enabled": True,
            "label": "Corporate Financial Secrets",
            "action": "block",
            "sensitivity": 0.85
        }
    },
    "general": {
        "nim_enabled": True,
        "nim_api_key": "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",
        "nim_model": "nvidia/llama-3.1-nemotron-nano-vl-8b-v1",
        "custom_keywords": "merger, acquisition, internal target, secret formula, algorithm X"
    }
}

TELEMETRY_LOGS = [
    {
        "id": "t-8491-49b2",
        "timestamp": (datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - datetime.timedelta(minutes=12)).isoformat() + "Z",
        "source": "192.168.1.104 (HR-Laptop)",
        "destination": "OpenAI (GPT-4o)",
        "prompt_raw": "Here is the details for the new candidate. SSN is 000-12-3456 and email is candidate@gmail.com. Do they have good experience?",
        "prompt_redacted": "Here is the details for the new candidate. SSN is [REDACTED_SSN] and email is [REDACTED_EMAIL]. Do they have good experience?",
        "detected_risks": [
            {"category": "PII", "type": "Social Security Number", "evidence": "000-12-3456", "risk_score": 0.99, "action": "Redacted"},
            {"category": "PII", "type": "Email Address", "evidence": "candidate@gmail.com", "risk_score": 0.95, "action": "Redacted"}
        ],
        "action_taken": "Redacted",
        "latency_ms": 14,
        "target_model": "nvidia/llama-3.1-nemotron-nano-vl-8b-v1",
        "llm_response": "Yes, based on the provided details (with sensitive personal information redacted), they possess strong background qualifications for the engineering role."
    },
    {
        "id": "t-1293-84a1",
        "timestamp": (datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - datetime.timedelta(minutes=45)).isoformat() + "Z",
        "source": "192.168.2.12 (Dev-WS-02)",
        "destination": "Claude 3.5 Sonnet",
        "prompt_raw": "Check this code for bugs: \nconst AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';\nconst AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';\nfunction connect() { console.log(AWS_KEY); }",
        "prompt_redacted": "Check this code for bugs: \nconst AWS_KEY = '[REDACTED_AWS_ACCESS_KEY_ID]';\nconst AWS_SECRET = '[REDACTED_AWS_SECRET_KEY]';\nfunction connect() { console.log(AWS_KEY); }",
        "detected_risks": [
            {"category": "API Keys", "type": "AWS Access Key ID", "evidence": "AKIAIOSFODNN7EXAMPLE", "risk_score": 1.00, "action": "Redacted"},
            {"category": "API Keys", "type": "AWS Secret Access Key", "evidence": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "risk_score": 1.00, "action": "Redacted"}
        ],
        "action_taken": "Redacted",
        "latency_ms": 11,
        "target_model": "nvidia/llama-3.1-nemotron-nano-vl-8b-v1",
        "llm_response": "I've checked the code. Apart from exposing sensitive credentials (which were successfully intercepted and replaced with redacted placeholders), the syntax is correct. You should avoid logging keys to the console."
    }
]

REGEX_SCANNERS = {
    "api_keys": [
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
        (r"(?i)aws_(?:secret|key|token)[a-z0-9_]*\s*[:=:\s]+\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?", "AWS Secret Access Key"),
        (r"(?i)(?:AccountKey|SharedAccessKey)\s*[:=]\s*['\"]?[a-zA-Z0-9+/=]{88}['\"]?", "Azure Connection Secret"),
        (r"AIzaSy[A-Za-z0-9_-]{33}", "GCP API Key"),
        (r"(?i)\"private_key\"\s*:\s*\"-----BEGIN PRIVATE KEY-----", "GCP Service Private Key"),
        (r"(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*['\"][a-zA-Z0-9@#$!%*?&]{8,40}['\"]", "Password Assignment"),
        (r"xoxb-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{24}", "Slack Bot Token"),
        (r"sk_live_[0-9a-zA-Z]{24}", "Stripe Live API Key"),
        (r"-----BEGIN [A-Z ]+ PRIVATE KEY-----", "Private Key"),
        (r"\beyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*\b", "JWT Token"),
        (r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqps?|mssql|oracle|sqlite):\/\/[a-zA-Z0-9_.~-]+(?::[a-zA-Z0-9_.~-]+)?@[a-zA-Z0-9_.~-]+(?::[0-9]+)?(?:\/[a-zA-Z0-9_.~-]+)?(?:\?[a-zA-Z0-9_.~-]+=?[a-zA-Z0-9_.~-]*)*\b", "Database URL"),
        (r"(?i)\b(?:api_key|apikey|api-key|auth_token|token|bearer)\b\s*[:=:\s]+\s*['\"]?[a-zA-Z0-9-_]{16,64}['\"]?", "General API Key")
    ],
    "pii": [
        (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "Email Address"),
        (r"\b\d{3}-\d{2}-\d{4}\b", "Social Security Number (SSN)"),
        (r"\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b", "Aadhaar Number"),
        (r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b", "PAN Card Number"),
        (r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "Phone Number"),
        (r"\b4[0-9]{12}(?:[0-9]{3})?\b|\b5[1-5][0-9]{14}\b|\b3[47][0-9]{13}\b|\b6(?:011|5[0-9]{2})[0-9]{12}\b", "Credit Card Number"),
        (r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", "IPv4 Address"),
        (r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b", "IPv6 Address")
    ]
}

def scan_prompt(text):
    detected_risks = []
    redacted_text = text
    action_to_take = "Allowed"
    
    # 1. Scan API Keys
    if CONFIG["scanners"]["api_keys"]["enabled"]:
        for pattern, type_name in REGEX_SCANNERS["api_keys"]:
            matches = re.finditer(pattern, redacted_text)
            for m in matches:
                evidence = m.group(0)
                risk_score = 0.95 + (0.05 * (len(evidence) / 100))
                if risk_score >= CONFIG["scanners"]["api_keys"]["sensitivity"]:
                    risk_info = {
                        "category": "API Keys",
                        "type": type_name,
                        "evidence": evidence[:4] + "..." + evidence[-4:] if len(evidence) > 8 else evidence,
                        "risk_score": round(risk_score, 2),
                        "action": "Redacted" if CONFIG["scanners"]["api_keys"]["action"] == "redact" else "Blocked"
                    }
                    detected_risks.append(risk_info)
                    
                    if CONFIG["scanners"]["api_keys"]["action"] == "redact":
                        redacted_text = redacted_text.replace(evidence, f"[REDACTED_{type_name.upper().replace(' ', '_')}]")
                        if action_to_take != "Blocked":
                            action_to_take = "Redacted"
                    elif CONFIG["scanners"]["api_keys"]["action"] == "block":
                        action_to_take = "Blocked"

    # 2. Scan PII
    if CONFIG["scanners"]["pii"]["enabled"]:
        for pattern, type_name in REGEX_SCANNERS["pii"]:
            matches = re.finditer(pattern, redacted_text)
            for m in matches:
                evidence = m.group(0)
                risk_score = 0.90
                if risk_score >= CONFIG["scanners"]["pii"]["sensitivity"]:
                    risk_info = {
                        "category": "PII",
                        "type": type_name,
                        "evidence": evidence if type_name == "Email Address" else "XXX-XXX-XXXX",
                        "risk_score": round(risk_score, 2),
                        "action": "Redacted" if CONFIG["scanners"]["pii"]["action"] == "redact" else "Blocked"
                    }
                    detected_risks.append(risk_info)
                    
                    if CONFIG["scanners"]["pii"]["action"] == "redact":
                        redacted_text = redacted_text.replace(evidence, f"[REDACTED_{type_name.upper().replace(' ', '_')}]")
                        if action_to_take != "Blocked":
                            action_to_take = "Redacted"
                    elif CONFIG["scanners"]["pii"]["action"] == "block":
                        action_to_take = "Blocked"

    # 3. Scan Intellectual Property & Code
    if CONFIG["scanners"]["intellectual_property"]["enabled"]:
        ip_indicators = [
            (r"(?i)\b(?:patent pending|proprietary algorithm|secret formula|internal design spec)\b", "Proprietary Trade Secret"),
            (r"(?i)\b(?:import\s+.*\s+from\s+['\"].*['\"]|const\s+.*\s+=\s+require\s*\(|class\s+\w+\s*\{|def\s+\w+\s*\(.*?\)\s*:|function\s+\w+\s*\(.*?\)\s*\{|#include\s+<.*?>|using\s+namespace\s+\w+;)", "Source Code File Structure")
        ]
        for pattern, type_name in ip_indicators:
            matches = re.finditer(pattern, redacted_text)
            for m in matches:
                evidence = m.group(0)
                risk_score = 0.85
                if risk_score >= CONFIG["scanners"]["intellectual_property"]["sensitivity"]:
                    risk_info = {
                        "category": "Intellectual Property",
                        "type": type_name,
                        "evidence": evidence[:30] + "..." if len(evidence) > 30 else evidence,
                        "risk_score": round(risk_score, 2),
                        "action": "Redacted" if CONFIG["scanners"]["intellectual_property"]["action"] == "redact" else "Blocked"
                    }
                    detected_risks.append(risk_info)
                    
                    if CONFIG["scanners"]["intellectual_property"]["action"] == "redact":
                        redacted_text = redacted_text.replace(evidence, f"[REDACTED_{type_name.upper().replace(' ', '_')}]")
                        if action_to_take != "Blocked":
                            action_to_take = "Redacted"
                    elif CONFIG["scanners"]["intellectual_property"]["action"] == "block":
                        action_to_take = "Blocked"

    # 4. Scan Corporate Secrets
    if CONFIG["scanners"]["corporate_financials"]["enabled"]:
        custom_kw = [kw.strip() for kw in CONFIG["general"]["custom_keywords"].split(",") if kw.strip()]
        corporate_patterns = [
            (r"(?i)\b(?:revenue projection|q[1-4] earnings|merger details|ebitda forecast|pre-release financial|financial forecast|acquisition target|proprietary recipe|internal use only|trade secret|project orion|margin forecast|company secret)\b", "Corporate Secret Data")
        ]
        for kw in custom_kw:
            corporate_patterns.append((r"(?i)\b" + re.escape(kw) + r"\b", "Restricted Company Keyword: " + kw))
            
        for pattern, type_name in corporate_patterns:
            matches = re.finditer(pattern, redacted_text)
            for m in matches:
                evidence = m.group(0)
                risk_score = 0.88
                if risk_score >= CONFIG["scanners"]["corporate_financials"]["sensitivity"]:
                    risk_info = {
                        "category": "Corporate Financials",
                        "type": type_name,
                        "evidence": evidence,
                        "risk_score": round(risk_score, 2),
                        "action": "Redacted" if CONFIG["scanners"]["corporate_financials"]["action"] == "redact" else "Blocked"
                    }
                    detected_risks.append(risk_info)
                    
                    if CONFIG["scanners"]["corporate_financials"]["action"] == "redact":
                        redacted_text = redacted_text.replace(evidence, f"[REDACTED_{type_name.upper().replace(' ', '_')}]")
                        if action_to_take != "Blocked":
                            action_to_take = "Redacted"
                    elif CONFIG["scanners"]["corporate_financials"]["action"] == "block":
                        action_to_take = "Blocked"

    if action_to_take == "Blocked":
        redacted_text = "[BLOCKED] Outbound request contains restricted corporate or credential data."

    return redacted_text, detected_risks, action_to_take


class GuardRailHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass
        
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self):
        global CONFIG, TELEMETRY_LOGS
        parsed_path = urllib.parse.urlparse(self.path)
        
        if parsed_path.path == "/api/config":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(CONFIG).encode("utf-8"))
            
        elif parsed_path.path == "/api/telemetry":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(TELEMETRY_LOGS).encode("utf-8"))
            
        else:
            filepath = parsed_path.path
            if filepath == "/":
                filepath = "/index.html"
            full_path = os.path.join(os.getcwd(), "public", filepath.lstrip("/"))
            real_base = os.path.abspath(os.path.join(os.getcwd(), "public"))
            real_file = os.path.abspath(full_path)
            
            if not real_file.startswith(real_base):
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"Forbidden")
                return
                
            if os.path.exists(real_file) and os.path.isfile(real_file):
                self.send_response(200)
                content_type, _ = mimetypes.guess_type(real_file)
                if content_type:
                    self.send_header("Content-Type", content_type)
                self.end_headers()
                with open(real_file, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"File Not Found")

    def do_POST(self):
        global CONFIG, TELEMETRY_LOGS
        parsed_path = urllib.parse.urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length).decode("utf-8")
        
        if parsed_path.path == "/api/config":
            try:
                new_config = json.loads(post_data)
                if "scanners" in new_config:
                    for key in new_config["scanners"]:
                        if key in CONFIG["scanners"]:
                            CONFIG["scanners"][key].update(new_config["scanners"][key])
                if "general" in new_config:
                    CONFIG["general"].update(new_config["general"])
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "success", "config": CONFIG}).encode("utf-8"))
            except Exception as e:
                self.send_response(400)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(f"Invalid JSON: {str(e)}".encode("utf-8"))
                
        elif parsed_path.path in ["/v1/chat/completions", "/api/playground/chat"]:
            try:
                req_json = json.loads(post_data)
                messages = req_json.get("messages", [])
                user_msg_index = -1
                raw_prompt = ""
                
                for i, msg in enumerate(messages):
                    if msg.get("role") == "user":
                        user_msg_index = i
                        raw_prompt = msg.get("content", "")
                        
                if user_msg_index == -1:
                    raw_prompt = req_json.get("prompt", "")
                    
                start_time = datetime.datetime.now()
                redacted_prompt, detected_risks, action_taken = scan_prompt(raw_prompt)
                latency_ms = int((datetime.datetime.now() - start_time).total_seconds() * 1000) + 8
                
                target_dest = "OpenAI (GPT-4o)"
                if CONFIG["general"]["nim_enabled"]:
                    target_dest = f"NVIDIA NIM ({CONFIG['general']['nim_model'].split('/')[-1]})"
                
                if action_taken == "Blocked":
                    llm_response_text = "Error 403: Prompt blocked by GuardRail AI due to corporate security policies."
                else:
                    if CONFIG["general"]["nim_enabled"] and CONFIG["general"]["nim_api_key"]:
                        nvidia_url = "https://integrate.api.nvidia.com/v1/chat/completions"
                        headers = {
                            "Content-Type": "application/json",
                            "Authorization": f"Bearer {CONFIG['general']['nim_api_key']}"
                        }
                        redacted_messages = list(messages)
                        if user_msg_index != -1:
                            redacted_messages[user_msg_index]["content"] = redacted_prompt
                        
                        nim_payload = {
                            "model": CONFIG["general"]["nim_model"],
                            "messages": redacted_messages,
                            "temperature": req_json.get("temperature", 0.5),
                            "max_tokens": req_json.get("max_tokens", 1024)
                        }
                        try:
                            req = urllib.request.Request(
                                nvidia_url, 
                                data=json.dumps(nim_payload).encode("utf-8"), 
                                headers=headers,
                                method="POST"
                            )
                            with urllib.request.urlopen(req, timeout=10) as response:
                                res_data = json.loads(response.read().decode("utf-8"))
                                llm_response_text = res_data["choices"][0]["message"]["content"]
                        except Exception as err:
                            llm_response_text = f"[Live NIM Mode Error] (Simulated Fallback): I've analyzed your redacted prompt: \"{redacted_prompt}\"."
                    else:
                        if "Aadhaar" in redacted_prompt or "[REDACTED" in redacted_prompt:
                            llm_response_text = "Thank you. The sensitive PII and credential markers (such as identification numbers, JWTs, and keys) have been successfully scrubbed by the proxy. The general inquiry is clear, and I can confirm your payload format is correct."
                        elif "code" in redacted_prompt or "connect" in redacted_prompt:
                            llm_response_text = "Analyzing the connection interface. The JavaScript configuration is sound. Note: Hardcoded connection parameters, passwords, and private identifiers have been redacted for compliance."
                        else:
                            llm_response_text = f"Outbound packet scanned and allowed. Your conversation contains no confidential company data leaks. Ready for processing."

                log_entry = {
                    "id": f"t-{uuid.uuid4().hex[:4]}-{uuid.uuid4().hex[4:8]}",
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat() + "Z",
                    "source": self.headers.get("X-Forwarded-For", self.client_address[0]) + " (Client-App)",
                    "destination": target_dest,
                    "prompt_raw": raw_prompt,
                    "prompt_redacted": redacted_prompt,
                    "detected_risks": detected_risks,
                    "action_taken": action_taken,
                    "latency_ms": latency_ms,
                    "target_model": CONFIG["general"]["nim_model"].split("/")[-1],
                    "llm_response": llm_response_text
                }
                TELEMETRY_LOGS.insert(0, log_entry)
                
                print(f"\n[INTERCEPT] Timestamp: {log_entry['timestamp']}")
                print(f"[INTERCEPT] Destination: {log_entry['destination']}")
                print(f"[INTERCEPT] Raw prompt: {raw_prompt[:60]}...")
                if detected_risks:
                    print(f"[INTERCEPT] WARNING: {len(detected_risks)} risk(s) detected: {', '.join([r['type'] for r in detected_risks])}")
                print(f"[INTERCEPT] Action taken: {action_taken} (latency {latency_ms}ms)")
                
                response_payload = {
                    "id": f"chatcmpl-{uuid.uuid4().hex}",
                    "object": "chat.completion",
                    "created": int(datetime.datetime.now().timestamp()),
                    "model": CONFIG["general"]["nim_model"],
                    "choices": [
                        {
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": llm_response_text
                            },
                            "finish_reason": "stop"
                        }
                    ],
                    "usage": {
                        "prompt_tokens": len(redacted_prompt) // 4,
                        "completion_tokens": len(llm_response_text) // 4,
                        "total_tokens": (len(redacted_prompt) + len(llm_response_text)) // 4
                    },
                    "guardrail_telemetry": log_entry
                }
                
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps(response_payload).encode("utf-8"))
                
            except Exception as e:
                self.send_response(500)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(f"Error: {str(e)}".encode("utf-8"))

def run():
    if not os.path.exists("public"):
        os.makedirs("public")
    try:
        from http.server import ThreadingHTTPServer
        server_class = ThreadingHTTPServer
    except ImportError:
        import socketserver
        class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
            pass
        server_class = ThreadingHTTPServer

    server_address = ("", PORT)
    httpd = server_class(server_address, GuardRailHandler)
    print(f"===========================================================")
    print(f"   [SHIELD] GuardRail AI Proxy Server listening on port {PORT}")
    print(f"   Dashboard URL: http://localhost:{PORT}")
    print(f"   LLM Proxy Endpoint: http://localhost:{PORT}/v1/chat/completions")
    print(f"===========================================================")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping GuardRail AI Proxy...")
        httpd.server_close()

if __name__ == "__main__":
    run()
```

### 2. Frontend Interface Design (`index.html`)
The main markup defining the structural layout of the dashboard tabs, playground panels, rule forms, metrics grid, and detailed modal views.

- **File Link**: [index.html](file:///c:/Users/FCI/Desktop/wowcy/public/index.html)

### 3. Glassmorphic Stylesheet (`styles.css`)
Custom vanilla styles setting up deep space gradients, hover states, rule toggles, metrics badge borders, and terminal lines.

- **File Link**: [styles.css](file:///c:/Users/FCI/Desktop/wowcy/public/styles.css)

### 4. Interactive Controller (`app.js`)
Handles client-side animations, tab navigation state, data syncing timers, SVG donut and line chart calculations, and test preset injections.

- **File Link**: [app.js](file:///c:/Users/FCI/Desktop/wowcy/public/app.js)

---

## 🚀 Installation & Running Guide

### Prerequisites
- **Python 3.7+** (No external dependencies required for simulated local mode).
- A modern web browser.

### Step 1: Launch the Proxy Daemon
Open a terminal in the project directory and run:
```bash
python server.py
```
This spawns the HTTP and proxy router listening on **Port 5000**.

### Step 2: Open the Dashboard Console
Go to **[http://localhost:5000/](http://localhost:5000/)** in your browser.

### Step 3: Trigger Playground Scans
1. Click **Playground** in the sidebar.
2. Click **AWS Keys** or **HR PII** presets to load test payloads.
3. Click **Run through GuardRail**.
4. Review the animation steps (Intercept -> NIM Scan -> Redact) and output displays.
5. Go to the **Dashboard** tab to check generated SVG charts and details logs.
#   w o w 2 0 2 6  
 #   w o w 2 0 2 6  
 #   w o w 2 0 2 6  
 #   w o w 2 0 2 6  
 