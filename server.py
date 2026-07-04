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

# PORT Configuration
PORT = 5000

# Default scanner configuration
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

# Pre-populated telemetry logs for rich visualization
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
        "target_model": "nvidia/llama-3.1-nemoguard-8b",
        "llm_response": "Yes, based on the provided details (with sensitive personal information redacted), they possess strong background qualifications for the engineering role."
    },
    {
        "id": "t-1293-84a1",
        "timestamp": (datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - datetime.timedelta(minutes=45)).isoformat() + "Z",
        "source": "192.168.2.12 (Dev-WS-02)",
        "destination": "Claude 3.5 Sonnet",
        "prompt_raw": "Check this code for bugs: \nconst AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';\nconst AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';\nfunction connect() { console.log(AWS_KEY); }",
        "prompt_redacted": "Check this code for bugs: \nconst AWS_KEY = '[REDACTED_AWS_API_KEY]';\nconst AWS_SECRET = '[REDACTED_AWS_SECRET_KEY]';\nfunction connect() { console.log(AWS_KEY); }",
        "detected_risks": [
            {"category": "API Keys", "type": "AWS Access Key ID", "evidence": "AKIAIOSFODNN7EXAMPLE", "risk_score": 1.00, "action": "Redacted"},
            {"category": "API Keys", "type": "AWS Secret Access Key", "evidence": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "risk_score": 1.00, "action": "Redacted"}
        ],
        "action_taken": "Redacted",
        "latency_ms": 11,
        "target_model": "nvidia/llama-3.1-nemoguard-8b",
        "llm_response": "I've checked the code. Apart from exposing sensitive credentials (which were successfully intercepted and replaced with redacted placeholders), the syntax is correct. You should avoid logging keys to the console."
    },
    {
        "id": "t-9021-39c4",
        "timestamp": (datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - datetime.timedelta(hours=2)).isoformat() + "Z",
        "source": "192.168.1.88 (Finance-PC)",
        "destination": "OpenAI (GPT-4o)",
        "prompt_raw": "Can you draft a press release? Our internal revenue target was $42M but we only reached $38M due to the confidential acquisition of Project Orion delaying sales.",
        "prompt_redacted": "[BLOCKED] Outbound request contains restricted corporate financial and acquisition data.",
        "detected_risks": [
            {"category": "Corporate Financials", "type": "Acquisition Secrets", "evidence": "acquisition of Project Orion", "risk_score": 0.92, "action": "Blocked"},
            {"category": "Corporate Financials", "type": "Internal Sales Target Leak", "evidence": "internal revenue target was $42M", "risk_score": 0.88, "action": "Blocked"}
        ],
        "action_taken": "Blocked",
        "latency_ms": 18,
        "target_model": "nvidia/llama-3.1-nemoguard-8b",
        "llm_response": "Error 403: Prompt blocked by GuardRail AI due to corporate security policies governing confidential financial information."
    }
]

# Regex patterns for scanning
REGEX_SCANNERS = {
    "api_keys": [
        # AWS Keys
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
        (r"(?i)aws_(?:secret|key|token)[a-z0-9_]*\s*[:=:\s]+\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?", "AWS Secret Access Key"),
        # Azure Keys
        (r"(?i)(?:AccountKey|SharedAccessKey)\s*[:=]\s*['\"]?[a-zA-Z0-9+/=]{88}['\"]?", "Azure Connection Secret"),
        # GCP Keys
        (r"AIzaSy[A-Za-z0-9_-]{33}", "GCP API Key"),
        (r"(?i)\"private_key\"\s*:\s*\"-----BEGIN PRIVATE KEY-----", "GCP Service Private Key"),
        # Passwords
        (r"(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*['\"][a-zA-Z0-9@#$!%*?&]{8,40}['\"]", "Password Assignment"),
        # Slack / Stripe / Private Key
        (r"xoxb-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{24}", "Slack Bot Token"),
        (r"sk_live_[0-9a-zA-Z]{24}", "Stripe Live API Key"),
        (r"-----BEGIN [A-Z ]+ PRIVATE KEY-----", "Private Key"),
        # JWT Tokens
        (r"\beyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*\b", "JWT Token"),
        # Database URLs
        (r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqps?|mssql|oracle|sqlite):\/\/[a-zA-Z0-9_.~-]+(?::[a-zA-Z0-9_.~-]+)?@[a-zA-Z0-9_.~-]+(?::[0-9]+)?(?:\/[a-zA-Z0-9_.~-]+)?(?:\?[a-zA-Z0-9_.~-]+=?[a-zA-Z0-9_.~-]*)*\b", "Database URL"),
        # General API Keys
        (r"(?i)\b(?:api_key|apikey|api-key|auth_token|token|bearer)\b\s*[:=:\s]+\s*['\"]?[a-zA-Z0-9-_]{16,64}['\"]?", "General API Key")
    ],
    "pii": [
        # Emails & SSN
        (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "Email Address"),
        (r"\b\d{3}-\d{2}-\d{4}\b", "Social Security Number (SSN)"),
        # Aadhaar Numbers (Indian UID)
        (r"\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b", "Aadhaar Number"),
        # PAN Cards (Indian Permanent Account Number)
        (r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b", "PAN Card Number"),
        # Phone Numbers
        (r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "Phone Number"),
        # Credit Cards
        (r"\b4[0-9]{12}(?:[0-9]{3})?\b|\b5[1-5][0-9]{14}\b|\b3[47][0-9]{13}\b|\b6(?:011|5[0-9]{2})[0-9]{12}\b", "Credit Card Number"),
        # IP Addresses
        (r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", "IPv4 Address"),
        (r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b", "IPv6 Address")
    ]
}

def scan_prompt(text):
    """
    Scans prompt text against active configuration policies.
    Returns: (redacted_text, detected_risks, action_to_take)
    """
    detected_risks = []
    redacted_text = text
    action_to_take = "Allowed"  # Can escalate to "Redacted" or "Blocked"
    
    # 1. Scan API Keys
    if CONFIG["scanners"]["api_keys"]["enabled"]:
        for pattern, type_name in REGEX_SCANNERS["api_keys"]:
            matches = re.finditer(pattern, redacted_text)
            for m in matches:
                evidence = m.group(0)
                risk_score = 0.95 + (0.05 * (len(evidence) / 100)) # dynamic proxy score
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
                        "evidence": evidence if type_name == "Email Address" else (evidence[:3] + "-XX-XXXX" if "-" in evidence else "XXX-XXX-XXXX"),
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

    # 3. Scan Intellectual Property & Code Keywords
    if CONFIG["scanners"]["intellectual_property"]["enabled"]:
        # Keyword and basic heuristic scan for code/proprietary info
        ip_indicators = [
            (r"(?i)\b(?:patent pending|proprietary algorithm|secret formula|internal design spec)\b", "Proprietary Trade Secret"),
            # Matches standard imports, function signatures, includes, class syntax to verify source code exfiltration
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

    # 4. Scan Corporate Financial Secrets
    if CONFIG["scanners"]["corporate_financials"]["enabled"]:
        # Match custom keywords set in settings or standard corporate leak terms
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
        # Silence standard HTTP requests logging in python terminal unless it is errors, to keep logs clean
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
        
        # API Routes
        if parsed_path.path == "/api/config":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(CONFIG).encode("utf-8"))
            return
            
        elif parsed_path.path == "/api/telemetry":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(TELEMETRY_LOGS).encode("utf-8"))
            return
            
        # Serve frontend static files
        else:
            filepath = parsed_path.path
            if filepath == "/":
                filepath = "/index.html"
                
            # Base directory is public/
            full_path = os.path.join(os.getcwd(), "public", filepath.lstrip("/"))
            
            # Prevent directory traversal attacks
            real_base = os.path.abspath(os.path.join(os.getcwd(), "public"))
            real_file = os.path.abspath(full_path)
            
            if not real_file.startswith(real_base):
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"Forbidden")
                return
                
            if os.path.exists(real_file) and os.path.isfile(real_file):
                self.send_response(200)
                # Guess content type
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
        
        # 1. Update Config API
        if parsed_path.path == "/api/config":
            try:
                new_config = json.loads(post_data)
                # Simple merge config
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
            return

        # 2. Playground submission or actual OpenAI endpoint proxy
        elif parsed_path.path in ["/v1/chat/completions", "/api/playground/chat"]:
            try:
                req_json = json.loads(post_data)
                
                # Extract prompt text from messages array
                messages = req_json.get("messages", [])
                user_msg_index = -1
                raw_prompt = ""
                
                # Find the latest user message
                for i, msg in enumerate(messages):
                    if msg.get("role") == "user":
                        user_msg_index = i
                        raw_prompt = msg.get("content", "")
                
                if user_msg_index == -1:
                    # Fallback if no structured messages (e.g. legacy completions)
                    raw_prompt = req_json.get("prompt", "")
                
                # Process scanning and redaction
                start_time = datetime.datetime.now()
                redacted_prompt, detected_risks, action_taken = scan_prompt(raw_prompt)
                
                # Dynamic performance overhead (NIM processing speed simulation)
                # Standard regex/NLP scans are incredibly fast (10-25ms)
                latency_ms = int((datetime.datetime.now() - start_time).total_seconds() * 1000) + 8
                
                llm_response_text = ""
                
                # Decide destination description
                target_dest = "OpenAI (GPT-4o)"
                if CONFIG["general"]["nim_enabled"]:
                    target_dest = f"NVIDIA NIM ({CONFIG['general']['nim_model'].split('/')[-1]})"
                
                if action_taken == "Blocked":
                    llm_response_text = "Error 403: Prompt blocked by GuardRail AI due to corporate security policies."
                else:
                    # If live NVIDIA NIM is configured and enabled, try calling actual model
                    if CONFIG["general"]["nim_enabled"] and CONFIG["general"]["nim_api_key"]:
                        # Prepare payload for NVIDIA NIM
                        nvidia_url = "https://integrate.api.nvidia.com/v1/chat/completions"
                        headers = {
                            "Content-Type": "application/json",
                            "Authorization": f"Bearer {CONFIG['general']['nim_api_key']}"
                        }
                        
                        # Replace message contents with redacted version
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
                                # Extract answer
                                llm_response_text = res_data["choices"][0]["message"]["content"]
                        except Exception as err:
                            llm_response_text = f"[Live NIM Mode Error] Failed to fetch NIM completion: {str(err)}. (Falling back to simulated response below)\n\n[Simulated Response]: I've analyzed your input: \"{redacted_prompt}\". Here is the safe analysis requested."
                    else:
                        # Simulated LLM Completion logic depending on prompt type
                        if "SSN" in redacted_prompt or "[REDACTED" in redacted_prompt:
                            llm_response_text = "I've received your query. Please note that several pieces of sensitive information (such as credentials, PII or proprietary metrics) were securely redacted before reaching me. Based on the clean prompt, here is a general evaluation: The request represents standard data operations and can be processed safely."
                        elif "code" in redacted_prompt or "connect" in redacted_prompt:
                            llm_response_text = "Reviewing the provided code snippet. The structure of the function `connect` is syntactically sound. No obvious logic errors were found. Note: Any hardcoded secret parameters have been redacted for compliance."
                        else:
                            llm_response_text = f"Hello! As a security-aware LLM agent, I have processed your prompt. GuardRail AI has scanned the outbound packet and deemed it safe. Response: Your request is clear, and I can confirm that there are no corporate policy violations in this dialogue."

                # Log to memory database
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
                TELEMETRY_LOGS.insert(0, log_entry) # Put newest log at the top
                
                # Print to terminal output for developer showcase
                print(f"\n[INTERCEPT] Timestamp: {log_entry['timestamp']}")
                print(f"[INTERCEPT] Destination: {log_entry['destination']}")
                print(f"[INTERCEPT] Raw prompt: {raw_prompt[:60]}...")
                if detected_risks:
                    print(f"[INTERCEPT] WARNING: {len(detected_risks)} risk(s) detected: {', '.join([r['type'] for r in detected_risks])}")
                print(f"[INTERCEPT] Action taken: {action_taken} (latency {latency_ms}ms)")
                
                # Standard OpenAI Chat Completions Response Format
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
                    # Extra fields for GuardRail dashboard telemetry debugging
                    "guardrail_telemetry": log_entry
                }
                
                self.send_response(200)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps(response_payload).encode("utf-8"))
                
            except Exception as e:
                self.send_response(500)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(f"Error handling proxy request: {str(e)}".encode("utf-8"))
            return

        else:
            self.send_response(404)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(b"Not Found")


def run():
    # Make sure public folder exists
    if not os.path.exists("public"):
        os.makedirs("public")
        
    # Use ThreadingHTTPServer for concurrent handlers
    # Python 3.7+ supports ThreadingHTTPServer out of the box
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
