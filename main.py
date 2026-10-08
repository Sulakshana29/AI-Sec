from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from google import genai
import os
import re
import logging
import json
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Initialize FastAPI app
app = FastAPI(title="LLM Security Gateway")

# ==========================================
# TELEMETRY & OBSERVABILITY
# ==========================================
# We log to a file so a SIEM agent (like Wazuh or Splunk) can read it
logging.basicConfig(
    filename='audit.log',
    level=logging.INFO,
    format='%(message)s'  # We only want the JSON string in the file
)

def log_audit_event(event_type: str, status: str, details: dict):
    """Logs structured JSON for SIEM ingestion."""
    log_entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event_type": event_type,
        "status": status,
        **details
    }
    logging.info(json.dumps(log_entry))

# Initialize Google GenAI client
# It automatically picks up GEMINI_API_KEY from the environment
api_key = os.getenv("GEMINI_API_KEY")
if not api_key:
    # Just a safety check to remind you if the key is missing
    print("WARNING: GEMINI_API_KEY is not set. Please set it in the .env file.")
    
client = genai.Client(api_key=api_key) if api_key else None

# Define the structure of the incoming request
class PromptRequest(BaseModel):
    prompt: str

# ==========================================
# INBOUND GUARDRAILS (Pre-call Inspection)
# ==========================================

def check_prompt_injection(prompt: str) -> bool:
    """Returns True if a prompt injection is detected."""
    malicious_phrases = [
        "ignore previous instructions",
        "ignore all previous",
        "system prompt",
        "disregard all",
        "bypass rules"
    ]
    prompt_lower = prompt.lower()
    for phrase in malicious_phrases:
        if phrase in prompt_lower:
            return True
    return False

def redact_pii(prompt: str) -> str:
    """Redacts basic emails and credit card numbers from the prompt."""
    # Redact Emails
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    redacted = re.sub(email_pattern, "[REDACTED EMAIL]", prompt)
    
    # Redact dummy credit cards (basic 16-digit check)
    cc_pattern = r'\b(?:\d[ -]*?){13,16}\b'
    redacted = re.sub(cc_pattern, "[REDACTED CC]", redacted)
    
    return redacted

# ==========================================
# OUTBOUND GUARDRAILS (Post-call Inspection)
# ==========================================

def check_outbound_secrets(response_text: str) -> bool:
    """Checks if the LLM accidentally leaked an API key or sensitive data."""
    # Look for things like AWS keys or hardcoded passwords
    forbidden_patterns = [
        r'AKIA[0-9A-Z]{16}', # Regex for an AWS Access Key
        r'password\s*=\s*[\'"][^\'"]+[\'"]' # Regex for a hardcoded password variable
    ]
    for pattern in forbidden_patterns:
        if re.search(pattern, response_text, re.IGNORECASE):
            return True
    return False

# ==========================================
# API ROUTES
# ==========================================

@app.post("/chat")
async def chat_with_llm(request: PromptRequest):
    """
    Phase 2: Inbound Guardrails
    Intercepts the prompt, checks for attacks and PII, then forwards to Gemini.
    """
    if not client:
         raise HTTPException(status_code=500, detail="Gemini API Client is not configured.")

    # 1. SECURITY CHECK: Prompt Injection
    if check_prompt_injection(request.prompt):
        # LOG THE ATTACK!
        log_audit_event("prompt_injection", "BLOCKED", {"prompt_length": len(request.prompt)})
        raise HTTPException(
            status_code=403, 
            detail="Security Policy Violation: Malicious prompt detected."
        )

    # 2. DATA PRIVACY: Redact PII
    safe_prompt = redact_pii(request.prompt)
    
    # LOG THE SAFE REQUEST
    was_redacted = safe_prompt != request.prompt
    log_audit_event("inbound_request", "ALLOWED", {"pii_redacted": was_redacted})

    try:
        # Forward the *safe, redacted* prompt to the Gemini model
        # We use gemini-3.8-flash as it is the latest, fast, and cost-effective model
        response = client.models.generate_content(
            model='gemini-3.8-flash',
            contents=safe_prompt
        )
        
        # 3. OUTBOUND DLP: Check for leaked secrets before returning to user
        if check_outbound_secrets(response.text):
            log_audit_event("outbound_dlp", "BLOCKED", {"reason": "leaked_secret"})
            raise HTTPException(
                status_code=500, 
                detail="Security Policy Violation: Upstream LLM attempted to leak sensitive data."
            )
            
        # LOG SUCCESS
        log_audit_event("outbound_response", "ALLOWED", {})
        
        # Return the LLM's response back to the user
        return {"response": response.text}
        
    except Exception as e:
        log_audit_event("upstream_error", "ERROR", {"error": str(e)})
        # If something goes wrong (e.g., invalid API key, Google servers down)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/test-dlp")
async def test_outbound_guardrail():
    """
    Simulates a scenario where the LLM accidentally leaks a secret.
    This lets us test the guardrail even if Google's servers are down.
    """
    # We pretend the AI returned this response
    fake_llm_response = "Here is the configuration you asked for. The AWS access key is AKIA1234567890ABCDEF."
    
    # 3. OUTBOUND DLP: Check for leaked secrets
    if check_outbound_secrets(fake_llm_response):
        log_audit_event("outbound_dlp_test", "BLOCKED", {"reason": "leaked_secret"})
        raise HTTPException(
            status_code=500, 
            detail="Security Policy Violation: Upstream LLM attempted to leak sensitive data."
        )
        
    return {"response": fake_llm_response}

@app.get("/")
async def health_check():
    """Simple health check endpoint to verify the gateway is running."""
    return {"status": "Gateway is active"}
