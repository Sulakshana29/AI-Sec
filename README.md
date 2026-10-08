# Enterprise LLM Security Gateway 🛡️

A lightweight, high-performance reverse proxy built with FastAPI that sits between internal client applications and upstream LLM providers (Google Gemini / OpenAI). It enforces security guardrails mapped to the **OWASP Top 10 for LLMs**.

## Features
- **Prompt Injection Firewall:** Blocks malicious jailbreak attempts pre-flight.
- **PII Redaction (DLP):** Strips emails and credit card numbers from prompts before they leave the corporate network.
- **Outbound Secret Scanning:** Intercepts LLM responses to prevent the leakage of AWS keys and passwords.
- **SIEM-Ready Telemetry:** Outputs structured JSON audit logs for easy ingestion into Wazuh, Splunk, or ELK.

## Architecture
The proxy abstracts API keys away from the client, handling all authentication with the upstream provider securely via environment variables. It operates as a stateless microservice, making it highly scalable in Kubernetes or ECS environments.

## Quick Start (Docker)

1. **Add your API Key:**
   Ensure you have a `.env` file in the root directory with your Google AI Studio key:
   ```env
   GEMINI_API_KEY=your_key_here
   ```
2. **Deploy with Docker Compose:**
   ```bash
   docker-compose up --build -d
   ```
3. **Test the API:**
   Navigate to `http://localhost:8000/docs` to use the Swagger UI.

## Testing the Guardrails (Offline Mode)
You can test the Outbound Data Leak Prevention without needing an active upstream connection by visiting the built-in mock route in your browser:
`http://localhost:8000/test-dlp`
