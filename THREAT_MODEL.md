# Threat Model: LLM Security Gateway

This document outlines the threats mitigated by this Security Gateway, mapped directly to the **OWASP Top 10 for Large Language Model Applications**.

## Mitigated Threats

### 1. Prompt Injection (OWASP LLM01)
- **Threat:** Attackers use crafted prompts to bypass LLM guardrails (e.g., "Ignore all previous instructions").
- **Mitigation:** The gateway acts as a pre-flight firewall, utilizing a heuristic engine to scan for known jailbreak phrases. If detected, the request is dropped with a `403 Forbidden` error before ever reaching the LLM provider.

### 2. Sensitive Information Disclosure (OWASP LLM06)
- **Threat (Inbound):** Internal users accidentally paste PII (Credit Cards, Emails, SSNs) into prompts, leaking data to third-party AI providers.
- **Mitigation (Inbound):** Regex and heuristic masking intercept the prompt and redact PII tokens (e.g., `[REDACTED EMAIL]`) before transmission.
- **Threat (Outbound):** The LLM is tricked into outputting proprietary secrets (e.g., AWS Access Keys, internal IP addresses).
- **Mitigation (Outbound):** The gateway intercepts the LLM's response. If a secret pattern is detected, the payload is destroyed and a `500 Security Violation` is returned to the client.

### 3. Insecure Plugin Design / Shadow AI (OWASP LLM07)
- **Threat:** Developers bypass corporate security by hitting OpenAI/Gemini endpoints directly from their workstations without logging.
- **Mitigation:** The gateway centralizes API key management. Clients do not possess the upstream API keys; they must route through this proxy. Every transaction is logged as structured JSON to `audit.log` for SIEM ingestion (e.g., Wazuh/ELK), ensuring 100% observability.
