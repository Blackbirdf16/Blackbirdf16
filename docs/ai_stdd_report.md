# AI + STDD Final Iteration Report

## PlantUML Plugin Installation (Visual Paradigm)
1. Download the latest release from [PlantUML-VP-Plugin](https://github.com/nbourdi/PlantUML-VP-Plugin/).
2. In Visual Paradigm, open **Tools → Plugins → Install** and select the downloaded `.vpp` plugin file.
3. Restart Visual Paradigm; confirm **PlantUML Export** appears under **Tools**.
4. For each Secure Tropos or DSM diagram, use **Tools → PlantUML Export** to generate `.puml` files checked into version control.

## SUD Objective (Feature-Level)
- **Function**: Secure password-reset flow for end users.
- **Goal**: Issue and validate tamper-resistant, time-bound reset tokens while throttling abuse and logging security events.
- **Success criteria**: Tokens cannot be forged or replayed; expired tokens fail; more than *N* requests/hour per user are blocked; audit entries exist for every validation attempt.

## Domain Knowledge for the Feature
- **Entities**: `UserAccount`, `ResetToken`, `ResetPolicy`, `AuditEvent` (see [`dsm_model.puml`](./dsm_model.puml)).
- **Trust boundaries**: Token generation/validation happens inside the service with an HMAC secret; delivery happens through the email service (considered semi-trusted).
- **Constraints**: Secrets must stay outside source control; tokens must be URL-safe; clocks must be in UTC seconds.
- **Edge cases**: Replayed tokens, clock skew, disabled accounts, brute-force attempts exceeding rate limits.

## Security Solution Pattern
- **Pattern**: **Signed, time-bound reset token with rate limiting**.
  - **Mechanism**: HMAC-SHA256 over `{userId, issuedAt, nonce}`; Base64URL payload + signature; TTL enforced server-side; per-user issuance counter sliding over 1 hour; structured audit log on validation attempts.
  - **Placement**: Issuance in password reset endpoint; validation in token exchange endpoint; throttling in shared policy layer; auditing in security log sink.
  - **Controls**: Secret rotation policy; `hmac.compare_digest` for constant-time comparison; rejection on expired timestamps or mismatched signatures; counter reset every hour.
  - **Why useful**: Prevents token tampering/replay, limits abuse, and provides forensic traceability.
- **Associated tests**:
  - Happy path: issued token validates and returns the expected user id.
  - Expiration: tokens older than TTL are rejected.
  - Integrity: altering payload or signature causes validation failure.
  - Rate limiting: more than `rate_limit_per_hour` issuance attempts in an hour raises an error.
  - Auditability: validation attempts produce auditable events (logged/observable hook).

## STDD Application with AI Assistance
1. **Specify**: Captured the feature objective, trust boundaries, and security tests above; exported models with the plugin (`secure_tropos_model.puml`, `dsm_model.puml`).
2. **Test**: Wrote the pytest cases first to encode happy-path, expiration, integrity, and rate-limit behaviors (`tests/test_password_reset.py`).
3. **Design**: Selected the signed-token pattern and mapped it to the DSM; diagrammed the STDD flow in [`stdd_security_diagram.puml`](./stdd_security_diagram.puml).
4. **Develop**: Implemented `PasswordResetService` with HMAC signing, TTL enforcement, and rate limiting (`sud/password_reset.py`).
5. **Double iteration with AI**: First prompt would describe the feature without diagrams; the second prompt should include the PlantUML exports above to enrich the generation with domain and trust-boundary context.
6. **Verify**: Execute pytest and linters in CI; assess any gaps and refine diagrams accordingly.

## Results and Conclusions
- The pattern yields deterministic, testable behavior; abuse cases (expiration, tampering, flooding) are encoded as tests.
- PlantUML exports keep the AI prompt grounded in the agreed model, reducing ambiguity between iterations.
- Security mechanisms (rate limiting, HMAC integrity, audit logging hooks) are lightweight yet cover confidentiality, integrity, availability, and accountability needs.
- Future work: integrate persistent audit storage and externalize rate-limit counters to Redis for horizontal scaling.
