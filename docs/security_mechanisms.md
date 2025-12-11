# Security Mechanisms Across the Lifecycle

This document defines security mechanisms that are embedded in every phase of the development life cycle. Each item states **what** the mechanism is, **where** it applies, **how** it is controlled, and **why** it is useful.

## Lifecycle Coverage

### Inception / Requirements
- **Abuse-case and threat modeling workshops**
  - **Where**: During requirements elaboration and backlog grooming.
  - **Control**: Required checklist in story definition of ready; findings logged as security user stories.
  - **Why**: Ensures risk-driven requirements and explicit acceptance criteria for security.
- **Data classification and handling rules**
  - **Where**: Requirements and architecture definition.
  - **Control**: Reference matrix in the project wiki; mandatory tag on stories that touch sensitive data.
  - **Why**: Avoids improper storage/transport of PII and secrets.

### Architecture / Design
- **Security patterns catalog (e.g., signed reset tokens, MFA, rate limiting)**
  - **Where**: Architecture decision records (ADR) and design specs.
  - **Control**: ADR template requires chosen pattern, alternatives, and rationale; peer review by security champion.
  - **Why**: Promotes consistent, battle-tested solutions.
- **Zero-trust integration points**
  - **Where**: Interface contracts between services.
  - **Control**: API definition must include authn/authz and audit requirements; design review gate before implementation.
  - **Why**: Minimizes implicit trust between components.

### Implementation
- **Secure coding checklists and linters**
  - **Where**: Pull requests and pre-commit hooks.
  - **Control**: `ruff`/`bandit` linters and `pre-commit` enforce style and basic security rules; failing checks block merges.
  - **Why**: Catches common issues (injection, unsafe APIs) early.
- **Secrets management**
  - **Where**: Local development and CI.
  - **Control**: `.env.example` plus vault-backed CI secrets; secret scanning (`gitleaks`) runs in CI.
  - **Why**: Prevents credential leakage and hard-coded secrets.

### Verification / Testing
- **Security-focused automated tests**
  - **Where**: Unit/integration test suites and CI pipelines.
  - **Control**: STDD stories must include abuse-case tests; failing tests block merges.
  - **Why**: Regression protection for mitigations.
- **Dynamic and dependency scanning**
  - **Where**: CI nightly/weekly jobs.
  - **Control**: `owasp zap` baseline or `pip-audit`/`npm audit` reports; severity threshold drives ticket creation.
  - **Why**: Detects runtime configuration gaps and vulnerable libraries.

### Release / Deployment
- **Artifact signing and provenance**
  - **Where**: Build pipeline outputs.
  - **Control**: Sigstore/cosign signing of images or packages; verification step before deployment.
  - **Why**: Ensures tamper evidence and trusted releases.
- **Infrastructure as Code policy checks**
  - **Where**: Terraform/Kubernetes manifests.
  - **Control**: `tfsec`/`kube-score` in CI; failing policies block deploys.
  - **Why**: Prevents misconfigurations (open security groups, privilege escalation).

### Operations / Monitoring
- **Security observability (logs, metrics, traces)**
  - **Where**: Runtime services and platform.
  - **Control**: Structured security logs routed to SIEM; alerting rules for auth failures, rate-limit trips, and policy violations.
  - **Why**: Enables rapid detection and response.
- **Continuous assurance**
  - **Where**: Post-deploy health checks and periodic reviews.
  - **Control**: Automated canary tests for security controls; quarterly threat model refresh and tabletop incident exercises.
  - **Why**: Keeps controls effective as the system evolves.

## Tooling and Purpose
- **PlantUML plugin for Visual Paradigm**: Export Secure Tropos and DSM models for STDD prompts.
- **Static analysis**: `ruff`, `bandit` for Python; enforce coding and security rules.
- **Secret scanning**: `gitleaks` to prevent credential commits.
- **Dependency audit**: `pip-audit` to flag vulnerable packages.
- **Dynamic testing**: `owasp zap` baseline scans for HTTP endpoints.
- **Artifact signing**: `cosign` for container and package integrity.
- **Observability stack**: Centralized logging/SIEM plus alerting for security signals.

## Integration into the STDD Cycle

| STDD Phase | Security Mechanisms | Tools/Controls |
| --- | --- | --- |
| **Specify** | Threat model updates, security user stories, pattern selection | PlantUML plugin, ADR template |
| **Test** | Security test design (abuse cases, fuzz cases) | Pytest, OWASP ZAP scripts |
| **Design** | Pattern application, trust boundary definitions | PlantUML/Visual Paradigm exports, ADR reviews |
| **Develop** | Secure coding checklist, linters, secret management | ruff, bandit, pre-commit, gitleaks |
| **Verify** | Automated tests and scans in CI | pytest, pip-audit, zap, cosign verify |
| **Deploy** | Signed artifacts, IaC policy checks | cosign, tfsec/kube-score |
| **Monitor** | Security observability, rate-limit dashboards | SIEM, metrics/alerts |

The [STDD security diagram](./stdd_security_diagram.puml) visualizes the customized flow for the final development iteration.
