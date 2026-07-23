# STRIDE Framework

STRIDE is a systematic methodology for identifying security threats. Each letter
names a category of threat that violates a specific security property. Apply it
**per-element**: for every process, data store, data flow, external entity, and
trust boundary in the system, ask which threats in each category apply.

## The six categories

| | Category | Violates | Description |
|---|----------|----------|-------------|
| **S** | Spoofing | Authentication | Impersonating something or someone else |
| **T** | Tampering | Integrity | Modifying data or code |
| **R** | Repudiation | Non-repudiation | Claiming to have not performed an action |
| **I** | Information Disclosure | Confidentiality | Exposing information to unauthorised individuals |
| **D** | Denial of Service | Availability | Denying or degrading service availability |
| **E** | Elevation of Privilege | Authorization | Gaining capabilities without proper authorization |

### Threat examples by category

- **Spoofing** — authentication bypass; identity theft/impersonation; credential
  compromise; session hijacking; certificate/token forgery.
- **Tampering** — data manipulation/corruption; code injection attacks;
  configuration modification; message/request tampering; file/database alteration.
- **Repudiation** — insufficient audit logging; log tampering/deletion;
  non-repudiation failures; transaction denial; accountability gaps.
- **Information Disclosure** — unauthorised data access; sensitive information
  leakage; privacy violations; reconnaissance/enumeration; metadata exposure.
- **Denial of Service** — resource exhaustion; service flooding/overload;
  infrastructure disruption; performance degradation; availability attacks.
- **Elevation of Privilege** — authorization bypass; privilege escalation; access
  control violations; administrative compromise; permission boundary failures.

## STRIDE-per-element

Enumerate against structure, not from memory. For each element in the system:

1. Identify what the element is (process, data store, data flow, external entity)
   and which **trust boundaries** it sits on or crosses — a trust boundary is any
   point where the level of trust changes (user → app, app → database, service →
   third party, tenant → tenant).
2. Walk all six STRIDE categories against that element. Record threats that
   genuinely apply, and mark categories that do not apply as "N/A" **explicitly**
   — an unrecorded category is a coverage gap, not a decision.
3. Prefer specific threats ("unauthenticated read of the orders table via the
   internal reporting API") over generic ones ("SQL injection"). Specificity is
   what makes the model actionable and repeatable.

Trust boundaries and data flows are where most real threats live — give
component interfaces, data in transit, and privileged operations extra attention.

## Extended threat domains

Beyond the classic categories, select the domains relevant to the system's
architecture, technology stack, and deployment model:

- **Traditional web** — SQL injection, XSS, CSRF; authentication/authorization
  flaws; session management issues; input validation failures.
- **Cloud infrastructure** — misconfigured services/permissions;
  container/orchestration vulnerabilities; API gateway security issues;
  serverless function attacks.
- **AI/ML systems** — prompt injection; training-data poisoning;
  model extraction/inversion; adversarial examples; excessive AI agency;
  AI decision manipulation.
- **IoT/embedded** — firmware tampering; device impersonation; communication
  protocol attacks; physical access threats.
- **Mobile applications** — app tampering/repackaging; device-specific attacks;
  platform integration issues; local data storage threats.
- **API/microservices** — service-to-service authentication; API abuse / rate
  limiting; inter-service communication; service mesh security.
