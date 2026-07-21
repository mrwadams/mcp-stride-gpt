# Security Tests

Generate test cases that validate a mitigation actually works. For each targeted
threat, include at least one **positive** test (control works) and one
**negative** test (attack is blocked).

## Test types

- **Unit** — test individual security controls in isolation.
- **Integration** — test security controls working together.
- **Penetration** — simulate real-world attack scenarios.
- **Compliance** — verify adherence to security standards.

## Coverage areas

- **Authentication** — identity verification and access controls.
- **Authorization** — permission and privilege validation.
- **Input validation** — data sanitization and bounds checking.
- **Encryption** — data protection in transit and at rest.
- **Logging** — security event detection and recording.

## Formats

**Gherkin** (default) — Given-When-Then behaviour-driven scenarios:

```gherkin
Feature: API Authentication
  Scenario: Unauthorized access attempt
    Given I am not authenticated
    When I attempt to access protected endpoint
    Then I should receive 401 Unauthorized
    And no sensitive data should be returned
```

**Checklist** — manual verification steps:

```
## SQL Injection Testing
- [ ] Test input validation with SQL metacharacters
- [ ] Verify parameterized queries are used
- [ ] Check error messages don't reveal database structure
- [ ] Test time-based blind injection
```

**Markdown** — structured test documentation:

```
### Test Case: XSS Protection
**Objective**: Verify XSS prevention in user input fields
**Steps**:
1. Submit XSS payload in username field
2. Verify output is properly escaped
3. Check CSP headers are present
**Expected**: Script tags rendered as text, not executed
```
