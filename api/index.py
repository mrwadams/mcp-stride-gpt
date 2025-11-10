#!/usr/bin/env python3

import sys
import os
import json
from http.server import BaseHTTPRequestHandler
import asyncio
from typing import Dict, Any
import traceback

# Import required modules for serverless environment
import uuid
import hashlib

# Enhanced error codes following MCP standards
ERROR_CODES = {
    'INVALID_PARAMETER': -32603,
    'TOOL_EXECUTION_FAILED': -32604,
    'INTERNAL_ERROR': -32603,
    'PAYLOAD_TOO_LARGE': -32600,
    'PAYLOAD_TOO_COMPLEX': -32600
}

# Payload validation limits
# These limits balance security (DoS prevention) with practical MCP usage
PAYLOAD_LIMITS = {
    'MAX_PAYLOAD_SIZE': 5_242_880,  # 5MB max payload size (increased for large threat models)
    'MAX_JSON_DEPTH': 20,            # Maximum nesting depth (MCP protocol + nested threat data)
    'MAX_OBJECT_KEYS': 500,          # Maximum keys in single object (rich threat metadata)
    'MAX_ARRAY_LENGTH': 2000,        # Maximum array length (large-scale threat assessments)
    'MAX_STRING_LENGTH': 500_000     # Maximum string length (500KB - detailed descriptions)
}

# Simplified tool implementations for Vercel deployment
# Note: These provide framework and guidance for LLM client analysis

def sanitize_error(error: Exception, error_context: str = "") -> tuple[str, str]:
    """
    Sanitize error messages to prevent information disclosure.

    Returns:
        tuple: (error_id, sanitized_message) where:
            - error_id: Unique identifier for correlating with server logs
            - sanitized_message: Generic error message safe for client

    Security measures:
        - Logs full error details to server logs (stderr)
        - Returns generic message to client
        - Generates unique error ID for correlation
        - Prevents leakage of: stack traces, file paths, internal implementation details
    """
    # Generate unique error ID for correlation
    error_id = str(uuid.uuid4())[:8]

    # Log detailed error information to server logs (stderr goes to Vercel logs)
    print(f"[ERROR {error_id}] Context: {error_context}", file=sys.stderr)
    print(f"[ERROR {error_id}] Exception Type: {type(error).__name__}", file=sys.stderr)
    print(f"[ERROR {error_id}] Exception Message: {str(error)}", file=sys.stderr)
    print(f"[ERROR {error_id}] Stack Trace:", file=sys.stderr)
    traceback.print_exc(file=sys.stderr)

    # Return generic message safe for client
    sanitized_message = f"An internal error occurred. Error ID: {error_id}"

    return error_id, sanitized_message

def validate_json_complexity(data: Any, current_depth: int = 0) -> Dict[str, Any]:
    """
    Recursively validate JSON complexity to prevent DoS attacks.

    Checks:
    - Maximum nesting depth
    - Maximum number of keys in objects
    - Maximum array length
    - Maximum string length

    Returns:
        Dict with 'valid' (bool) and 'error' (str) if invalid
    """
    # Check depth limit
    if current_depth > PAYLOAD_LIMITS['MAX_JSON_DEPTH']:
        return {
            'valid': False,
            'error': f"JSON nesting depth exceeds maximum of {PAYLOAD_LIMITS['MAX_JSON_DEPTH']}"
        }

    # Validate dictionaries/objects
    if isinstance(data, dict):
        # Check number of keys
        if len(data) > PAYLOAD_LIMITS['MAX_OBJECT_KEYS']:
            return {
                'valid': False,
                'error': f"Object contains {len(data)} keys, exceeds maximum of {PAYLOAD_LIMITS['MAX_OBJECT_KEYS']}"
            }

        # Recursively validate values
        for key, value in data.items():
            # Validate key length
            if isinstance(key, str) and len(key) > PAYLOAD_LIMITS['MAX_STRING_LENGTH']:
                return {
                    'valid': False,
                    'error': f"Object key length exceeds maximum of {PAYLOAD_LIMITS['MAX_STRING_LENGTH']}"
                }

            # Recursively validate value
            result = validate_json_complexity(value, current_depth + 1)
            if not result['valid']:
                return result

    # Validate arrays
    elif isinstance(data, list):
        # Check array length
        if len(data) > PAYLOAD_LIMITS['MAX_ARRAY_LENGTH']:
            return {
                'valid': False,
                'error': f"Array length {len(data)} exceeds maximum of {PAYLOAD_LIMITS['MAX_ARRAY_LENGTH']}"
            }

        # Recursively validate elements
        for item in data:
            result = validate_json_complexity(item, current_depth + 1)
            if not result['valid']:
                return result

    # Validate strings
    elif isinstance(data, str):
        if len(data) > PAYLOAD_LIMITS['MAX_STRING_LENGTH']:
            return {
                'valid': False,
                'error': f"String length {len(data)} exceeds maximum of {PAYLOAD_LIMITS['MAX_STRING_LENGTH']}"
            }

    # Other types (int, float, bool, None) are inherently safe

    return {'valid': True, 'error': None}


def get_stride_threat_framework(args: Dict[str, Any]) -> Dict[str, Any]:
    """Provide STRIDE threat modeling framework for LLM client analysis."""
    app_description = args.get('app_description', '')
    app_type = args.get('app_type', 'Web Application')
    auth_methods = args.get('authentication_methods', ['Username/Password'])
    internet_facing = args.get('internet_facing', True)
    sensitive_data = args.get('sensitive_data_types', ['User Data'])

    return {
        "stride_framework": {
            "description": "STRIDE threat modeling methodology for systematic security analysis",
            "categories": {
                "S": {
                    "name": "Spoofing",
                    "description": "Impersonating something or someone else",
                    "threat_examples": [
                        "Authentication bypass",
                        "Identity theft/impersonation",
                        "Credential compromise",
                        "Session hijacking",
                        "Certificate/token forgery"
                    ]
                },
                "T": {
                    "name": "Tampering",
                    "description": "Modifying data or code",
                    "threat_examples": [
                        "Data manipulation/corruption",
                        "Code injection attacks",
                        "Configuration modification",
                        "Message/request tampering",
                        "File/database alteration"
                    ]
                },
                "R": {
                    "name": "Repudiation",
                    "description": "Claiming to have not performed an action",
                    "threat_examples": [
                        "Insufficient audit logging",
                        "Log tampering/deletion",
                        "Non-repudiation failures",
                        "Transaction denial",
                        "Accountability gaps"
                    ]
                },
                "I": {
                    "name": "Information Disclosure",
                    "description": "Exposing information to unauthorized individuals",
                    "threat_examples": [
                        "Unauthorized data access",
                        "Sensitive information leakage",
                        "Privacy violations",
                        "Reconnaissance/enumeration",
                        "Metadata exposure"
                    ]
                },
                "D": {
                    "name": "Denial of Service",
                    "description": "Denying or degrading service availability",
                    "threat_examples": [
                        "Resource exhaustion",
                        "Service flooding/overload",
                        "Infrastructure disruption",
                        "Performance degradation",
                        "Availability attacks"
                    ]
                },
                "E": {
                    "name": "Elevation of Privilege",
                    "description": "Gaining capabilities without proper authorization",
                    "threat_examples": [
                        "Authorization bypass",
                        "Privilege escalation",
                        "Access control violations",
                        "Administrative compromise",
                        "Permission boundary failures"
                    ]
                }
            },
            "extended_threat_domains": {
                "traditional_web": [
                    "SQL injection, XSS, CSRF",
                    "Authentication/authorization flaws",
                    "Session management issues",
                    "Input validation failures"
                ],
                "cloud_infrastructure": [
                    "Misconfigured services/permissions",
                    "Container/orchestration vulnerabilities",
                    "API gateway security issues",
                    "Serverless function attacks"
                ],
                "ai_ml_systems": [
                    "Prompt injection attacks",
                    "Training data poisoning",
                    "Model extraction/inversion",
                    "Adversarial examples",
                    "Excessive AI agency",
                    "AI decision manipulation"
                ],
                "iot_embedded": [
                    "Firmware tampering",
                    "Device impersonation",
                    "Communication protocol attacks",
                    "Physical access threats"
                ],
                "mobile_applications": [
                    "App tampering/repackaging",
                    "Device-specific attacks",
                    "Platform integration issues",
                    "Local data storage threats"
                ],
                "api_microservices": [
                    "Service-to-service authentication",
                    "API abuse/rate limiting",
                    "Inter-service communication",
                    "Service mesh security"
                ]
            }
        },
        "application_context": {
            "app_description": app_description,
            "app_type": app_type,
            "authentication_methods": auth_methods,
            "internet_facing": internet_facing,
            "sensitive_data_types": sensitive_data
        },
        "analysis_guidance": "Use this STRIDE framework to systematically identify specific threats for the described application. Consider which extended threat domains are relevant based on the application's architecture, technology stack, and deployment model. The LLM client should analyze the application context and select appropriate threats from each STRIDE category and relevant threat domain.",
        "next_steps": {
            "recommended_workflow": [
                "1. Analyze application using STRIDE framework to identify specific threats",
                "2. Document each threat with ID, category, and description",
                "3. Call calculate_threat_risk_scores with your threat list",
                "4. Call validate_threat_coverage to check completeness",
                "5. Generate mitigations for high-priority threats"
            ],
            "optional_tools": [
                "create_threat_attack_trees - Visualize attack paths",
                "generate_security_tests - Create test cases"
            ]
        }
    }

def generate_threat_mitigations(args: Dict[str, Any]) -> Dict[str, Any]:
    """Provide mitigation framework for LLM client analysis."""
    threats = args.get('threats', [])
    priority_filter = args.get('priority_filter', 'all')

    return {
        "mitigation_framework": {
            "description": "Structured approach to generate threat mitigations",
            "categories": {
                "Preventive": "Controls that prevent threats from occurring",
                "Detective": "Controls that detect when threats occur",
                "Corrective": "Controls that respond to and recover from threats"
            },
            "difficulty_levels": {
                "Easy": "Can be implemented quickly with existing tools/processes",
                "Medium": "Requires moderate effort and possibly new tools",
                "Hard": "Requires significant resources, time, or architectural changes"
            },
            "priority_levels": {
                "High": "Critical security controls that should be implemented immediately",
                "Medium": "Important controls that should be planned for near-term implementation",
                "Low": "Nice-to-have controls for comprehensive defense"
            }
        },
        "threat_context": threats,
        "priority_filter": priority_filter,
        "analysis_guidance": "For each threat provided, generate specific, actionable mitigation strategies. Consider defense-in-depth principles and prioritize based on risk level and implementation difficulty.",
        "next_steps": {
            "after_mitigations": [
                "1. Call generate_security_tests to create test cases",
                "2. Call create_threat_attack_trees to visualize attack paths",
                "3. Call generate_threat_report to create deliverable document",
                "4. Implement high-priority preventive controls first"
            ]
        }
    }

def calculate_threat_risk_scores(args: Dict[str, Any]) -> Dict[str, Any]:
    """Provide DREAD scoring framework for LLM client analysis."""
    threats = args.get('threats', [])
    scoring_guidance = args.get('scoring_guidance', {})

    return {
        "dread_framework": {
            "description": "DREAD risk assessment methodology for threat prioritization",
            "scoring_criteria": {
                "Damage": {
                    "description": "How bad would an attack be?",
                    "scale": "1-10 (1=minimal damage, 10=complete system compromise)",
                    "factors": ["Financial impact", "Data sensitivity", "Regulatory consequences", "Business continuity"]
                },
                "Reproducibility": {
                    "description": "How easy is it to reproduce the attack?",
                    "scale": "1-10 (1=very difficult, 10=very easy)",
                    "factors": ["Attack complexity", "Required tools/skills", "Environmental dependencies"]
                },
                "Exploitability": {
                    "description": "How much work is it to launch the attack?",
                    "scale": "1-10 (1=very hard, 10=very easy)",
                    "factors": ["Technical skill required", "Time investment", "Resource requirements"]
                },
                "Affected_Users": {
                    "description": "How many users would be impacted?",
                    "scale": "1-10 (1=few users, 10=all users)",
                    "factors": ["User base size", "Impact scope", "Cascading effects"]
                },
                "Discoverability": {
                    "description": "How easy is it to discover the threat?",
                    "scale": "1-10 (1=very hard, 10=very easy)",
                    "factors": ["Visibility of attack surface", "Documentation availability", "Common vulnerability"]
                }
            },
            "risk_levels": {
                "Critical": "40-50 points - Immediate action required",
                "High": "30-39 points - High priority for remediation",
                "Medium": "20-29 points - Medium priority",
                "Low": "5-19 points - Low priority but should be addressed"
            }
        },
        "calibration_guidance": {
            "damage": {
                "1-3": "Minimal: Affects single user, non-critical functionality, easily recoverable",
                "4-6": "Moderate: Affects multiple users, important functionality, recovery required",
                "7-9": "High: Affects most users, critical functionality, difficult recovery",
                "10": "Catastrophic: Complete system compromise, all users affected, irrecoverable"
            },
            "reproducibility": {
                "1-3": "Difficult: Requires specific timing, race conditions, or rare circumstances",
                "4-6": "Moderate: Requires specific configuration or user actions",
                "7-9": "Easy: Reproducible with standard tools and documentation",
                "10": "Always: 100% reproducible, deterministic"
            },
            "exploitability": {
                "1-3": "Expert: Requires deep expertise, custom tools, significant time investment",
                "4-6": "Intermediate: Requires moderate skill, some tool customization",
                "7-9": "Basic: Standard tools and scripts available, minimal expertise needed",
                "10": "Trivial: No technical skill required, fully automated tools exist"
            },
            "affected_users": {
                "1-3": "Few: < 10% of users, isolated impact",
                "4-6": "Some: 10-50% of users, limited scope",
                "7-9": "Most: 50-90% of users, widespread impact",
                "10": "All: 100% of users affected, system-wide impact"
            },
            "discoverability": {
                "1-3": "Hidden: Requires source code review, insider knowledge, or deep analysis",
                "4-6": "Obscure: Requires investigation, testing, or documentation review",
                "7-9": "Obvious: Visible through normal usage or basic testing",
                "10": "Public: Documented, well-known, or immediately apparent"
            }
        },
        "scoring_examples": [
            {
                "threat": "SQL Injection in public-facing API endpoint",
                "context": "E-commerce website with customer database",
                "dread_breakdown": {
                    "Damage": {
                        "score": 10,
                        "rationale": "Complete database compromise, customer PII exposure, financial data theft"
                    },
                    "Reproducibility": {
                        "score": 9,
                        "rationale": "Easily reproducible with standard tools (SQLMap), well-documented technique"
                    },
                    "Exploitability": {
                        "score": 8,
                        "rationale": "Requires basic SQL knowledge, automated tools available, public exploits exist"
                    },
                    "Affected_Users": {
                        "score": 10,
                        "rationale": "All users' data potentially exposed, entire database accessible"
                    },
                    "Discoverability": {
                        "score": 9,
                        "rationale": "Common vulnerability, easily detected by automated scanners, OWASP Top 10"
                    },
                    "total": 46,
                    "priority": "Critical"
                }
            },
            {
                "threat": "Insufficient audit logging for admin actions",
                "context": "Internal business application",
                "dread_breakdown": {
                    "Damage": {
                        "score": 6,
                        "rationale": "Enables malicious activity without detection, complicates forensics, compliance risk"
                    },
                    "Reproducibility": {
                        "score": 10,
                        "rationale": "Always reproducible - logging is either present or not"
                    },
                    "Exploitability": {
                        "score": 5,
                        "rationale": "Requires legitimate admin access first, not directly exploitable"
                    },
                    "Affected_Users": {
                        "score": 7,
                        "rationale": "Affects incident response capability, impacts all users indirectly"
                    },
                    "Discoverability": {
                        "score": 6,
                        "rationale": "Requires code review or documentation review to discover"
                    },
                    "total": 34,
                    "priority": "High"
                }
            },
            {
                "threat": "Weak password policy (minimum 6 characters, no complexity)",
                "context": "Consumer web application",
                "dread_breakdown": {
                    "Damage": {
                        "score": 7,
                        "rationale": "Individual account compromise, potential for credential stuffing"
                    },
                    "Reproducibility": {
                        "score": 8,
                        "rationale": "Brute force attacks are reliable with weak passwords"
                    },
                    "Exploitability": {
                        "score": 7,
                        "rationale": "Requires password hash access or online brute force, standard tools available"
                    },
                    "Affected_Users": {
                        "score": 6,
                        "rationale": "Affects users who choose weak passwords, not all users"
                    },
                    "Discoverability": {
                        "score": 8,
                        "rationale": "Easily discoverable during registration or password change"
                    },
                    "total": 36,
                    "priority": "High"
                }
            },
            {
                "threat": "Missing CSRF protection on low-impact form",
                "context": "User preference settings update",
                "dread_breakdown": {
                    "Damage": {
                        "score": 3,
                        "rationale": "Limited to changing non-critical user preferences"
                    },
                    "Reproducibility": {
                        "score": 8,
                        "rationale": "Easily reproducible with standard CSRF techniques"
                    },
                    "Exploitability": {
                        "score": 6,
                        "rationale": "Requires social engineering to get user to visit malicious page"
                    },
                    "Affected_Users": {
                        "score": 4,
                        "rationale": "Affects individual users who fall victim to social engineering"
                    },
                    "Discoverability": {
                        "score": 7,
                        "rationale": "Detectable with automated security scanners"
                    },
                    "total": 28,
                    "priority": "Medium"
                }
            },
            {
                "threat": "Information disclosure via verbose error messages",
                "context": "Stack traces exposed to users in production",
                "dread_breakdown": {
                    "Damage": {
                        "score": 5,
                        "rationale": "Reveals internal structure, file paths, technology versions - aids reconnaissance"
                    },
                    "Reproducibility": {
                        "score": 7,
                        "rationale": "Reproducible by triggering error conditions"
                    },
                    "Exploitability": {
                        "score": 6,
                        "rationale": "Requires ability to trigger errors, not directly exploitable"
                    },
                    "Affected_Users": {
                        "score": 5,
                        "rationale": "Information disclosure to potential attackers, indirect user impact"
                    },
                    "Discoverability": {
                        "score": 8,
                        "rationale": "Easily discovered through normal usage and error triggering"
                    },
                    "total": 31,
                    "priority": "High"
                }
            }
        ],
        "threats": threats,
        "scoring_guidance": scoring_guidance,
        "analysis_guidance": "Score each threat using the DREAD criteria. Provide justification for each score based on the specific threat characteristics and application context.",
        "next_steps": {
            "after_scoring": [
                "1. Prioritize threats by DREAD score (Critical: 40-50, High: 30-39)",
                "2. Call validate_threat_coverage to ensure no gaps",
                "3. Call generate_threat_mitigations for high-priority threats",
                "4. Consider create_threat_attack_trees for critical threats"
            ]
        }
    }

def create_threat_attack_trees(args: Dict[str, Any]) -> Dict[str, Any]:
    """Provide attack tree framework for LLM client analysis."""
    threats = args.get('threats', [])
    max_depth = args.get('max_depth', 3)
    output_format = args.get('output_format', 'both')

    return {
        "attack_tree_framework": {
            "description": "Hierarchical representation of attack paths and methods",
            "structure": {
                "root_goal": "Primary objective the attacker wants to achieve",
                "sub_goals": "Intermediate objectives that support the root goal",
                "attack_methods": "Specific techniques or vulnerabilities that enable each sub-goal",
                "prerequisites": "Conditions or access required for each attack method"
            },
            "common_patterns": {
                "reconnaissance": ["Information gathering", "System enumeration", "Social engineering"],
                "initial_access": ["Phishing", "Credential stuffing", "Vulnerability exploitation"],
                "privilege_escalation": ["Local exploits", "Credential theft", "Authorization bypass"],
                "persistence": ["Backdoors", "Scheduled tasks", "Registry modification"],
                "exfiltration": ["Data staging", "Command and control", "Covert channels"]
            }
        },
        "output_formats": {
            "text": {
                "description": "ASCII tree structure using └── and ├── characters",
                "example": """Goal: Steal API Keys
├── [OR] Exploit Public Deployment
│   ├── Access public instance
│   └── Extract from browser
└── [OR] Exploit Local Deployment
    └── Read .env file"""
            },
            "mermaid": {
                "description": "Mermaid.js graph syntax for rendering diagrams",
                "example": """graph TD
    A[Steal API Keys] --> B{OR}
    B --> C[Exploit Public]
    B --> D[Exploit Local]
    C --> E[Access instance]
    C --> F[Extract from browser]
    D --> G[Read .env file]"""
            },
            "json": {
                "description": "Structured JSON representation",
                "example": {
                    "root": "Steal API Keys",
                    "type": "OR",
                    "children": [
                        {
                            "goal": "Exploit Public Deployment",
                            "methods": ["Access instance", "Extract from browser"]
                        }
                    ]
                }
            },
            "both": {
                "description": "Returns both text and mermaid formats",
                "note": "Current default, provides multiple visualization options"
            }
        },
        "threat_context": threats,
        "max_depth": max_depth,
        "output_format": output_format,
        "analysis_guidance": "Create attack trees showing how threats could be realized. Start with high-level attack goals and decompose into specific attack vectors and prerequisites."
    }

def generate_security_tests(args: Dict[str, Any]) -> Dict[str, Any]:
    """Provide security testing framework for LLM client analysis."""
    threats = args.get('threats', [])
    test_type = args.get('test_type', 'mixed')
    format_type = args.get('format_type', 'gherkin')

    return {
        "security_testing_framework": {
            "description": "Structured approach to validate threat mitigations through testing",
            "test_types": {
                "unit": "Test individual security controls in isolation",
                "integration": "Test security controls working together",
                "penetration": "Simulate real-world attack scenarios",
                "compliance": "Verify adherence to security standards"
            },
            "test_formats": {
                "gherkin": "Given-When-Then behavior-driven format",
                "procedural": "Step-by-step test procedures",
                "checklist": "Verification checklists"
            },
            "coverage_areas": {
                "authentication": "Identity verification and access controls",
                "authorization": "Permission and privilege validation",
                "input_validation": "Data sanitization and bounds checking",
                "encryption": "Data protection in transit and at rest",
                "logging": "Security event detection and recording"
            }
        },
        "use_cases": {
            "unit_testing": {
                "description": "Generate unit tests for security functions",
                "example": "Test input validation, authentication checks, authorization logic"
            },
            "integration_testing": {
                "description": "Generate integration tests for security flows",
                "example": "Test end-to-end authentication, authorization workflows"
            },
            "manual_testing": {
                "description": "Generate test cases for manual security testing",
                "example": "Penetration testing checklists, security review procedures"
            },
            "automated_security_scanning": {
                "description": "Generate test scenarios for security scanners",
                "example": "DAST tool configurations, security test automation"
            }
        },
        "format_examples": {
            "gherkin": {
                "description": "Behavior-driven development test scenarios",
                "example": """Feature: API Authentication
  Scenario: Unauthorized access attempt
    Given I am not authenticated
    When I attempt to access protected endpoint
    Then I should receive 401 Unauthorized
    And no sensitive data should be returned"""
            },
            "checklist": {
                "description": "Manual testing checklist",
                "example": """## SQL Injection Testing
- [ ] Test input validation with SQL metacharacters
- [ ] Verify parameterized queries are used
- [ ] Check error messages don't reveal database structure
- [ ] Test time-based blind injection"""
            },
            "markdown": {
                "description": "Structured test documentation",
                "example": """### Test Case: XSS Protection
**Objective**: Verify XSS prevention in user input fields
**Steps**:
1. Submit XSS payload in username field
2. Verify output is properly escaped
3. Check CSP headers are present
**Expected**: Script tags rendered as text, not executed"""
            }
        },
        "threat_context": threats,
        "test_type": test_type,
        "format_type": format_type,
        "analysis_guidance": "Generate specific test cases to validate that security controls effectively mitigate the identified threats. Include both positive and negative test scenarios."
    }

def generate_threat_report(args: Dict[str, Any]) -> str:
    """Generate threat report as formatted markdown string for LLM client analysis.

    CRITICAL: This function MUST return a string (the markdown report), not a dict.
    The MCP handler expects content[0].text to be a string.
    """
    threat_model = args.get('threat_model', [])
    mitigations = args.get('mitigations', [])
    dread_scores = args.get('dread_scores', [])
    attack_trees = args.get('attack_trees', [])
    include_sections = args.get('include_sections', ['executive_summary', 'threats', 'mitigations', 'risk_scores'])

    # Build the markdown report as a string
    report = "# STRIDE Threat Model Report\n\n"

    if 'executive_summary' in include_sections:
        report += """## Executive Summary

*This section should provide a high-level overview of the threat modeling exercise, key findings, and recommended actions.*

**Instructions for LLM client:**
- Summarize the total number of threats identified across STRIDE categories
- Highlight critical and high-priority threats
- Provide key recommendations for immediate action
- Include risk assessment summary

"""

    report += """## Application Overview

*Describe the application architecture, components, and security-relevant characteristics based on the application context used for threat modeling.*

"""

    if 'threats' in include_sections:
        report += """## Threat Analysis

*Detail the identified threats organized by STRIDE category. For each threat, include:*
- Threat ID
- Description
- STRIDE category
- Attack scenarios
- Potential impact

### Spoofing Threats
*List and describe spoofing-related threats (identity impersonation, authentication bypass)*

### Tampering Threats
*List and describe tampering-related threats (data/code modification)*

### Repudiation Threats
*List and describe repudiation-related threats (insufficient logging, accountability gaps)*

### Information Disclosure Threats
*List and describe information disclosure threats (unauthorized data access, privacy violations)*

### Denial of Service Threats
*List and describe denial of service threats (resource exhaustion, availability attacks)*

### Elevation of Privilege Threats
*List and describe privilege escalation threats (authorization bypass, access control violations)*

"""

    if 'risk_scores' in include_sections:
        report += """## Risk Assessment

*Provide DREAD scores and risk prioritization for identified threats.*

### Critical Priority Threats (DREAD: 40-50)
*Threats requiring immediate action*

### High Priority Threats (DREAD: 30-39)
*Threats requiring prompt remediation*

### Medium Priority Threats (DREAD: 20-29)
*Threats for near-term planning*

### Low Priority Threats (DREAD: 5-19)
*Threats for long-term consideration*

"""

    if 'mitigations' in include_sections:
        report += """## Recommended Mitigations

*Detail specific mitigation strategies organized by priority. For each mitigation:*
- Control type (Preventive/Detective/Corrective)
- Implementation difficulty (Easy/Medium/Hard)
- Priority level
- Specific implementation guidance

### High Priority Mitigations
*Critical security controls for immediate implementation*

### Medium Priority Mitigations
*Important controls for near-term planning*

### Low Priority Mitigations
*Additional defensive measures for comprehensive security*

"""

    report += """## Security Testing Plan

*Outline test cases to validate mitigation effectiveness. Include:*
- Test scenarios for each major threat
- Acceptance criteria
- Testing methodology (unit, integration, penetration)

## Implementation Roadmap

*Provide timeline and sequencing for mitigation implementation:*
- Phase 1 (0-30 days): Critical mitigations
- Phase 2 (30-90 days): High-priority mitigations
- Phase 3 (90+ days): Medium and low-priority mitigations

## Appendix

### Threat Model Data
*Technical details about the threat model*

**Total Threats Identified:** {threat_count}

### STRIDE Coverage
*Breakdown of threats by STRIDE category*

### References
*Standards, frameworks, and resources referenced*
- STRIDE Threat Modeling Methodology
- DREAD Risk Assessment Framework
- OWASP Top 10
- CWE/SANS Top 25

---

**Report Generated:** [Date]
**Threat Modeling Framework:** STRIDE
**Risk Scoring Method:** DREAD

*This report was generated using the STRIDE GPT MCP Server threat modeling framework. The LLM client should populate each section with specific analysis based on the provided threat model data.*
""".format(threat_count=len(threat_model) if isinstance(threat_model, list) else 0)

    return report

def validate_threat_coverage(args: Dict[str, Any]) -> Dict[str, Any]:
    """Provide coverage validation framework for LLM client analysis."""
    threat_model = args.get('threat_model', [])
    app_context = args.get('app_context', {})

    return {
        "coverage_framework": {
            "description": "Systematic validation of STRIDE threat model completeness",
            "stride_categories": {
                "S": "Spoofing - Verify all identity-related threats are considered",
                "T": "Tampering - Verify all data/code integrity threats are considered",
                "R": "Repudiation - Verify all accountability threats are considered",
                "I": "Information Disclosure - Verify all confidentiality threats are considered",
                "D": "Denial of Service - Verify all availability threats are considered",
                "E": "Elevation of Privilege - Verify all authorization threats are considered"
            },
            "validation_criteria": {
                "completeness": "All STRIDE categories addressed for each trust boundary",
                "specificity": "Threats are specific to the application context",
                "actionability": "Threats lead to implementable mitigations",
                "risk_alignment": "High-risk threats receive appropriate attention"
            },
            "common_gaps": {
                "trust_boundaries": "Missing threats at component interfaces",
                "data_flows": "Insufficient consideration of data in transit",
                "privileged_operations": "Inadequate coverage of admin functions",
                "error_conditions": "Missing threat consideration for edge cases"
            }
        },
        "threat_model": threat_model,
        "app_context": app_context,
        "analysis_guidance": "Review the threat model against this framework to identify coverage gaps. Ensure each STRIDE category is adequately represented for all trust boundaries and data flows."
    }

def get_repository_analysis_guide(args: Dict[str, Any]) -> Dict[str, Any]:
    """Provide structured framework for extracting threat modeling inputs from repository analysis."""
    analysis_stage = args.get('analysis_stage', 'initial')
    repo_context = args.get('repository_context', {})

    # Common framework returned for all stages
    base_framework = {
        "analysis_framework": {
            "description": "Structured approach to repository analysis for threat modeling",
            "stages": {
                "initial": {
                    "objective": "Quick scan to understand tech stack, architecture, and deployment model",
                    "target_files": "3-5 key files",
                    "focus": "High-level only",
                    "output": "Tech stack, deployment model, basic architecture"
                },
                "deep_dive": {
                    "objective": "Extract detailed security context for threat modeling",
                    "target_files": "10-15 targeted files/searches",
                    "focus": "Security-critical components only",
                    "output": "Trust boundaries, sensitive data, access controls"
                },
                "validation": {
                    "objective": "Verify sufficient context for threat modeling",
                    "target_files": "Review completeness",
                    "output": "Readiness assessment or identified gaps"
                }
            }
        },
        "context_management": {
            "description": "Efficient analysis principles to preserve context for threat modeling",
            "optimization_principles": [
                "When in doubt, search instead of read",
                "STOP after 3-5 file reads in initial stage - assess readiness",
                "STOP after 8-12 searches/reads in deep_dive - assess readiness",
                "Don't re-read files - reference previous reads by file path",
                "Search returns snippets; full reads return entire files",
                "Use file path references in threat descriptions, not code snippets"
            ],
            "stopping_checkpoints": {
                "after_initial": "After 3-5 file reads, STOP and ask: Can I identify app type, tech stack, deployment model? If yes, proceed to deep_dive. If no, read 1-2 more specific files.",
                "after_deep_dive": "After 8-12 searches/reads, STOP and ask: Can I populate the output_template fields? If yes, start threat modeling. If no, search for specific missing info only.",
                "principle": "Don't read for completeness - read until you have enough. More files = wasted context."
            },
            "decision_guidance": {
                "read_full_file_when": [
                    "You need specific configuration values (.env.example, config files)",
                    "File type is typically small (package.json, docker-compose.yml, README)",
                    "You need the complete architecture overview"
                ],
                "use_search_when": [
                    "Looking for patterns (authentication methods, authorization checks)",
                    "Examining application code (controllers, services, middleware)",
                    "File type is typically large (application logic, route handlers)",
                    "You need to understand 'how' something works, not specific values"
                ]
            }
        }
    }

    # Stage-specific guidance
    if analysis_stage == "initial":
        base_framework["prioritized_reading_strategy"] = {
            "description": "File reading strategy based on information value and typical file sizes",
            "read_these_files": {
                "priority": "Read first - typically small with high information density",
                "files": [
                    "README.md - architecture overview",
                    "package.json / requirements.txt / pom.xml - tech stack identification",
                    "docker-compose.yml / Dockerfile - deployment model",
                    ".env.example - integrations and required services"
                ],
                "characteristics": "Config and documentation files are usually small, contain specific values needed for threat modeling",
                "method": "Use mcp__github__get_file_contents"
            },
            "search_instead_of_read": {
                "priority": "Use code search to extract relevant snippets - avoid full reads",
                "patterns": [
                    "OpenAPI/Swagger specs - search for endpoint definitions",
                    "Auth middleware - search for 'authenticate' OR 'jwt.verify' patterns",
                    "Database models - search for 'model' OR 'schema' patterns",
                    "Controllers/routes - search for specific endpoints or patterns"
                ],
                "characteristics": "Application code files are typically large; search gives you relevant snippets without full file content",
                "method": "Use mcp__github__search_code with targeted queries"
            },
            "avoid_or_skip": {
                "priority": "Never read these fully - always use search or skip entirely",
                "files": [
                    "Application code files (controllers, services, handlers) - search instead",
                    "Database migrations - infer schema from models or search",
                    "Test files - usually not needed for threat modeling",
                    "Generated code / build artifacts - not relevant",
                    "Large documentation files - search for specific sections if needed"
                ],
                "alternative": "Use mcp__github__search_code with specific keywords"
            }
        }

        base_framework["initial_reconnaissance"] = {
            "files_to_examine_first": {
                "documentation": ["README.md", "ARCHITECTURE.md", "docs/architecture.*", "docs/design.*"],
                "package_managers": ["package.json", "requirements.txt", "pom.xml", "Cargo.toml", "go.mod", "Gemfile", "composer.json"],
                "containerization": ["docker-compose.yml", "Dockerfile", "docker-compose.yaml", ".dockerignore"],
                "configuration": [".env.example", "config/", "*.config.js", "*.config.ts", "application.yml", "appsettings.json"],
                "infrastructure": ["terraform/", "*.tf", "cloudformation/", "*.yaml", "kubernetes/", "k8s/", ".github/workflows/", ".gitlab-ci.yml"],
                "api_specs": ["openapi.yaml", "swagger.json", "schema.graphql", "*.proto"]
            },
            "extraction_patterns": {
                "authentication_mechanisms": {
                    "JWT": ["jsonwebtoken", "pyjwt", "jose", "jwt-decode", "auth0"],
                    "OAuth_2.0": ["passport", "passport-oauth2", "authlib", "spring-security-oauth2", "oauth2client"],
                    "Session-based": ["express-session", "django.contrib.sessions", "flask-session", "rack-session"],
                    "API_Keys": ["API key validation patterns in code", "x-api-key headers"],
                    "SAML_SSO": ["saml2", "passport-saml", "ruby-saml"],
                    "Multi-factor": ["speakeasy", "pyotp", "authy", "totp"]
                },
                "deployment_model": {
                    "Containerized_microservices": ["Dockerfile AND kubernetes/", "docker-compose with multiple services"],
                    "Serverless_functions": ["serverless.yml", "sam-template.yaml", "netlify.toml", "vercel.json with functions"],
                    "Multi-container_application": ["docker-compose.yml with multiple services"],
                    "Client-side_SPA": ["Static hosting config", "Build output to dist/ or build/"],
                    "Traditional_server": ["Server configuration files", "No containerization"]
                },
                "technology_stack": {
                    "Frontend": {
                        "React": ["react", "react-dom in dependencies"],
                        "Vue": ["vue in dependencies"],
                        "Angular": ["@angular/core"],
                        "Svelte": ["svelte in dependencies"],
                        "Next.js": ["next in dependencies"]
                    },
                    "Backend": {
                        "Express": ["express in dependencies"],
                        "FastAPI": ["fastapi in requirements"],
                        "Django": ["django in requirements"],
                        "Spring_Boot": ["spring-boot in pom.xml/gradle"],
                        "Rails": ["rails in Gemfile"],
                        "Flask": ["flask in requirements"]
                    },
                    "Database": {
                        "PostgreSQL": ["pg", "psycopg2", "postgresql"],
                        "MongoDB": ["mongodb", "mongoose", "pymongo"],
                        "MySQL": ["mysql", "mysql2", "mysqlclient"],
                        "Redis": ["redis", "ioredis"],
                        "DynamoDB": ["aws-sdk dynamodb", "boto3 dynamodb"]
                    },
                    "Message_Queues": ["rabbitmq", "kafka", "aws-sdk sqs", "celery"],
                    "Caching": ["redis", "memcached", "node-cache"]
                }
            }
        }

    elif analysis_stage == "deep_dive":
        primary_lang = repo_context.get('primary_language', '').lower()
        framework = repo_context.get('framework_detected', '').lower()

        base_framework["deep_dive_analysis"] = {
            "trust_boundaries": {
                "external_boundaries": {
                    "description": "Entry points from untrusted sources",
                    "locations_to_examine": [
                        "Public API endpoints (routes, controllers, handlers)",
                        "Authentication entry points (login, registration, password reset)",
                        "File upload handlers and multipart form processors",
                        "Webhook receivers and callback endpoints",
                        "GraphQL/gRPC/WebSocket endpoints",
                        "Public-facing web pages and forms"
                    ]
                },
                "internal_boundaries": {
                    "description": "Trust transitions within the system",
                    "locations_to_examine": [
                        "Service-to-service communication (microservices)",
                        "Database access layers and query builders",
                        "Admin/privileged functionality and dashboards",
                        "Background job processors and queues",
                        "Third-party API integrations and SDKs",
                        "Shared libraries and common modules"
                    ]
                }
            },
            "code_patterns_to_analyze": {
                "sensitive_data_handling": {
                    "user_models": "Models/schemas with email, password, name, address, phone, SSN",
                    "payment_processing": "Stripe, PayPal, payment gateway integrations",
                    "healthcare_data": "HIPAA-related fields, patient records, PHI",
                    "financial_data": "Transaction models, account balances, trading data",
                    "credentials_secrets": "API keys, tokens, certificates, encryption keys",
                    "files_to_check": ["models/", "schemas/", "entities/", "domain/", "database/migrations/"]
                },
                "access_control_patterns": {
                    "middleware_decorators": "@require_auth, @admin_only, @permission_required, authenticate middleware",
                    "rbac_implementations": "Role and permission models, access control lists",
                    "row_level_security": "Multi-tenancy, data isolation patterns",
                    "admin_functionality": "Admin panels, privileged operations",
                    "files_to_check": ["middleware/", "decorators/", "guards/", "policies/", "permissions/"]
                },
                "data_flow_analysis": {
                    "request_handling": "Request → Validation → Processing → Storage flow",
                    "user_input": "Form handling, API body parsing, query parameters",
                    "serialization": "Data transformation, API responses, template rendering",
                    "logging_audit": "Security event logging, audit trails, activity logs",
                    "files_to_check": ["routes/", "controllers/", "handlers/", "api/", "views/"]
                },
                "external_dependencies": {
                    "third_party_apis": "Payment, authentication, analytics services",
                    "cloud_services": "AWS S3, SQS, Lambda, Azure, GCP services",
                    "cdn_assets": "Static asset hosting, CDN configuration",
                    "communication": "Email (SendGrid, SES), SMS (Twilio)",
                    "monitoring": "Sentry, DataDog, New Relic, logging services",
                    "files_to_check": ["package.json/requirements.txt dependencies", "config/", "services/", "integrations/"]
                }
            }
        }

        # Add technology-specific guides
        base_framework["technology_guides"] = {
            "web_applications": {
                "applicable_if": "React/Vue/Angular + Node.js/Django/Rails + Database",
                "key_files": [
                    "src/routes/ or src/controllers/ - API endpoints and routing",
                    "src/middleware/auth.* - Authentication and authorization",
                    "src/models/ or src/schemas/ - Database schemas and sensitive fields",
                    "src/services/ - Business logic and external integrations",
                    ".env.example - Configuration template and required secrets"
                ],
                "security_focus": [
                    "API authentication and authorization patterns",
                    "CORS configuration and origin validation",
                    "Session management and token handling",
                    "Input validation and sanitization libraries",
                    "Database query patterns (prepared statements vs. string concatenation)"
                ]
            },
            "api_services": {
                "applicable_if": "FastAPI, Express, Django REST, Spring Boot, ASP.NET Core",
                "key_files": [
                    "Route/endpoint definitions and handlers",
                    "Authentication middleware and security filters",
                    "Input validation schemas (Pydantic, Joi, Bean Validation)",
                    "Database ORM models and repositories",
                    "API documentation (OpenAPI/Swagger specs)"
                ],
                "security_focus": [
                    "OAuth 2.0 / JWT implementation and validation",
                    "Rate limiting and request throttling",
                    "API versioning and backward compatibility",
                    "Input validation and type safety",
                    "Error handling and information disclosure prevention"
                ]
            },
            "cloud_infrastructure": {
                "applicable_if": "Terraform, CloudFormation, Pulumi, CDK",
                "key_files": [
                    "*.tf or *.yaml - Infrastructure definitions",
                    "IAM roles, policies, and permission boundaries",
                    "Security groups, NACLs, firewall rules",
                    "KMS keys and secrets management configuration",
                    "CI/CD pipeline definitions and deployment workflows"
                ],
                "security_focus": [
                    "IAM least privilege principle",
                    "Network segmentation and isolation",
                    "Encryption in transit (TLS) and at rest (KMS)",
                    "Secrets rotation and management",
                    "Resource exposure (public vs. private endpoints)"
                ]
            },
            "ai_ml_systems": {
                "applicable_if": "Python ML stack, LangChain, vector databases, model serving",
                "key_files": [
                    "Model serving and inference code",
                    "Training pipelines and data preprocessing",
                    "Vector database configurations (Pinecone, Weaviate, ChromaDB)",
                    "RAG system implementations and prompt templates",
                    "Agent/tool configurations and permissions"
                ],
                "security_focus": [
                    "Prompt injection and jailbreak vectors",
                    "Training data provenance and validation",
                    "Model access controls and API authentication",
                    "Inference API rate limiting and abuse prevention",
                    "AI agent boundaries, tool permissions, and autonomy limits"
                ]
            },
            "mobile_applications": {
                "applicable_if": "React Native, Flutter, iOS/Android native",
                "key_files": [
                    "API client and network layer",
                    "Local storage and keychain/keystore usage",
                    "Authentication and token management",
                    "Deep linking and URL scheme handling",
                    "App permissions and entitlements"
                ],
                "security_focus": [
                    "Certificate pinning and TLS validation",
                    "Secure local storage (encrypted databases)",
                    "Token storage in secure enclaves",
                    "Code obfuscation and reverse engineering protection",
                    "Platform-specific security features (biometrics, sandboxing)"
                ]
            }
        }

    elif analysis_stage == "validation":
        base_framework["validation_checklist"] = {
            "architecture_understanding": {
                "application_type": "Web app, API, mobile, infrastructure, AI/ML system identified",
                "technology_stack": "Primary languages, frameworks, and platforms documented",
                "deployment_model": "Cloud, on-premise, hybrid, serverless determined",
                "system_components": "Major components and their interactions mapped"
            },
            "security_context": {
                "authentication_methods": "All auth mechanisms identified (JWT, OAuth, sessions, etc.)",
                "authorization_approach": "RBAC, ABAC, or custom authorization understood",
                "sensitive_data_types": "PII, payment data, health data, credentials catalogued",
                "trust_boundaries": "External and internal boundaries identified",
                "external_dependencies": "Third-party services and APIs mapped"
            },
            "deployment_operations": {
                "internet_exposure": "Public, private, or hybrid exposure determined",
                "infrastructure_config": "Cloud resources, networking, security groups analyzed",
                "cicd_security": "Deployment pipeline and artifact security reviewed",
                "secrets_management": "How secrets are stored and accessed identified"
            },
            "readiness_assessment": {
                "minimum_requirements": [
                    "app_description can be written (2-4 sentences)",
                    "app_type is clear",
                    "At least one authentication_method identified",
                    "internet_facing status is known",
                    "At least one sensitive_data_type identified"
                ],
                "quality_indicators": [
                    "Trust boundaries are clearly understood",
                    "Data flow patterns have been traced",
                    "External dependencies are documented",
                    "Access control patterns are identified"
                ]
            }
        }

    # Output template - always included
    base_framework["output_template"] = {
        "description": "Structured format for calling get_stride_threat_framework",
        "threat_modeling_input": {
            "app_description": {
                "template": "[App Type] with [Key Components]. Uses [Frontend Tech] frontend, [Backend Tech] backend, [Database Tech] for persistence. Handles [Key Functionality]. Deployed as [Deployment Model]. Integrates with [External Services].",
                "example": "E-commerce web application with product catalog, shopping cart, and checkout. Uses React frontend, Node.js/Express backend, PostgreSQL for persistence. Handles payment processing via Stripe. Deployed as Docker containers on AWS ECS. Integrates with SendGrid for emails and S3 for product images.",
                "extraction_guidance": "Synthesize repository analysis into a concise architectural description (2-4 sentences) focusing on components, data flows, and external dependencies."
            },
            "app_type": {
                "valid_values": ["Web Application", "API Service", "Mobile Application", "Cloud Infrastructure", "AI/ML System", "IoT System"],
                "extraction_guidance": "Choose the primary application category based on repository structure and purpose."
            },
            "authentication_methods": {
                "common_patterns": {
                    "JWT": ["jsonwebtoken", "pyjwt", "jose libraries"],
                    "OAuth 2.0": ["passport", "authlib", "spring-security-oauth2"],
                    "Session-based": ["express-session", "django.contrib.sessions"],
                    "API Keys": ["API key validation in headers/query params"],
                    "Multi-factor": ["speakeasy", "pyotp", "authy"],
                    "None/Public": ["No authentication found - public API or static site"]
                },
                "extraction_guidance": "Identify ALL authentication mechanisms by analyzing auth middleware, security configuration, and dependency usage. Provide as an array."
            },
            "internet_facing": {
                "indicators": {
                    "true": ["Public API endpoints", "Frontend assets", "CDN configuration", "Public load balancers", "Domain/DNS configuration"],
                    "false": ["VPN requirements", "Private subnets only", "Internal service mesh", "No public ingress", "Localhost only"],
                    "partial": ["Admin panel behind VPN", "Public API + private admin", "Hybrid architecture"]
                },
                "extraction_guidance": "Analyze deployment configuration and network architecture to determine internet exposure. Use boolean true/false."
            },
            "sensitive_data_types": {
                "detection_patterns": {
                    "PII": ["User models with email, name, address, phone", "GDPR compliance mentions"],
                    "Payment Cards": ["Stripe/PayPal integration", "PCI compliance references", "Payment/transaction models"],
                    "Healthcare Data": ["HIPAA compliance", "Patient/medical record models", "PHI handling"],
                    "Authentication Credentials": ["Password hashing", "Token storage", "Session data"],
                    "Financial Data": ["Transaction models", "Account balances", "Trading/investment data"],
                    "Proprietary Data": ["Trade secrets", "Algorithms", "Business logic", "Source code"]
                },
                "extraction_guidance": "Examine data models, API payloads, and compliance documentation to identify ALL sensitive data types. Provide as an array."
            }
        },
        "validation": {
            "description": "Verify extraction completeness before calling get_stride_threat_framework",
            "required_fields": ["app_description", "app_type", "authentication_methods", "internet_facing", "sensitive_data_types"],
            "quality_checks": {
                "app_description": "Should be 2-4 sentences covering architecture, components, and key functionality",
                "authentication_methods": "At least one method identified, or explicitly state ['None/Public'] if truly unauthenticated",
                "sensitive_data_types": "At least one type identified based on data models and functionality, or ['User Data'] as minimum"
            }
        }
    }

    # GitHub MCP integration examples
    base_framework["github_mcp_integration"] = {
        "description": "Optimized workflow using GitHub MCP server - prefer search over full file reads",
        "initial_stage_workflow": {
            "step_1": {
                "tool": "mcp__github__get_file_contents",
                "params_example": '{"owner": "org", "repo": "repo", "path": "README.md"}',
                "purpose": "Architecture overview",
                "rationale": "README files contain structured overview; worth reading in full"
            },
            "step_2": {
                "tool": "mcp__github__get_file_contents",
                "params_example": '{"owner": "org", "repo": "repo", "path": "package.json"}',
                "purpose": "Tech stack identification",
                "rationale": "Package manifests are typically small config files"
            },
            "step_3": {
                "tool": "mcp__github__get_file_contents",
                "params_example": '{"owner": "org", "repo": "repo", "path": "docker-compose.yml"}',
                "purpose": "Deployment model",
                "rationale": "Docker configs are small, contain specific deployment info"
            },
            "checkpoint": {
                "action": "STOP - Can you identify: app type, tech stack, deployment model?",
                "if_yes": "Proceed to deep_dive stage",
                "if_no": "Read .env.example or one more config file, then proceed"
            }
        },
        "deep_dive_workflow": {
            "prefer_search_for_patterns": {
                "authentication": {
                    "tool": "mcp__github__search_code",
                    "query": 'repo:org/repo "passport.authenticate" OR "jwt.verify"',
                    "rationale": "Search returns relevant auth code snippets without full middleware files"
                },
                "data_models": {
                    "tool": "mcp__github__search_code",
                    "query": 'repo:org/repo path:models/ OR path:schemas/',
                    "rationale": "Search shows model structure without full file content"
                },
                "authorization": {
                    "tool": "mcp__github__search_code",
                    "query": 'repo:org/repo "@require" OR "@admin" OR "authorize"',
                    "rationale": "Search finds authorization patterns across codebase"
                }
            },
            "read_for_specific_values": {
                "configuration": {
                    "tool": "mcp__github__get_file_contents",
                    "path": ".env.example",
                    "rationale": "Config files are small and contain specific integration details"
                }
            },
            "checkpoint": {
                "action": "STOP after 8-12 searches/reads - Can you populate output_template fields?",
                "if_yes": "Start threat modeling with get_stride_threat_framework",
                "if_no": "Do 1-2 targeted searches for specific missing info only"
            }
        },
        "search_patterns": {
            "authentication": 'repo:owner/repo "jwt.verify" OR "passport.authenticate" OR "auth.check"',
            "authorization": 'repo:owner/repo "@require" OR "@admin" OR "permission.check" OR "authorize"',
            "sensitive_data": 'repo:owner/repo path:models/ "password" OR "email" OR "ssn" OR "credit_card"',
            "input_validation": 'repo:owner/repo "validate(" OR "sanitize(" OR "escape("',
            "database_queries": 'repo:owner/repo "query(" OR "execute(" OR "SELECT" OR "INSERT"',
            "api_endpoints": 'repo:owner/repo "app.get" OR "app.post" OR "@route" OR "@endpoint"'
        }
    }

    # Stage-specific analysis guidance
    if analysis_stage == "initial":
        guidance = """INITIAL RECONNAISSANCE STAGE:

1. Read 3-5 small, high-value files (README, package.json/requirements.txt, docker-compose.yml)
2. STOP after 3-5 file reads - assess readiness to proceed
3. Don't read for completeness - read until you have enough

Goal: Quickly identify app type, tech stack, and deployment model with minimal context usage.

Stopping Checkpoint: After 3-5 files, ask yourself:
- Can I identify the application type?
- Do I know the tech stack?
- Is the deployment model clear?

If YES → Proceed to deep_dive stage
If NO → Read 1-2 more specific files, then proceed anyway"""

        base_framework["next_steps"] = {
            "after_initial_analysis": [
                "STOP after 3-5 file reads",
                "If you have: app type, tech stack, deployment model",
                "→ Proceed to analysis_stage='deep_dive'",
                "",
                "If missing critical info:",
                "→ Read 1-2 more targeted files, then proceed to deep_dive"
            ],
            "stopping_checkpoint": [
                "After 3-5 file reads, STOP and assess",
                "Don't read more files for completeness",
                "Move to deep_dive even if some details are unclear"
            ],
            "github_mcp_tips": [
                "Use mcp__github__get_file_contents for README.md, package.json/requirements.txt, docker-compose.yml",
                "Config and documentation files are typically small; safe to read in full",
                "STOP after 3-5 files - don't keep reading"
            ]
        }

    elif analysis_stage == "deep_dive":
        guidance = """DEEP DIVE ANALYSIS STAGE:

1. Use code SEARCH (not file reads) to find security patterns:
   - Search for authentication patterns (jwt.verify, passport.authenticate)
   - Search for data models (path:models/, path:schemas/)
   - Search for authorization patterns (@require, @admin, authorize)

2. Only read full files for configs (.env.example) - search application code instead

3. STOP after 8-12 searches/reads and assess readiness

Goal: Extract security context using targeted searches, not exhaustive file reading.

Stopping Checkpoint: After 8-12 searches/reads, ask yourself:
- Can I populate the output_template fields (auth methods, sensitive data, etc.)?
- Do I know enough about trust boundaries?

If YES → Proceed to validation stage
If NO → Do 1-2 targeted searches for specific missing info, then proceed anyway"""

        base_framework["next_steps"] = {
            "after_deep_dive": [
                "STOP after 8-12 searches/reads",
                "If you can populate output_template fields:",
                "→ Proceed to analysis_stage='validation'",
                "",
                "If missing specific details:",
                "→ Do 1-2 targeted searches, then proceed to validation"
            ],
            "stopping_checkpoint": [
                "After 8-12 searches/reads, STOP and assess",
                "Don't search for completeness - search until you have enough",
                "Move to validation even if some details are unclear"
            ],
            "github_mcp_tips": [
                "PREFER mcp__github__search_code over mcp__github__get_file_contents",
                "Search examples: 'repo:org/repo \"jwt.verify\" OR \"passport.authenticate\"'",
                "Search returns relevant snippets; full reads return entire files",
                "Only read full files for config/documentation; search application code"
            ]
        }

    elif analysis_stage == "validation":
        guidance = """VALIDATION STAGE:

Check if you can populate the minimum required fields for threat modeling:
- app_description (2-4 sentences)
- app_type
- authentication_methods (at least one)
- internet_facing (true/false)
- sensitive_data_types (at least one)

If YES → Call get_stride_threat_framework and start threat modeling
If NO → Do 1-2 targeted searches for missing info, then start threat modeling anyway

Don't aim for perfect information - aim for sufficient information to identify threats."""

        base_framework["next_steps"] = {
            "if_validation_passes": [
                "1. Format your findings using the output_template",
                "2. Call get_stride_threat_framework with extracted data",
                "3. Begin STRIDE threat identification"
            ],
            "if_validation_fails": [
                "1. Identify 1-2 specific missing pieces",
                "2. Do targeted searches for those specific items only",
                "3. Proceed to threat modeling even if gaps remain"
            ],
            "minimum_required_for_stride": [
                "app_description (2-4 sentences)",
                "app_type (e.g., Web Application, API Service)",
                "authentication_methods (at least one, or 'None/Public')",
                "internet_facing (true/false)",
                "sensitive_data_types (at least one, or 'User Data' as default)"
            ]
        }

    else:
        guidance = "Unknown analysis stage. Valid stages: 'initial', 'deep_dive', 'validation'"

    base_framework["analysis_guidance"] = guidance
    base_framework["current_stage"] = analysis_stage
    base_framework["repository_context"] = repo_context

    return base_framework

def handle_mcp_request(body: dict) -> dict:
    """Handle MCP JSON-RPC requests using the improved MCP server"""
    
    method = body.get('method')
    params = body.get('params', {})
    request_id = body.get('id')
    
    
    # Handle initialize
    if method == 'initialize':
        return {
            "jsonrpc": "2.0",
            "result": {
                "protocolVersion": "2025-03-26",
                "capabilities": {
                    "tools": {"listChanged": False}
                },
                "serverInfo": {
                    "name": "STRIDE GPT MCP Server",
                    "version": "0.1.0"
                },
                "instructions": "Professional threat modeling server using the STRIDE methodology."
            },
            "id": request_id
        }
    
    # Handle tools/list
    elif method == 'tools/list':
        tools = [
            {
                "name": "get_stride_threat_framework",
                "description": "Get comprehensive STRIDE threat modeling framework and guidance for threat analysis",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "app_description": {
                            "type": "string",
                            "description": "Detailed description of the application architecture and functionality"
                        },
                        "app_type": {
                            "type": "string", 
                            "description": "Type of application",
                            "default": "Web Application"
                        },
                        "authentication_methods": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of authentication methods used",
                            "default": ["Username/Password"]
                        },
                        "internet_facing": {
                            "type": "boolean",
                            "description": "Whether the application is accessible from the internet",
                            "default": True
                        },
                        "sensitive_data_types": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Types of sensitive data handled",
                            "default": ["User Data"]
                        }
                    },
                    "required": ["app_description"]
                }
            },
            {
                "name": "generate_threat_mitigations",
                "description": "Generate actionable security mitigations for identified threats",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "threats": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "additionalProperties": True
                            },
                            "description": "Array of threat objects"
                        },
                        "priority_filter": {
                            "type": "string",
                            "description": "Filter by priority",
                            "default": "all"
                        }
                    },
                    "required": ["threats"]
                }
            },
            {
                "name": "create_threat_attack_trees",
                "description": "Generate application-wide attack tree showing common attack vectors",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "threats": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "additionalProperties": True
                            },
                            "description": "Array of threat objects (used for context)"
                        },
                        "max_depth": {
                            "type": "integer",
                            "description": "Maximum tree depth",
                            "default": 3
                        },
                        "output_format": {
                            "type": "string",
                            "description": "Output format",
                            "default": "both"
                        }
                    },
                    "required": ["threats"]
                }
            },
            {
                "name": "calculate_threat_risk_scores",
                "description": "Calculate DREAD risk scores to prioritize threats by severity",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "threats": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "additionalProperties": True
                            },
                            "description": "Array of threat objects"
                        },
                        "scoring_guidance": {
                            "type": "object",
                            "additionalProperties": True,
                            "description": "Optional guidance for scoring adjustments"
                        }
                    },
                    "required": ["threats"]
                }
            },
            {
                "name": "generate_security_tests",
                "description": "Generate security test cases to validate threat mitigations",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "threats": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "additionalProperties": True
                            },
                            "description": "Array of threat objects"
                        },
                        "test_type": {
                            "type": "string",
                            "description": "Type of tests",
                            "default": "mixed"
                        },
                        "format_type": {
                            "type": "string",
                            "description": "Output format",
                            "default": "gherkin"
                        }
                    },
                    "required": ["threats"]
                }
            },
            {
                "name": "generate_threat_report",
                "description": "Format complete threat analysis as professional markdown report",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "threat_model": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "additionalProperties": True
                            },
                            "description": "Array of threat objects"
                        },
                        "mitigations": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "additionalProperties": True
                            },
                            "description": "Optional array of mitigation strategies"
                        },
                        "dread_scores": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "additionalProperties": True
                            },
                            "description": "Optional array of DREAD scores"
                        },
                        "attack_trees": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "additionalProperties": True
                            },
                            "description": "Optional array of attack trees"
                        },
                        "include_sections": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Sections to include in report",
                            "default": ["executive_summary", "threats", "mitigations", "risk_scores"]
                        }
                    },
                    "required": ["threat_model"]
                }
            },
            {
                "name": "validate_threat_coverage",
                "description": "Validate STRIDE coverage completeness and suggest threat model enhancements",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "threat_model": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "additionalProperties": True
                            },
                            "description": "Array of threat objects to validate"
                        },
                        "app_context": {
                            "type": "object",
                            "additionalProperties": True,
                            "description": "Application context information"
                        }
                    },
                    "required": ["threat_model", "app_context"]
                }
            },
            {
                "name": "get_repository_analysis_guide",
                "description": "Get structured framework for extracting threat modeling inputs from repository analysis using GitHub MCP or similar tools",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "analysis_stage": {
                            "type": "string",
                            "description": "Analysis stage: 'initial' (quick scan), 'deep_dive' (detailed security analysis), or 'validation' (readiness check)",
                            "enum": ["initial", "deep_dive", "validation"],
                            "default": "initial"
                        },
                        "repository_context": {
                            "type": "object",
                            "description": "Optional context about the repository",
                            "properties": {
                                "primary_language": {
                                    "type": "string",
                                    "description": "Primary programming language detected"
                                },
                                "framework_detected": {
                                    "type": "string",
                                    "description": "Primary framework or platform detected"
                                },
                                "repository_type": {
                                    "type": "string",
                                    "description": "Type of repository",
                                    "enum": ["application", "library", "infrastructure", "unknown"]
                                }
                            }
                        }
                    },
                    "required": []
                }
            }
        ]
        return {
            "jsonrpc": "2.0",
            "result": {"tools": tools},
            "id": request_id
        }
    
    # Handle tools/call - actual implementation
    elif method == 'tools/call':
        tool_name = params.get('name')
        arguments = params.get('arguments', {})
        
        try:
            if tool_name == 'get_stride_threat_framework':
                result = get_stride_threat_framework(arguments)
                return {
                    "jsonrpc": "2.0",
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(result, indent=2)
                            }
                        ]
                    },
                    "id": request_id
                }
            
            elif tool_name == 'generate_threat_mitigations':
                result = generate_threat_mitigations(arguments)
                return {
                    "jsonrpc": "2.0",
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(result, indent=2)
                            }
                        ]
                    },
                    "id": request_id
                }
            
            elif tool_name == 'calculate_threat_risk_scores':
                result = calculate_threat_risk_scores(arguments)
                return {
                    "jsonrpc": "2.0",
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(result, indent=2)
                            }
                        ]
                    },
                    "id": request_id
                }
            
            elif tool_name == 'create_threat_attack_trees':
                result = create_threat_attack_trees(arguments)
                return {
                    "jsonrpc": "2.0",
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(result, indent=2)
                            }
                        ]
                    },
                    "id": request_id
                }
            
            elif tool_name == 'generate_security_tests':
                result = generate_security_tests(arguments)
                return {
                    "jsonrpc": "2.0",
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(result, indent=2)
                            }
                        ]
                    },
                    "id": request_id
                }
            
            elif tool_name == 'generate_threat_report':
                result = generate_threat_report(arguments)
                return {
                    "jsonrpc": "2.0",
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": result  # This returns markdown directly
                            }
                        ]
                    },
                    "id": request_id
                }
            
            elif tool_name == 'validate_threat_coverage':
                result = validate_threat_coverage(arguments)
                return {
                    "jsonrpc": "2.0",
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(result, indent=2)
                            }
                        ]
                    },
                    "id": request_id
                }

            elif tool_name == 'get_repository_analysis_guide':
                result = get_repository_analysis_guide(arguments)
                return {
                    "jsonrpc": "2.0",
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(result, indent=2)
                            }
                        ]
                    },
                    "id": request_id
                }

            else:
                return {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": ERROR_CODES['INVALID_PARAMETER'],
                        "message": f"Unknown tool: {tool_name}"
                    },
                    "id": request_id
                }
                
        except Exception as e:
            error_id, sanitized_message = sanitize_error(e, f"Tool execution: {tool_name}")
            return {
                "jsonrpc": "2.0",
                "error": {
                    "code": ERROR_CODES['TOOL_EXECUTION_FAILED'],
                    "message": sanitized_message
                },
                "id": request_id
            }
    
    else:
        return {
            "jsonrpc": "2.0",
            "error": {
                "code": -32601,
                "message": f"Method not found: {method}"
            },
            "id": request_id
        }


class handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Mcp-Session-Id')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.end_headers()
        
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.end_headers()
        
        response_data = {
            "name": "STRIDE GPT MCP Server",
            "version": "0.1.0",
            "description": "Professional threat modeling server using the STRIDE methodology",
            "tools": [
                "get_stride_threat_framework",
                "generate_threat_mitigations",
                "create_threat_attack_trees",
                "calculate_threat_risk_scores",
                "generate_security_tests",
                "generate_threat_report",
                "validate_threat_coverage",
                "get_repository_analysis_guide"
            ],
            "endpoints": {
                "POST /": "MCP JSON-RPC endpoint"
            }
        }
        self.wfile.write(json.dumps(response_data, indent=2).encode())
        
    def do_POST(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))

            # Validate payload size before reading
            if content_length > PAYLOAD_LIMITS['MAX_PAYLOAD_SIZE']:
                self.send_error_response(413, {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": ERROR_CODES['PAYLOAD_TOO_LARGE'],
                        "message": f"Payload size {content_length} bytes exceeds maximum of {PAYLOAD_LIMITS['MAX_PAYLOAD_SIZE']} bytes"
                    },
                    "id": None
                })
                return

            post_data = self.rfile.read(content_length)

            try:
                body = json.loads(post_data.decode('utf-8'))
            except json.JSONDecodeError:
                self.send_error_response(400, {
                    "jsonrpc": "2.0",
                    "error": {"code": -32700, "message": "Parse error"},
                    "id": None
                })
                return

            # Validate JSON complexity
            complexity_result = validate_json_complexity(body)
            if not complexity_result['valid']:
                self.send_error_response(400, {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": ERROR_CODES['PAYLOAD_TOO_COMPLEX'],
                        "message": f"Payload complexity validation failed: {complexity_result['error']}"
                    },
                    "id": body.get('id')
                })
                return

            # Validate JSON-RPC
            if not body.get('jsonrpc') == '2.0' or not body.get('method'):
                self.send_error_response(400, {
                    "jsonrpc": "2.0",
                    "error": {"code": -32600, "message": "Invalid Request"},
                    "id": body.get('id')
                })
                return
            
            # Handle MCP request using our improved server
            response = handle_mcp_request(body)
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('X-XSS-Protection', '1; mode=block')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
            
        except Exception as e:
            error_id, sanitized_message = sanitize_error(e, "HTTP POST request handling")
            self.send_error_response(500, {
                "jsonrpc": "2.0",
                "error": {"code": -32603, "message": sanitized_message},
                "id": None
            })
    
    def send_error_response(self, status_code, error_data):
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(error_data).encode())