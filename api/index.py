#!/usr/bin/env python3

import sys
import os
import json
from http.server import BaseHTTPRequestHandler
import asyncio
from typing import Dict, Any

# Import required modules for serverless environment
import uuid
import hashlib

# Enhanced error codes following MCP standards
ERROR_CODES = {
    'INVALID_PARAMETER': -32603,
    'TOOL_EXECUTION_FAILED': -32604,
    'INTERNAL_ERROR': -32603
}

# Simplified tool implementations for Vercel deployment
# Note: These provide framework and guidance for LLM client analysis

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
        "analysis_guidance": "Use this STRIDE framework to systematically identify specific threats for the described application. Consider which extended threat domains are relevant based on the application's architecture, technology stack, and deployment model. The LLM client should analyze the application context and select appropriate threats from each STRIDE category and relevant threat domain."
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
        "analysis_guidance": "For each threat provided, generate specific, actionable mitigation strategies. Consider defense-in-depth principles and prioritize based on risk level and implementation difficulty."
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
        "threats": threats,
        "scoring_guidance": scoring_guidance,
        "analysis_guidance": "Score each threat using the DREAD criteria. Provide justification for each score based on the specific threat characteristics and application context."
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
        "threat_context": threats,
        "test_type": test_type,
        "format_type": format_type,
        "analysis_guidance": "Generate specific test cases to validate that security controls effectively mitigate the identified threats. Include both positive and negative test scenarios."
    }

def generate_threat_report(args: Dict[str, Any]) -> str:
    """Provide threat report template for LLM client analysis."""
    threat_model = args.get('threat_model', [])
    include_sections = args.get('include_sections', ['executive_summary', 'threats', 'mitigations', 'risk_scores'])
    
    report_template = """# STRIDE Threat Model Report

## Executive Summary
*Provide a high-level overview of the threat modeling exercise, key findings, and recommended actions.*

## Application Overview
*Describe the application architecture, components, and security-relevant characteristics.*

## Threat Analysis
*Detail the identified threats organized by STRIDE category.*

### Spoofing Threats
*List and describe spoofing-related threats*

### Tampering Threats  
*List and describe tampering-related threats*

### Repudiation Threats
*List and describe repudiation-related threats*

### Information Disclosure Threats
*List and describe information disclosure threats*

### Denial of Service Threats
*List and describe denial of service threats*

### Elevation of Privilege Threats
*List and describe privilege escalation threats*

## Risk Assessment
*Provide DREAD scores and risk prioritization for identified threats.*

## Recommended Mitigations
*Detail specific mitigation strategies organized by priority.*

### High Priority Mitigations
*Critical security controls for immediate implementation*

### Medium Priority Mitigations  
*Important controls for near-term planning*

### Low Priority Mitigations
*Additional defensive measures for comprehensive security*

## Security Testing Plan
*Outline test cases to validate mitigation effectiveness.*

## Implementation Roadmap
*Provide timeline and sequencing for mitigation implementation.*

## Appendix
*Additional technical details, references, and supporting information.*
"""
    
    return {
        "report_template": report_template,
        "threat_model": threat_model,
        "include_sections": include_sections,
        "analysis_guidance": "Use this template to create a comprehensive threat modeling report. Populate each section with specific analysis based on the provided threat model data."
    }

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
                    "target_files": "5-10 key files",
                    "output": "Tech stack, deployment model, basic architecture"
                },
                "deep_dive": {
                    "objective": "Extract detailed security context for threat modeling",
                    "target_files": "20-40 targeted files",
                    "output": "Trust boundaries, sensitive data, access controls"
                },
                "validation": {
                    "objective": "Verify sufficient context for threat modeling",
                    "target_files": "Review completeness",
                    "output": "Readiness assessment or identified gaps"
                }
            }
        }
    }

    # Stage-specific guidance
    if analysis_stage == "initial":
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

    # Stage-specific analysis guidance
    if analysis_stage == "initial":
        guidance = """INITIAL RECONNAISSANCE STAGE:

1. Start with high-level documentation and configuration files to understand the system architecture
2. Examine package managers to identify the technology stack and frameworks
3. Check containerization and infrastructure files to determine deployment model
4. Review configuration templates to understand required services and integrations

Goal: Quickly build a mental model of what the application is, how it's built, and where it runs.

Next Steps: Call this tool again with analysis_stage='deep_dive' once you have basic architecture understanding."""

    elif analysis_stage == "deep_dive":
        guidance = """DEEP DIVE ANALYSIS STAGE:

1. Focus on security-relevant code: authentication, authorization, data models
2. Identify trust boundaries by tracing request flows from external entry points
3. Examine data models and schemas to catalogue sensitive data types
4. Analyze access control patterns and privilege escalation paths
5. Map external dependencies and third-party integrations

Use the technology-specific guides provided to focus your analysis on the most relevant files for the detected stack.

Goal: Extract detailed security context needed for comprehensive threat modeling.

Next Steps: Call this tool again with analysis_stage='validation' to verify you have sufficient information."""

    elif analysis_stage == "validation":
        guidance = """VALIDATION STAGE:

1. Review the validation checklist to ensure all required context has been extracted
2. Verify you can populate all required fields for get_stride_threat_framework
3. Check quality indicators to assess completeness

If validation passes:
- Proceed to call get_stride_threat_framework with your structured extraction
- Use the output_template provided as a guide for formatting your input

If validation fails:
- Identify specific gaps from the checklist
- Return to deep_dive analysis for missing information
- Focus on the specific areas that are incomplete

Goal: Confirm readiness for threat modeling or identify gaps to fill."""

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
                            "items": {"type": "object"},
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
                            "items": {"type": "object"},
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
                            "items": {"type": "object"},
                            "description": "Array of threat objects"
                        },
                        "scoring_guidance": {
                            "type": "object",
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
                            "items": {"type": "object"},
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
                            "items": {"type": "object"},
                            "description": "Array of threat objects"
                        },
                        "mitigations": {
                            "type": "array",
                            "items": {"type": "object"},
                            "description": "Optional array of mitigation strategies"
                        },
                        "dread_scores": {
                            "type": "array",
                            "items": {"type": "object"},
                            "description": "Optional array of DREAD scores"
                        },
                        "attack_trees": {
                            "type": "array",
                            "items": {"type": "object"},
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
                            "items": {"type": "object"},
                            "description": "Array of threat objects to validate"
                        },
                        "app_context": {
                            "type": "object",
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
            return {
                "jsonrpc": "2.0",
                "error": {
                    "code": ERROR_CODES['TOOL_EXECUTION_FAILED'],
                    "message": f"Tool execution failed: {str(e)}"
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
            self.send_error_response(500, {
                "jsonrpc": "2.0",
                "error": {"code": -32603, "message": f"Internal error: {str(e)}"},
                "id": None
            })
    
    def send_error_response(self, status_code, error_data):
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(error_data).encode())