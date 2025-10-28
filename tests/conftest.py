"""Shared pytest fixtures for STRIDE GPT MCP tests."""
import sys
import os
import pytest

# Add api directory to path so we can import from index.py
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from api.index import (
    get_stride_threat_framework,
    generate_threat_mitigations,
    calculate_threat_risk_scores,
    create_threat_attack_trees,
    generate_security_tests,
    generate_threat_report,
    validate_threat_coverage,
    get_repository_analysis_guide,
    handle_mcp_request
)


@pytest.fixture
def sample_app_context():
    """Sample application context for testing."""
    return {
        "app_description": "E-commerce platform with user authentication, product catalog, shopping cart, and Stripe payment processing",
        "app_type": "Web Application",
        "authentication_methods": ["JWT", "OAuth 2.0"],
        "internet_facing": True,
        "sensitive_data_types": ["PII", "Payment Cards", "Authentication Credentials"]
    }


@pytest.fixture
def sample_threats():
    """Sample threat objects for testing."""
    return [
        {
            "threat_id": "T001",
            "threat_name": "SQL Injection in Product Search",
            "stride_category": "T",
            "description": "Attacker can inject SQL commands through the product search field",
            "severity": "High",
            "affected_component": "Product Search API"
        },
        {
            "threat_id": "T002",
            "threat_name": "Weak Password Policy",
            "stride_category": "S",
            "description": "Users can set weak passwords that are easily guessable",
            "severity": "Medium",
            "affected_component": "Authentication System"
        },
        {
            "threat_id": "T003",
            "threat_name": "Missing CSRF Protection",
            "stride_category": "T",
            "description": "State-changing operations lack CSRF token validation",
            "severity": "High",
            "affected_component": "Web Forms"
        }
    ]


@pytest.fixture
def sample_mcp_request():
    """Sample MCP request for protocol testing."""
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "get_stride_threat_framework",
            "arguments": {
                "app_description": "Simple web app",
                "app_type": "Web Application"
            }
        }
    }


@pytest.fixture
def sample_mitigations():
    """Sample mitigation objects for testing."""
    return [
        {
            "threat_id": "T001",
            "mitigation_id": "M001",
            "strategy": "Use parameterized queries",
            "control_type": "Preventive",
            "difficulty": "Easy",
            "priority": "High"
        }
    ]


@pytest.fixture
def sample_dread_scores():
    """Sample DREAD score objects for testing."""
    return [
        {
            "threat_id": "T001",
            "dread_score": {
                "damage": 9,
                "reproducibility": 8,
                "exploitability": 7,
                "affected_users": 9,
                "discoverability": 8,
                "total": 41,
                "risk_level": "Critical"
            }
        }
    ]
