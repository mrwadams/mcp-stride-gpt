"""
Unit tests for MCP server tool functions.

Tests all threat modeling tools including:
- get_stride_threat_framework
- generate_threat_mitigations
- calculate_threat_risk_scores
- create_threat_attack_trees
- generate_security_tests
- generate_threat_report
- validate_threat_coverage
- get_repository_analysis_guide
"""

import pytest
import sys
import os

# Add api directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api'))

from index import (
    get_stride_threat_framework,
    generate_threat_mitigations,
    calculate_threat_risk_scores,
    create_threat_attack_trees,
    generate_security_tests,
    generate_threat_report,
    validate_threat_coverage,
    get_repository_analysis_guide
)


class TestGetStrideThreatFramework:
    """Tests for get_stride_threat_framework function."""

    def test_basic_call_with_minimal_args(self):
        """Test with just app_description."""
        args = {'app_description': 'A simple web application'}
        result = get_stride_threat_framework(args)

        assert 'stride_framework' in result
        assert 'application_context' in result
        assert 'analysis_guidance' in result
        assert 'next_steps' in result

    def test_framework_structure(self):
        """Test that framework contains all STRIDE categories."""
        args = {'app_description': 'Test app'}
        result = get_stride_threat_framework(args)

        categories = result['stride_framework']['categories']
        assert 'S' in categories  # Spoofing
        assert 'T' in categories  # Tampering
        assert 'R' in categories  # Repudiation
        assert 'I' in categories  # Information Disclosure
        assert 'D' in categories  # Denial of Service
        assert 'E' in categories  # Elevation of Privilege

    def test_extended_threat_domains(self):
        """Test that extended threat domains are included."""
        args = {'app_description': 'Test app'}
        result = get_stride_threat_framework(args)

        domains = result['stride_framework']['extended_threat_domains']
        assert 'traditional_web' in domains
        assert 'cloud_infrastructure' in domains
        assert 'ai_ml_systems' in domains
        assert 'iot_embedded' in domains
        assert 'mobile_applications' in domains
        assert 'api_microservices' in domains

    def test_application_context_capture(self):
        """Test that application context is properly captured."""
        args = {
            'app_description': 'E-commerce platform',
            'app_type': 'Web Application',
            'authentication_methods': ['JWT', 'OAuth 2.0'],
            'internet_facing': True,
            'sensitive_data_types': ['Payment Cards', 'PII']
        }
        result = get_stride_threat_framework(args)

        context = result['application_context']
        assert context['app_description'] == 'E-commerce platform'
        assert context['app_type'] == 'Web Application'
        assert 'JWT' in context['authentication_methods']
        assert context['internet_facing'] is True
        assert 'Payment Cards' in context['sensitive_data_types']

    def test_default_values(self):
        """Test that default values are applied correctly."""
        args = {'app_description': 'Test app'}
        result = get_stride_threat_framework(args)

        context = result['application_context']
        assert context['app_type'] == 'Web Application'
        assert context['authentication_methods'] == ['Username/Password']
        assert context['internet_facing'] is True
        assert context['sensitive_data_types'] == ['User Data']


class TestGenerateThreatMitigations:
    """Tests for generate_threat_mitigations function."""

    def test_basic_call(self):
        """Test basic mitigation generation."""
        threats = [
            {'id': 'T1', 'category': 'S', 'description': 'Authentication bypass'}
        ]
        args = {'threats': threats}
        result = generate_threat_mitigations(args)

        assert 'mitigation_framework' in result
        assert 'threat_context' in result
        assert 'analysis_guidance' in result

    def test_mitigation_framework_structure(self):
        """Test mitigation framework contains required categories."""
        args = {'threats': []}
        result = generate_threat_mitigations(args)

        framework = result['mitigation_framework']
        assert 'categories' in framework
        assert 'Preventive' in framework['categories']
        assert 'Detective' in framework['categories']
        assert 'Corrective' in framework['categories']

    def test_difficulty_levels(self):
        """Test difficulty levels are defined."""
        args = {'threats': []}
        result = generate_threat_mitigations(args)

        framework = result['mitigation_framework']
        assert 'difficulty_levels' in framework
        assert 'Easy' in framework['difficulty_levels']
        assert 'Medium' in framework['difficulty_levels']
        assert 'Hard' in framework['difficulty_levels']

    def test_priority_filter(self):
        """Test priority filter parameter is captured for LLM context."""
        # These parameters are passed through to provide context to the LLM client
        # The MCP server itself doesn't filter - it provides framework for LLM to use
        args = {
            'threats': [],
            'priority_filter': 'high'
        }
        result = generate_threat_mitigations(args)

        # Verify parameter is captured in output for LLM context
        assert result['priority_filter'] == 'high'

        # Verify framework includes priority level definitions
        assert 'priority_levels' in result['mitigation_framework']
        assert 'High' in result['mitigation_framework']['priority_levels']

        # Test default value
        result_default = generate_threat_mitigations({'threats': []})
        assert result_default['priority_filter'] == 'all'

    def test_threat_context_preservation(self):
        """Test that threat context is preserved and properly structured."""
        threats = [
            {'id': 'T1', 'category': 'S', 'description': 'Test threat'},
            {'id': 'T2', 'category': 'T', 'description': 'Another threat'}
        ]
        args = {'threats': threats}
        result = generate_threat_mitigations(args)

        # Verify threats are preserved exactly
        assert result['threat_context'] == threats
        assert len(result['threat_context']) == 2
        assert result['threat_context'][0]['id'] == 'T1'

        # Test with empty threats
        result_empty = generate_threat_mitigations({'threats': []})
        assert result_empty['threat_context'] == []


class TestCalculateThreatRiskScores:
    """Tests for calculate_threat_risk_scores function."""

    def test_basic_call(self):
        """Test basic DREAD scoring."""
        args = {'threats': []}
        result = calculate_threat_risk_scores(args)

        assert 'dread_framework' in result
        assert 'threats' in result
        assert 'analysis_guidance' in result

    def test_dread_scoring_criteria(self):
        """Test that all DREAD criteria are defined."""
        args = {'threats': []}
        result = calculate_threat_risk_scores(args)

        criteria = result['dread_framework']['scoring_criteria']
        assert 'Damage' in criteria
        assert 'Reproducibility' in criteria
        assert 'Exploitability' in criteria
        assert 'Affected_Users' in criteria
        assert 'Discoverability' in criteria

    def test_risk_levels(self):
        """Test that risk levels are defined."""
        args = {'threats': []}
        result = calculate_threat_risk_scores(args)

        risk_levels = result['dread_framework']['risk_levels']
        assert 'Critical' in risk_levels
        assert 'High' in risk_levels
        assert 'Medium' in risk_levels
        assert 'Low' in risk_levels

    def test_calibration_guidance(self):
        """Test that calibration guidance is provided."""
        args = {'threats': []}
        result = calculate_threat_risk_scores(args)

        calibration = result['calibration_guidance']
        assert 'damage' in calibration
        assert 'reproducibility' in calibration
        assert 'exploitability' in calibration
        assert 'affected_users' in calibration
        assert 'discoverability' in calibration

    def test_scoring_examples(self):
        """Test that scoring examples are comprehensive and well-structured."""
        args = {'threats': []}
        result = calculate_threat_risk_scores(args)

        examples = result['scoring_examples']

        # Should have multiple examples (at least 5 per test_improvements.py)
        assert len(examples) >= 5, f"Expected at least 5 examples, got {len(examples)}"

        # Verify each example has required structure
        for i, example in enumerate(examples):
            assert 'threat' in example, f"Example {i} missing 'threat' field"
            assert 'context' in example, f"Example {i} missing 'context' field"
            assert 'dread_breakdown' in example, f"Example {i} missing 'dread_breakdown'"

            # Verify threat description is non-empty
            assert len(example['threat']) > 0, f"Example {i} has empty threat"

            # Verify DREAD breakdown has all required fields
            dread = example['dread_breakdown']
            required_fields = ['Damage', 'Reproducibility', 'Exploitability', 'Affected_Users', 'Discoverability']
            for field in required_fields:
                assert field in dread, f"Example {i} missing DREAD field: {field}"
                assert dread[field] is not None, f"Example {i} has null {field}"

            # Verify total and priority are present
            assert 'total' in dread, f"Example {i} missing 'total' score"
            assert 'priority' in dread, f"Example {i} missing 'priority'"

            # Verify total score is reasonable (DREAD scores are 1-10 per dimension, 5 dimensions)
            assert isinstance(dread['total'], (int, float)), f"Example {i} total is not numeric"
            assert 5 <= dread['total'] <= 50, f"Example {i} total {dread['total']} out of valid range (5-50)"


class TestCreateThreatAttackTrees:
    """Tests for create_threat_attack_trees function."""

    def test_basic_call(self):
        """Test basic attack tree generation."""
        args = {'threats': []}
        result = create_threat_attack_trees(args)

        assert 'attack_tree_framework' in result
        assert 'output_formats' in result
        assert 'threat_context' in result

    def test_attack_tree_structure(self):
        """Test attack tree structure is defined."""
        args = {'threats': []}
        result = create_threat_attack_trees(args)

        framework = result['attack_tree_framework']
        assert 'structure' in framework
        assert 'root_goal' in framework['structure']
        assert 'sub_goals' in framework['structure']
        assert 'attack_methods' in framework['structure']

    def test_output_formats(self):
        """Test that all output formats are defined."""
        args = {'threats': []}
        result = create_threat_attack_trees(args)

        formats = result['output_formats']
        assert 'text' in formats
        assert 'mermaid' in formats
        assert 'json' in formats
        assert 'both' in formats

    def test_max_depth_parameter(self):
        """Test max_depth parameter is captured and validated."""
        # Test custom depth
        args = {'threats': [], 'max_depth': 5}
        result = create_threat_attack_trees(args)
        assert result['max_depth'] == 5

        # Test default depth
        result_default = create_threat_attack_trees({'threats': []})
        assert result_default['max_depth'] == 3  # Default value

        # Verify framework guidance references depth concept
        assert 'structure' in result['attack_tree_framework']

    def test_output_format_parameter(self):
        """Test output_format parameter validation and documentation."""
        # Test mermaid format
        args = {'threats': [], 'output_format': 'mermaid'}
        result = create_threat_attack_trees(args)
        assert result['output_format'] == 'mermaid'

        # Test default format
        result_default = create_threat_attack_trees({'threats': []})
        assert result_default['output_format'] == 'both'  # Default value

        # Verify all output formats are documented
        assert 'output_formats' in result
        assert 'mermaid' in result['output_formats']
        assert 'text' in result['output_formats']
        assert 'json' in result['output_formats']
        assert 'both' in result['output_formats']

        # Verify format documentation includes examples
        assert 'example' in result['output_formats']['mermaid']


class TestGenerateSecurityTests:
    """Tests for generate_security_tests function."""

    def test_basic_call(self):
        """Test basic security test generation."""
        args = {'threats': []}
        result = generate_security_tests(args)

        assert 'security_testing_framework' in result
        assert 'threat_context' in result
        assert 'analysis_guidance' in result

    def test_test_types(self):
        """Test that all test types are defined."""
        args = {'threats': []}
        result = generate_security_tests(args)

        test_types = result['security_testing_framework']['test_types']
        assert 'unit' in test_types
        assert 'integration' in test_types
        assert 'penetration' in test_types
        assert 'compliance' in test_types

    def test_test_formats(self):
        """Test that test formats are defined."""
        args = {'threats': []}
        result = generate_security_tests(args)

        formats = result['security_testing_framework']['test_formats']
        assert 'gherkin' in formats
        assert 'procedural' in formats
        assert 'checklist' in formats

    def test_format_examples(self):
        """Test that format examples are provided."""
        args = {'threats': []}
        result = generate_security_tests(args)

        examples = result['format_examples']
        assert 'gherkin' in examples
        assert 'checklist' in examples
        assert 'markdown' in examples

    def test_parameters(self):
        """Test that parameters are captured and documented."""
        args = {
            'threats': [],
            'test_type': 'unit',
            'format_type': 'checklist'
        }
        result = generate_security_tests(args)

        # Verify parameters are captured for LLM context
        assert result['test_type'] == 'unit'
        assert result['format_type'] == 'checklist'

        # Test defaults
        result_default = generate_security_tests({'threats': []})
        assert result_default['test_type'] == 'mixed'  # Default from implementation
        assert result_default['format_type'] == 'gherkin'

        # Verify test types are properly documented in framework
        assert 'test_types' in result['security_testing_framework']
        assert 'unit' in result['security_testing_framework']['test_types']

        # Verify format types are documented
        assert 'test_formats' in result['security_testing_framework']
        assert 'checklist' in result['security_testing_framework']['test_formats']


class TestGenerateThreatReport:
    """Tests for generate_threat_report function."""

    def test_basic_call(self):
        """Test basic report generation."""
        args = {'threat_model': []}
        result = generate_threat_report(args)

        assert isinstance(result, str)
        assert '# STRIDE Threat Model Report' in result

    def test_report_structure(self):
        """Test that report has expected sections."""
        args = {'threat_model': []}
        result = generate_threat_report(args)

        assert '## Executive Summary' in result
        assert '## Application Overview' in result
        assert '## Threat Analysis' in result
        assert '## Risk Assessment' in result
        assert '## Recommended Mitigations' in result

    def test_stride_categories_in_report(self):
        """Test that all STRIDE categories are included."""
        args = {'threat_model': []}
        result = generate_threat_report(args)

        assert '### Spoofing Threats' in result
        assert '### Tampering Threats' in result
        assert '### Repudiation Threats' in result
        assert '### Information Disclosure Threats' in result
        assert '### Denial of Service Threats' in result
        assert '### Elevation of Privilege Threats' in result

    def test_include_sections_parameter(self):
        """Test that include_sections parameter filters content."""
        args = {
            'threat_model': [],
            'include_sections': ['threats']
        }
        result = generate_threat_report(args)

        # Should include threats section
        assert '## Threat Analysis' in result
        # Should not include executive summary
        assert '## Executive Summary' not in result

    def test_threat_count(self):
        """Test that threat count is calculated correctly."""
        threats = [
            {'id': 'T1', 'description': 'Threat 1'},
            {'id': 'T2', 'description': 'Threat 2'},
            {'id': 'T3', 'description': 'Threat 3'}
        ]
        args = {'threat_model': threats}
        result = generate_threat_report(args)

        assert '**Total Threats Identified:** 3' in result


class TestValidateThreatCoverage:
    """Tests for validate_threat_coverage function."""

    def test_basic_call(self):
        """Test basic coverage validation."""
        args = {'threat_model': [], 'app_context': {}}
        result = validate_threat_coverage(args)

        assert 'coverage_framework' in result
        assert 'threat_model' in result
        assert 'app_context' in result

    def test_stride_categories_in_framework(self):
        """Test that all STRIDE categories are in validation framework."""
        args = {'threat_model': [], 'app_context': {}}
        result = validate_threat_coverage(args)

        categories = result['coverage_framework']['stride_categories']
        assert 'S' in categories
        assert 'T' in categories
        assert 'R' in categories
        assert 'I' in categories
        assert 'D' in categories
        assert 'E' in categories

    def test_validation_criteria(self):
        """Test that validation criteria are defined."""
        args = {'threat_model': [], 'app_context': {}}
        result = validate_threat_coverage(args)

        criteria = result['coverage_framework']['validation_criteria']
        assert 'completeness' in criteria
        assert 'specificity' in criteria
        assert 'actionability' in criteria
        assert 'risk_alignment' in criteria

    def test_common_gaps(self):
        """Test that common gaps are identified."""
        args = {'threat_model': [], 'app_context': {}}
        result = validate_threat_coverage(args)

        gaps = result['coverage_framework']['common_gaps']
        assert 'trust_boundaries' in gaps
        assert 'data_flows' in gaps
        assert 'privileged_operations' in gaps


class TestGetRepositoryAnalysisGuide:
    """Tests for get_repository_analysis_guide function."""

    def test_basic_call(self):
        """Test basic call with no args."""
        args = {}
        result = get_repository_analysis_guide(args)

        assert 'analysis_framework' in result
        assert 'analysis_guidance' in result
        assert 'current_stage' in result

    def test_analysis_stages(self):
        """Test that all analysis stages are defined."""
        args = {}
        result = get_repository_analysis_guide(args)

        stages = result['analysis_framework']['stages']
        assert 'initial' in stages
        assert 'deep_dive' in stages
        assert 'validation' in stages

    def test_initial_stage(self):
        """Test initial reconnaissance stage."""
        args = {'analysis_stage': 'initial'}
        result = get_repository_analysis_guide(args)

        assert result['current_stage'] == 'initial'
        assert 'initial_reconnaissance' in result
        assert 'files_to_examine_first' in result['initial_reconnaissance']

    def test_deep_dive_stage(self):
        """Test deep dive analysis stage."""
        args = {'analysis_stage': 'deep_dive'}
        result = get_repository_analysis_guide(args)

        assert result['current_stage'] == 'deep_dive'
        assert 'deep_dive_analysis' in result
        assert 'trust_boundaries' in result['deep_dive_analysis']

    def test_validation_stage(self):
        """Test validation stage."""
        args = {'analysis_stage': 'validation'}
        result = get_repository_analysis_guide(args)

        assert result['current_stage'] == 'validation'
        assert 'validation_checklist' in result

    def test_output_template(self):
        """Test that output template is always included."""
        args = {}
        result = get_repository_analysis_guide(args)

        assert 'output_template' in result
        assert 'threat_modeling_input' in result['output_template']

    def test_github_mcp_integration(self):
        """Test that GitHub MCP integration examples are provided."""
        args = {}
        result = get_repository_analysis_guide(args)

        assert 'github_mcp_integration' in result
        assert 'initial_stage_examples' in result['github_mcp_integration']
        assert 'deep_dive_examples' in result['github_mcp_integration']

    def test_repository_context(self):
        """Test that repository context is preserved and structured."""
        context = {
            'primary_language': 'Python',
            'framework_detected': 'FastAPI',
            'dependencies': ['pydantic', 'uvicorn']
        }
        args = {'repository_context': context}
        result = get_repository_analysis_guide(args)

        # Verify context is preserved exactly
        assert result['repository_context'] == context
        assert result['repository_context']['primary_language'] == 'Python'
        assert result['repository_context']['framework_detected'] == 'FastAPI'

        # Test with empty context
        result_empty = get_repository_analysis_guide({})
        assert 'repository_context' in result_empty
        assert result_empty['repository_context'] == {}
