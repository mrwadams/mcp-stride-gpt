"""Unit tests for STRIDE GPT MCP tool functions."""
import pytest
import sys
import os

# Add api directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from api.index import (
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

    @pytest.mark.unit
    def test_basic_framework_structure(self, sample_app_context):
        """Test that framework returns expected structure."""
        result = get_stride_threat_framework(sample_app_context)

        # Verify top-level structure
        assert "stride_framework" in result
        assert "application_context" in result
        assert "analysis_guidance" in result

    @pytest.mark.unit
    def test_all_stride_categories_present(self, sample_app_context):
        """Test that all 6 STRIDE categories are included."""
        result = get_stride_threat_framework(sample_app_context)
        categories = result["stride_framework"]["categories"]

        stride_keys = ["S", "T", "R", "I", "D", "E"]
        for key in stride_keys:
            assert key in categories
            assert "name" in categories[key]
            assert "description" in categories[key]
            assert "threat_examples" in categories[key]

    @pytest.mark.unit
    def test_extended_domains_included(self, sample_app_context):
        """Test that extended threat domains are included."""
        result = get_stride_threat_framework(sample_app_context)

        assert "extended_threat_domains" in result["stride_framework"]
        domains = result["stride_framework"]["extended_threat_domains"]

        # Check for key domains
        assert "traditional_web" in domains
        assert "ai_ml_systems" in domains
        assert "cloud_infrastructure" in domains

    @pytest.mark.unit
    def test_defaults_when_minimal_input(self):
        """Test framework works with minimal input."""
        minimal_args = {"app_description": "Test app"}
        result = get_stride_threat_framework(minimal_args)

        # Should still return complete framework
        assert "stride_framework" in result
        assert "application_context" in result

        # Check defaults are applied
        context = result["application_context"]
        assert context["app_type"] == "Web Application"
        assert context["authentication_methods"] == ["Username/Password"]
        assert context["internet_facing"] is True

    @pytest.mark.unit
    def test_ai_ml_context_detection(self):
        """Test AI/ML context is detected in application description."""
        ai_app = {
            "app_description": "AI-powered chatbot using LLM for customer support with RAG",
            "app_type": "AI/ML Application"
        }
        result = get_stride_threat_framework(ai_app)

        # Should include AI/ML specific guidance
        assert "extended_threat_domains" in result["stride_framework"]
        assert "ai_ml_systems" in result["stride_framework"]["extended_threat_domains"]


class TestGenerateThreatMitigations:
    """Tests for generate_threat_mitigations function."""

    @pytest.mark.unit
    def test_mitigation_framework_structure(self, sample_threats):
        """Test mitigation framework returns expected structure."""
        args = {"threats": sample_threats}
        result = generate_threat_mitigations(args)

        assert "mitigation_framework" in result
        assert "control_types" in result["mitigation_framework"]
        assert "implementation_guidance" in result

    @pytest.mark.unit
    def test_control_types_defined(self, sample_threats):
        """Test that all control types are defined."""
        args = {"threats": sample_threats}
        result = generate_threat_mitigations(args)

        control_types = result["mitigation_framework"]["control_types"]
        assert "preventive" in control_types
        assert "detective" in control_types
        assert "corrective" in control_types

    @pytest.mark.unit
    def test_priority_filter_high(self, sample_threats):
        """Test filtering mitigations by high priority."""
        args = {"threats": sample_threats, "priority_filter": "high"}
        result = generate_threat_mitigations(args)

        # Should still return framework
        assert "mitigation_framework" in result
        assert result["priority_filter"] == "high"

    @pytest.mark.unit
    def test_empty_threats_list(self):
        """Test handling of empty threats list."""
        args = {"threats": []}
        result = generate_threat_mitigations(args)

        # Should still return framework for guidance
        assert "mitigation_framework" in result


class TestCalculateThreatRiskScores:
    """Tests for calculate_threat_risk_scores function."""

    @pytest.mark.unit
    def test_dread_framework_structure(self, sample_threats):
        """Test DREAD framework returns expected structure."""
        args = {"threats": sample_threats}
        result = calculate_threat_risk_scores(args)

        assert "dread_framework" in result
        assert "scoring_criteria" in result["dread_framework"]
        assert "risk_levels" in result["dread_framework"]

    @pytest.mark.unit
    def test_all_dread_criteria_present(self, sample_threats):
        """Test that all DREAD criteria are defined."""
        args = {"threats": sample_threats}
        result = calculate_threat_risk_scores(args)

        criteria = result["dread_framework"]["scoring_criteria"]
        dread_keys = ["damage", "reproducibility", "exploitability", "affected_users", "discoverability"]

        for key in dread_keys:
            assert key in criteria
            assert "description" in criteria[key]
            assert "scale" in criteria[key]

    @pytest.mark.unit
    def test_risk_level_definitions(self, sample_threats):
        """Test that risk levels are properly defined."""
        args = {"threats": sample_threats}
        result = calculate_threat_risk_scores(args)

        risk_levels = result["dread_framework"]["risk_levels"]
        assert "critical" in risk_levels
        assert "high" in risk_levels
        assert "medium" in risk_levels
        assert "low" in risk_levels

    @pytest.mark.unit
    def test_example_scores_provided(self, sample_threats):
        """Test that example scores are included for guidance."""
        args = {"threats": sample_threats}
        result = calculate_threat_risk_scores(args)

        assert "examples" in result["dread_framework"]
        examples = result["dread_framework"]["examples"]
        assert len(examples) > 0


class TestCreateThreatAttackTrees:
    """Tests for create_threat_attack_trees function."""

    @pytest.mark.unit
    def test_attack_tree_framework_structure(self, sample_threats):
        """Test attack tree framework structure."""
        args = {"threats": sample_threats}
        result = create_threat_attack_trees(args)

        assert "attack_tree_framework" in result
        assert "common_patterns" in result["attack_tree_framework"]
        assert "output_formats" in result["attack_tree_framework"]

    @pytest.mark.unit
    def test_output_format_options(self, sample_threats):
        """Test different output format options."""
        for format_type in ["text", "mermaid", "json", "both"]:
            args = {"threats": sample_threats, "output_format": format_type}
            result = create_threat_attack_trees(args)

            assert "attack_tree_framework" in result
            assert result.get("requested_format") == format_type

    @pytest.mark.unit
    def test_max_depth_parameter(self, sample_threats):
        """Test max_depth parameter is respected."""
        args = {"threats": sample_threats, "max_depth": 5}
        result = create_threat_attack_trees(args)

        assert "attack_tree_framework" in result
        assert result.get("max_depth") == 5

    @pytest.mark.unit
    def test_common_attack_patterns_included(self, sample_threats):
        """Test that common attack patterns are provided."""
        args = {"threats": sample_threats}
        result = create_threat_attack_trees(args)

        patterns = result["attack_tree_framework"]["common_patterns"]
        assert isinstance(patterns, dict)
        assert len(patterns) > 0


class TestGenerateSecurityTests:
    """Tests for generate_security_tests function."""

    @pytest.mark.unit
    def test_testing_framework_structure(self, sample_threats):
        """Test testing framework structure."""
        args = {"threats": sample_threats}
        result = generate_security_tests(args)

        assert "testing_framework" in result
        assert "test_types" in result["testing_framework"]
        assert "format_examples" in result["testing_framework"]

    @pytest.mark.unit
    def test_test_type_options(self, sample_threats):
        """Test different test type options."""
        for test_type in ["unit", "integration", "penetration", "mixed"]:
            args = {"threats": sample_threats, "test_type": test_type}
            result = generate_security_tests(args)

            assert "testing_framework" in result
            assert result.get("requested_test_type") == test_type

    @pytest.mark.unit
    def test_format_type_options(self, sample_threats):
        """Test different format type options."""
        for format_type in ["gherkin", "checklist", "markdown"]:
            args = {"threats": sample_threats, "format_type": format_type}
            result = generate_security_tests(args)

            assert "testing_framework" in result
            assert result.get("requested_format") == format_type

    @pytest.mark.unit
    def test_example_test_cases_included(self, sample_threats):
        """Test that example test cases are provided."""
        args = {"threats": sample_threats}
        result = generate_security_tests(args)

        assert "format_examples" in result["testing_framework"]
        examples = result["testing_framework"]["format_examples"]
        assert len(examples) > 0


class TestGenerateThreatReport:
    """Tests for generate_threat_report function."""

    @pytest.mark.unit
    def test_report_returns_string(self, sample_threats):
        """Test that report returns markdown string."""
        args = {"threat_model": sample_threats}
        result = generate_threat_report(args)

        assert isinstance(result, str)
        assert len(result) > 0

    @pytest.mark.unit
    def test_report_has_markdown_structure(self, sample_threats):
        """Test that report contains markdown headers."""
        args = {"threat_model": sample_threats}
        result = generate_threat_report(args)

        # Check for common markdown elements
        assert "# " in result  # Header
        assert "## " in result  # Subheader

    @pytest.mark.unit
    def test_report_with_all_sections(self, sample_threats, sample_mitigations, sample_dread_scores):
        """Test report with all optional sections."""
        args = {
            "threat_model": sample_threats,
            "mitigations": sample_mitigations,
            "dread_scores": sample_dread_scores,
            "include_sections": ["executive_summary", "threats", "mitigations", "risk_scores"]
        }
        result = generate_threat_report(args)

        assert isinstance(result, str)
        assert "Executive Summary" in result or "executive" in result.lower()

    @pytest.mark.unit
    def test_report_with_minimal_input(self, sample_threats):
        """Test report generation with minimal input."""
        args = {"threat_model": sample_threats}
        result = generate_threat_report(args)

        assert isinstance(result, str)
        assert len(result) > 100  # Should have substantial content


class TestValidateThreatCoverage:
    """Tests for validate_threat_coverage function."""

    @pytest.mark.unit
    def test_validation_framework_structure(self, sample_threats, sample_app_context):
        """Test validation framework structure."""
        args = {"threat_model": sample_threats, "app_context": sample_app_context}
        result = validate_threat_coverage(args)

        assert "validation_framework" in result
        assert "coverage_criteria" in result["validation_framework"]
        assert "common_gaps" in result["validation_framework"]

    @pytest.mark.unit
    def test_stride_coverage_check(self, sample_threats, sample_app_context):
        """Test STRIDE coverage validation."""
        args = {"threat_model": sample_threats, "app_context": sample_app_context}
        result = validate_threat_coverage(args)

        assert "validation_framework" in result
        framework = result["validation_framework"]
        assert "coverage_criteria" in framework

    @pytest.mark.unit
    def test_common_gaps_identification(self, sample_threats, sample_app_context):
        """Test that common gaps are identified."""
        args = {"threat_model": sample_threats, "app_context": sample_app_context}
        result = validate_threat_coverage(args)

        assert "common_gaps" in result["validation_framework"]
        gaps = result["validation_framework"]["common_gaps"]
        assert isinstance(gaps, list)
        assert len(gaps) > 0


class TestGetRepositoryAnalysisGuide:
    """Tests for get_repository_analysis_guide function."""

    @pytest.mark.unit
    def test_initial_stage_guidance(self):
        """Test initial stage analysis guidance."""
        args = {"analysis_stage": "initial"}
        result = get_repository_analysis_guide(args)

        assert "stage" in result
        assert result["stage"] == "initial"
        assert "guidance" in result

    @pytest.mark.unit
    def test_deep_dive_stage_guidance(self):
        """Test deep dive stage guidance."""
        args = {
            "analysis_stage": "deep_dive",
            "repository_context": {
                "primary_language": "javascript",
                "framework_detected": "express",
                "repository_type": "application"
            }
        }
        result = get_repository_analysis_guide(args)

        assert "stage" in result
        assert result["stage"] == "deep_dive"
        assert "guidance" in result
        assert "technology_specific_guides" in result

    @pytest.mark.unit
    def test_validation_stage_guidance(self):
        """Test validation stage guidance."""
        args = {"analysis_stage": "validation"}
        result = get_repository_analysis_guide(args)

        assert "stage" in result
        assert result["stage"] == "validation"
        assert "guidance" in result
        assert "validation_checklist" in result

    @pytest.mark.unit
    def test_technology_specific_guides_included(self):
        """Test that technology-specific guides are available."""
        args = {
            "analysis_stage": "deep_dive",
            "repository_context": {
                "framework_detected": "fastapi"
            }
        }
        result = get_repository_analysis_guide(args)

        assert "technology_specific_guides" in result

    @pytest.mark.unit
    def test_default_stage_is_initial(self):
        """Test that default stage is initial if not specified."""
        args = {}
        result = get_repository_analysis_guide(args)

        assert "stage" in result
        # Should default to initial stage
        assert result["stage"] in ["initial", "quick_start"]
