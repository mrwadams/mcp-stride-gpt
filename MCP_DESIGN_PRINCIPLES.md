# MCP Server Design Principles: Building Effective Information Providers for LLMs

*A comprehensive guide to designing MCP servers that leverage LLM capabilities instead of competing with them*

---

## Introduction

After building and refining the STRIDE GPT MCP server, we've learned valuable lessons about what makes MCP servers effective. This post covers the key design principles, common anti-patterns, and best practices for building MCP servers that work harmoniously with LLM clients.

## The Core Mental Model

### Wrong Mental Model: "Smart Analyst"
```
MCP Server = Mini-LLM that analyzes and generates content
```
This leads to servers that try to understand context, perform semantic analysis, and generate final outputs.

### Correct Mental Model: "Smart Database"
```
MCP Server = Specialized information provider with rich, structured data
LLM Client = Intelligent consumer that analyzes and generates based on that data
```

## Fundamental Design Principles

### 1. Information Provider, Not Analyzer

**✅ DO: Provide Rich Frameworks**
```python
def get_threat_framework():
    return {
        "stride_categories": {
            "S": {
                "description": "Identity spoofing and authentication bypass",
                "traditional_threats": ["User impersonation", "Token manipulation"],
                "ai_ml_threats": ["Deepfake attacks", "Model impersonation"],
                "mitigation_patterns": ["MFA", "Certificate-based auth"]
            }
            # ... comprehensive framework data
        },
        "application_analysis": analyze_app_context(app_description),
        "recommended_focus_areas": identify_focus_areas(app_type, data_types)
    }
```

**❌ DON'T: Try to Generate Final Threats**
```python
def analyze_threats():
    # Server tries to understand context and generate threats
    if "payment" in description:
        threats.append("Payment fraud")  # Brittle analysis
    return {"threats": threats}  # Minimal, final output
```

### 2. Semantic Analysis is LLM Territory

**✅ DO: Provide Analysis Frameworks**
```python
def get_risk_scoring_framework():
    return {
        "dread_criteria": {
            "damage": {
                "1-3": {"description": "Minor impact", "examples": [...], "ai_ml_factors": [...]},
                "4-6": {"description": "Moderate impact", "examples": [...], "ai_ml_factors": [...]}
            }
        },
        "context_considerations": {
            "traditional": ["Industry", "Compliance", "Business size"],
            "ai_ml": ["Model criticality", "Data sensitivity", "AI maturity"]
        }
    }
```

**❌ DON'T: Use Keyword Matching**
```python
def calculate_risk():
    # Brittle semantic analysis
    if any(word in description for word in ["payment", "financial"]):
        damage_score += 2
    return {"risk_score": damage_score}
```

### 3. Completeness Over Convenience

**✅ DO: Provide Complete Information**
```python
def get_test_frameworks():
    return {
        "test_patterns": all_test_patterns,      # Complete set
        "format_examples": all_format_types,     # All options
        "coverage_guidance": comprehensive_guide  # Full framework
    }
```

**❌ DON'T: Impose Arbitrary Limits**
```python
def generate_tests():
    return {
        "test_cases": test_cases[:5],  # Artificial limit
        "suggestions": suggestions[:3]  # Constrains LLM creativity
    }
```

### 4. Context-Aware but Not Context-Dependent

**✅ DO: Analyze Context to Provide Relevant Information**
```python
def get_security_framework(app_description, app_type):
    # Analyze to provide relevant information
    components = identify_components(app_description)
    frameworks = get_relevant_frameworks(app_type)
    
    return {
        "identified_components": components,
        "applicable_frameworks": frameworks,
        "context_analysis": app_analysis
    }
```

**❌ DON'T: Make Final Decisions Based on Context**
```python
def analyze_app(description):
    # Server makes final decisions
    if "AI" in description:
        return generate_ai_threats()  # Server decides what threats exist
    else:
        return generate_web_threats() # Server limits possibilities
```

## Common Anti-Patterns to Avoid

### 1. The "Empty Promise" Anti-Pattern

**Problem:** Tools promise analysis but return empty data
```python
def analyze_threats():
    return {
        "threats": [],           # Empty promise
        "components": [],        # No value provided
        "risk_analysis": None    # Placeholder response
    }
```

**Solution:** Return rich information that enables analysis
```python
def get_threat_framework():
    return {
        "framework_guidance": comprehensive_stride_framework,
        "application_context": analyzed_context,
        "reference_examples": example_threats
    }
```

### 2. The "Keyword Matching" Anti-Pattern

**Problem:** Server attempts semantic analysis through text matching
```python
# Brittle and unreliable
if "llm" in description.lower():
    add_ai_threats()
if "payment" in description.lower():
    increase_risk_score()
```

**Solution:** Provide frameworks for LLM semantic analysis
```python
return {
    "ai_ml_indicators": ["LLM", "model", "training", "inference"],
    "analysis_guidance": "LLM should analyze description for AI/ML patterns",
    "frameworks_by_type": {
        "ai_ml": ai_ml_frameworks,
        "traditional": traditional_frameworks
    }
}
```

### 3. The "Convenience Limits" Anti-Pattern

**Problem:** Server limits output for "readability" or "performance"
```python
return {
    "results": results[:10],     # Arbitrary limit
    "suggestions": top_5_only    # Constrains LLM options
}
```

**Solution:** Provide complete information; let LLM decide scope
```python
return {
    "complete_results": all_results,
    "prioritization_guidance": "LLM should select most relevant items",
    "result_metadata": {"total_count": len(all_results)}
}
```

### 4. The "Final Output" Anti-Pattern

**Problem:** Server returns final, formatted outputs
```python
def generate_report():
    return {
        "report": "# Final Report\n This is the completed analysis..."
    }
```

**Solution:** Provide report structure and data for LLM assembly
```python
def get_report_framework():
    return {
        "report_template": report_structure,
        "data_for_report": {
            "threats": threat_data,
            "statistics": calculated_stats
        },
        "formatting_guidance": formatting_examples
    }
```

## Best Practices

### 1. Rich Documentation in Code

Include comprehensive guidance in docstrings that LLM clients can access:

```python
def get_stride_framework(app_description: str) -> Dict[str, Any]:
    """Get comprehensive STRIDE threat modeling framework.
    
    ## STRIDE Categories with AI/ML Extensions:
    
    **Spoofing (S)**: Identity spoofing, authentication bypass
    - Traditional: User impersonation, token manipulation
    - AI/ML: Deepfake attacks, model identity spoofing, synthetic biometrics
    
    **Tampering (T)**: Data integrity violations
    - Traditional: Parameter tampering, data modification
    - AI/ML: Prompt injection (OWASP LLM01), training data poisoning
    
    [... comprehensive framework documentation ...]
    
    ## Usage Guidance:
    LLM clients should analyze the application description against these 
    frameworks to generate context-specific threats.
    """
```

### 2. Structured Return Formats

Use consistent, rich data structures:

```python
return {
    "frameworks": {
        "primary": main_framework,
        "supplementary": additional_frameworks
    },
    "context_analysis": {
        "application_type": analyzed_type,
        "identified_components": components,
        "risk_factors": risk_indicators
    },
    "guidance": {
        "usage_instructions": how_to_use,
        "customization_tips": adaptation_guide
    },
    "metadata": {
        "framework_version": "2025.1",
        "last_updated": timestamp
    }
}
```

### 3. Example-Driven Design

Provide examples as inspiration, not constraints:

```python
return {
    "base_patterns": standard_patterns,
    "example_adaptations": [
        {
            "context": "Healthcare AI system",
            "adaptation": "HIPAA-compliant threat scenarios"
        },
        {
            "context": "Financial trading bot", 
            "adaptation": "Market manipulation threats"
        }
    ],
    "customization_guidance": "Adapt examples to your specific domain"
}
```

### 4. Composability with Other MCP Servers

Design for integration:

```python
# Your MCP server provides threat modeling
def get_threat_framework(): ...

# Works with GitHub MCP for code analysis
# Works with Terraform MCP for infrastructure analysis
# Works with Kubernetes MCP for container analysis

# LLM client can combine information from multiple servers
```

## Testing Your MCP Server Design

Ask these questions about each tool:

### Information Richness Check
- ✅ Does this tool return substantial, useful information?
- ✅ Would an expert human find this data valuable for the task?
- ❌ Am I returning empty lists or placeholder responses?

### Responsibility Boundary Check  
- ✅ Am I providing frameworks and data for analysis?
- ✅ Is the LLM client empowered to do intelligent reasoning?
- ❌ Am I trying to replace LLM semantic understanding?

### Completeness Check
- ✅ Am I providing all relevant information available?
- ✅ Can the LLM client choose what's most appropriate?
- ❌ Am I artificially limiting output for "convenience"?

### Creativity Check
- ✅ Can LLM clients adapt and extend my information creatively?
- ✅ Are my examples inspiring rather than constraining?
- ❌ Am I forcing specific outputs or formats?

## Real-World Example: STRIDE GPT MCP Server

### Before: Anti-Patterns in Action
```python
def analyze_application_threats():
    # Empty promise - returns no useful data
    return {
        "threats": [],      # Placeholder
        "components": [],   # Placeholder  
        "coverage": {}      # Placeholder
    }

def calculate_risk_scores():
    # Keyword matching attempt
    if "payment" in threat_description:
        damage_score = 8
    # Artificial limits
    return {"top_risks": risks[:5]}
```

### After: Correct MCP Pattern
```python
def get_stride_threat_framework():
    # Rich framework information
    return {
        "stride_frameworks": {
            "S": {"traditional": [...], "ai_ml": [...], "examples": [...]},
            "T": {"traditional": [...], "ai_ml": [...], "examples": [...]}
        },
        "application_analysis": {
            "components": identified_components,
            "trust_boundaries": boundary_analysis,
            "risk_factors": risk_indicators
        },
        "guidance": "LLM should generate threats using frameworks and context"
    }

def get_dread_scoring_framework():
    # Complete scoring criteria and examples
    return {
        "scoring_criteria": complete_dread_framework,
        "ai_ml_considerations": ai_specific_factors,
        "example_scorings": reference_examples,
        "context_guidance": scoring_instructions
    }
```

## The Composable MCP Ecosystem

Well-designed MCP servers create powerful workflows:

```
GitHub MCP → Repository analysis → Code structure, dependencies
    ↓
STRIDE GPT MCP → Threat frameworks → Security analysis  
    ↓
LLM Client → Intelligent synthesis → Comprehensive security report
```

Each server focuses on its domain expertise while enabling rich, multi-server workflows.

## Deployment Best Practices

### Thin Deployment Wrappers

When adapting MCP servers for different deployment platforms (Vercel, AWS Lambda, etc.), keep deployment adapters as thin wrappers that import your main MCP server code:

**✅ DO: Thin Deployment Wrapper**
```python
# api/index.py (Vercel deployment wrapper)
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from stride_mcp.tools import register_tools
from mcp.server.fastmcp import FastMCP

# Create MCP server instance using your main implementation
mcp = FastMCP("STRIDE-GPT", "Professional threat modeling server")
register_tools(mcp)

def handle_mcp_request(body):
    # Delegate to the real MCP server implementation
    tool_name = body.get('params', {}).get('name')
    arguments = body.get('params', {}).get('arguments', {})
    
    if tool_name in mcp._tools:
        result = mcp._tools[tool_name](**arguments)
        return format_mcp_response(result, body.get('id'))
```

**❌ DON'T: Reimplementing Logic in Deployment Wrapper**
```python
# api/index.py - Bad pattern
def analyze_threats():
    # Duplicate implementation with different logic
    if "payment" in description:
        threats.append({"name": "Payment fraud"})
    return {"threats": threats}
```

### Benefits of Thin Wrappers:
- **Single source of truth** for your MCP server logic
- **Consistent behavior** between local development and production
- **Easy debugging** - if it works locally, it works in production
- **Reduced maintenance** - only one implementation to maintain

## Conclusion

Effective MCP servers are **information multipliers** that enhance LLM capabilities rather than replacing them. By following these principles:

- **Provide rich frameworks** instead of empty promises
- **Enable semantic analysis** instead of attempting it
- **Offer complete information** instead of convenient limits  
- **Inspire creativity** instead of constraining output
- **Use thin deployment wrappers** instead of reimplementing logic

You'll build MCP servers that unlock the full potential of LLM reasoning while providing genuine value through domain expertise and structured information.

The goal is not to build mini-LLMs, but to build the **best possible information sources** that LLMs can leverage for intelligent analysis and generation.

---

## About This Guide

This guide was developed while building the [STRIDE GPT MCP Server](https://github.com/mrwadams/stride-gpt), learning from both successes and mistakes in the implementation. The principles here reflect hard-won insights from beta testing and real-world usage.

For questions or discussions about MCP server design, feel free to open an issue in the STRIDE GPT repository or reach out to the community.