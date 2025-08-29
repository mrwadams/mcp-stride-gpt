# STRIDE GPT MCP Server

A serverless MCP (Model Context Protocol) HTTP server deployed on Vercel that provides STRIDE threat modeling tools for comprehensive security analysis. This server exposes powerful threat modeling frameworks as standardized MCP tools that can be used by any MCP-compatible client.

## 🚀 Latest Updates (Beta Testing)

**Enhanced AI/ML Threat Coverage** - Based on beta tester feedback, I've significantly enhanced the server's ability to handle AI/ML security threats:

- ✅ **Complete OWASP LLM Top 10 (2025) Integration** - All 10 LLM vulnerabilities mapped to STRIDE categories
- ✅ **AI/ML-Specific Threat Frameworks** - Comprehensive coverage of prompt injection, model poisoning, excessive agency, and more
- ✅ **Rich Framework Data** - Tools now return detailed threat modeling information instead of placeholders
- ✅ **Enhanced Architecture Analysis** - Identifies AI/ML components (RAG systems, vector databases, model serving)
- ✅ **AI/ML Trust Boundaries** - Human-AI interfaces, model-data boundaries, training-inference boundaries
- ✅ **Specialized Attack Vectors** - AI input attacks, model manipulation, training pipeline compromise
- ✅ **AI/ML-Specific Mitigations** - OWASP LLM vulnerability mitigations and AI safety controls

🔄 **For Beta Testers**: 
- Please reload the MCP server / restart your MCP client to ensure you're using the updated frameworks
- **Important**: The repository has been standardized to use only the serverless Vercel deployment. Local MCP server files have been removed to prevent deployment confusion and ensure consistent behavior across all users.

## Features

- **Comprehensive STRIDE Analysis**: Generate threats across all six STRIDE categories with detailed framework guidance
- **Framework-Based Architecture**: MCP server provides threat modeling frameworks; LLM client performs semantic analysis
- **Risk Assessment**: Calculate DREAD scores with detailed justifications and scoring criteria
- **Attack Trees**: Generate hierarchical attack trees with Mermaid diagram support
- **Composable Architecture**: Designed to work seamlessly with other MCP servers (e.g., GitHub MCP)
- **Mitigation Planning**: Generate actionable security mitigations with implementation guidance
- **Test Case Generation**: Create security test cases in multiple formats (Gherkin, Checklist, Markdown)
- **Professional Reports**: Format complete threat models as executive-ready markdown reports
- **Coverage Validation**: Analyze threat model completeness and suggest enhancements

## Support the Project

If you find STRIDE GPT MCP useful, please consider supporting the project:

- ⭐ **Star the repository** on GitHub to help more people discover the tool
- ☕ **Buy me a coffee** to support continued development and maintenance

<a href="https://buymeacoffee.com/mrwadams" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px; width: 217px;">
</a>

## Usage

### Hosted MCP Server

The easiest way to use STRIDE GPT is through our hosted MCP server on Vercel:

**🌐 Server URL: https://mcp.stridegpt.ai/**

This serverless deployment provides all STRIDE GPT threat modeling tools without requiring local installation. Simply reference the URL in your MCP client configuration.

#### Adding to Claude Code

Add the hosted server to your Claude Code MCP configuration:

```bash
# Add the hosted STRIDE GPT MCP server
claude mcp add stride-gpt https://mcp.stridegpt.ai/ --transport http
```


## Configuration

### Claude Desktop (Hosted Server)

Add the hosted server to your Claude Desktop configuration:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`  
- **Linux**: `~/.config/claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "stride-gpt": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://mcp.stridegpt.ai/"],
      "description": "STRIDE GPT - Professional threat modeling using STRIDE methodology"
    }
  }
}
```

**Prerequisites**: Node.js must be installed for the `mcp-remote` package to work.

- Restart Claude Desktop after configuration changes

### GitHub Repository Analysis

For repository analysis, we recommend using the **official GitHub MCP server** alongside STRIDE GPT:

**Complete Configuration with GitHub MCP (Hosted STRIDE GPT):**
```json
{
  "mcpServers": {
    "stride-gpt": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://mcp.stridegpt.ai/"],
      "description": "STRIDE GPT - Professional threat modeling using STRIDE methodology"
    },
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "your-github-token"
      }
    }
  }
}
```

**Recommended Workflow:**
1. Use GitHub MCP server to analyze repository structure, files, and technologies
2. Use STRIDE GPT to analyze threats for the identified application architecture
3. Generate comprehensive threat model, risk scores, and mitigations

**Links:**
- [GitHub MCP Server](https://github.com/github/github-mcp-server)
- [GitHub MCP Server Documentation](https://github.com/github/github-mcp-server#readme)

## Recommended MCP Server Combinations

STRIDE GPT MCP server is designed to work seamlessly with other specialized MCP servers, creating powerful security analysis workflows. Here are the most effective combinations:

### Core Security Stack

**GitHub MCP + STRIDE GPT** - Repository analysis and threat modeling
- **Use Case**: Analyze repository structure, dependencies, and code patterns, then generate comprehensive threat models
- **Workflow**: GitHub MCP identifies tech stack and architecture → STRIDE GPT models security threats
- **Setup**: [GitHub MCP Server](https://github.com/github/github-mcp-server)

**Terraform MCP + STRIDE GPT** - Infrastructure-as-Code security analysis  
- **Use Case**: Analyze Terraform configurations for security misconfigurations before deployment
- **Workflow**: Terraform MCP parses infrastructure code → STRIDE GPT identifies infrastructure threats
- **Benefits**: Shift-left security, prevent deployment of vulnerable infrastructure

**Kubernetes MCP + STRIDE GPT** - Container orchestration security
- **Use Case**: Analyze Kubernetes manifests, RBAC policies, and container configurations
- **Workflow**: Kubernetes MCP analyzes cluster config → STRIDE GPT models container security threats
- **Focus Areas**: Pod security, network segmentation, orchestration vulnerabilities

**Docker Hub MCP + STRIDE GPT** - Container image and registry security
- **Use Case**: Analyze Docker images, container configurations, and registry metadata for security vulnerabilities
- **Workflow**: Docker Hub MCP queries container images and metadata → STRIDE GPT models container security threats
- **Benefits**: Base image vulnerability analysis, container configuration security, supply chain threat modeling
- **Setup**: [Docker Hub MCP Server](https://www.docker.com/blog/introducing-docker-hub-mcp-server/)

### Advanced Security Pipelines

**GitHub + Terraform + STRIDE GPT** - Complete DevSecOps analysis
- **Stage 1**: Repository analysis (code, dependencies, CI/CD)
- **Stage 2**: Infrastructure analysis (cloud resources, networking, IAM)  
- **Stage 3**: End-to-end threat modeling covering application and infrastructure
- **Output**: Comprehensive security assessment from source code to deployed infrastructure

**Docker Hub + Kubernetes + STRIDE GPT** - Complete container security pipeline
- **Stage 1**: Docker Hub MCP analyzes container images and base vulnerabilities
- **Stage 2**: Kubernetes MCP examines deployment manifests and runtime configs
- **Stage 3**: STRIDE GPT generates comprehensive containerized application threat model
- **Output**: End-to-end container security assessment from image to deployment

**AWS/Cloud MCP + STRIDE GPT** - Cloud security analysis
- **Use Case**: Analyze deployed cloud resources and security configurations
- **Benefits**: Runtime security assessment, compliance validation, threat hunting

### Workflow Benefits

1. **Composable Architecture**: Each MCP server handles its domain expertise
2. **Single Session**: One Claude conversation, multiple specialized tools
3. **No Custom Integration**: Leverage existing, maintained MCP servers
4. **Comprehensive Coverage**: Code → Infrastructure → Runtime → Threats
5. **Professional Output**: Executive-ready security reports and actionable recommendations

## Available Tools

### Core Analysis Tools

#### `analyze_application_threats`
**Description**: Generate comprehensive STRIDE threat model for an application

**Inputs**:
- `app_description` (string, required): Detailed description of the application
- `app_type` (string, default: "Web Application"): Type of application
- `authentication_methods` (array, default: ["Username/Password"]): Auth methods used
- `internet_facing` (boolean, default: true): Whether app is internet-accessible
- `sensitive_data_types` (array, default: ["User Data"]): Types of sensitive data

**Output**: Complete threat model with threats categorized by STRIDE, architecture components, trust boundaries, and coverage analysis

#### `generate_threat_mitigations`
**Description**: Generate security mitigations for multiple threats

**Inputs**:
- `threats` (array, required): Array of threat objects from analyze_application_threats
- `priority_filter` (string, default: "all"): Filter by "all", "high", "medium", "low"

**Output**: Comprehensive mitigation strategies with implementation difficulty, priorities, and defense layer categorization

#### `calculate_threat_risk_scores`
**Description**: Calculate DREAD risk scores for multiple threats

**Inputs**:
- `threats` (array, required): Array of threat objects
- `scoring_guidance` (object, optional): Custom scoring criteria

**Output**: DREAD scores with justifications, risk levels, and priority rankings

#### `create_threat_attack_trees`
**Description**: Generate attack trees for multiple threats

**Inputs**:
- `threats` (array, required): Array of threat objects
- `max_depth` (integer, default: 3): Maximum tree depth
- `output_format` (string, default: "both"): "structured", "mermaid", or "both"

**Output**: Hierarchical attack trees with optional Mermaid diagrams and critical path analysis

### Specialized Tools


#### `generate_security_tests`
**Description**: Generate security test cases for multiple threats

**Inputs**:
- `threats` (array, required): Array of threat objects
- `test_type` (string, default: "mixed"): "unit", "integration", "penetration", "mixed"
- `format_type` (string, default: "gherkin"): "gherkin", "checklist", "markdown"

**Output**: Comprehensive test cases with objectives and coverage estimates

#### `generate_threat_report`
**Description**: Format complete threat analysis as professional markdown report

**Inputs**:
- `threat_model` (array, required): Array of threat objects
- `mitigations` (array, optional): Array of mitigation objects
- `dread_scores` (array, optional): Array of DREAD score objects
- `attack_trees` (array, optional): Array of attack tree objects
- `include_sections` (array, default: ["executive_summary", "threats", "mitigations", "risk_scores"]): Sections to include

**Output**: Complete markdown report with executive summary and comprehensive statistics

#### `validate_threat_coverage`
**Description**: Validate threat model completeness and suggest enhancements

**Inputs**:
- `threat_model` (array, required): Array of threat objects
- `app_context` (object, required): Application context information

**Output**: Validation results, STRIDE coverage analysis, enhancement suggestions, and completeness scoring

## Usage Examples

### Basic Threat Analysis

```json
{
  "tool": "analyze_application_threats",
  "arguments": {
    "app_description": "E-commerce platform with user registration, product catalog, shopping cart, payment processing via Stripe, and order management. Uses React frontend, Node.js/Express backend, PostgreSQL database, and Redis for session storage.",
    "app_type": "Web Application",
    "authentication_methods": ["OAuth 2.0", "Multi-Factor Authentication"],
    "internet_facing": true,
    "sensitive_data_types": ["PII", "Payment Cards", "Transaction History"]
  }
}
```

### Repository-to-Threat-Model Workflow (with GitHub MCP)

This example demonstrates the powerful combination of GitHub MCP + STRIDE GPT MCP servers:

**Step 1: Repository Analysis (GitHub MCP)**
```
Use GitHub MCP to analyze repository:
- Get file structure and identify key components
- Read README.md, pyproject.toml, package.json for tech stack
- Examine source code structure and dependencies
- Identify authentication methods, data handling patterns
```

**Step 2: Threat Modeling (STRIDE GPT MCP)**
```json
{
  "tool": "analyze_application_threats",
  "arguments": {
    "app_description": "FastAPI web framework - high-performance Python API framework with OAuth2/JWT support, dependency injection, automatic OpenAPI docs, built on Starlette/Pydantic. Handles routing, middleware, authentication, validation for internet-facing APIs.",
    "app_type": "API Service", 
    "authentication_methods": ["OAuth 2.0", "JWT tokens", "API Keys"],
    "internet_facing": true,
    "sensitive_data_types": ["User Data", "Authentication Tokens", "API Keys"]
  }
}
```

**Step 3: Risk Assessment**
```json
{
  "tool": "calculate_threat_risk_scores",
  "arguments": {
    "threats": [/* threats from step 2 */]
  }
}
```

**Step 4: Generate Final Report**
```json
{
  "tool": "generate_threat_report", 
  "arguments": {
    "threat_model": [/* threats */],
    "mitigations": [/* mitigations */],
    "dread_scores": [/* risk scores */]
  }
}
```

### Complete Security Assessment Workflow

1. **Generate Threats**: Use `analyze_application_threats` to get comprehensive threat model
2. **Assess Risk**: Use `calculate_threat_risk_scores` with the threats from step 1
3. **Plan Mitigations**: Use `generate_threat_mitigations` with high-priority threats
4. **Create Documentation**: Use `generate_threat_report` to generate final report


## Development

### Running in Development Mode

```bash
# Start development server
uv run mcp dev src/stride_mcp/server.py

# Run with specific transport
uv run python src/stride_mcp/server.py --transport stdio
```

### Testing

```bash
# Run tests
uv run pytest

# Type checking
uv run pyright

# Linting
uv run ruff check .
uv run ruff format .
```

## Architecture

The server is built using the MCP Python SDK and follows these design principles:

- **Framework-Based Design**: MCP server provides comprehensive threat modeling frameworks and guidance through detailed docstrings; LLM clients perform the actual semantic analysis and threat generation
- **Composable MCP Pattern**: Designed to work alongside other specialized MCP servers (e.g., GitHub MCP for repository analysis)
- **Structured Output**: Uses Pydantic models for consistent, validated outputs across all tools
- **Comprehensive Guidance**: Each tool includes extensive documentation and framework guidance for high-quality threat modeling
- **Stateless Design**: Each tool call is independent and self-contained with no persistent state
- **Professional Quality**: Tools generate executive-ready reports and actionable security recommendations

## STRIDE Methodology

The server implements the complete STRIDE threat modeling methodology:

- **S**poofing: Identity verification attacks
- **T**ampering: Data integrity attacks
- **R**epudiation: Non-repudiation attacks
- **I**nformation Disclosure: Confidentiality attacks
- **D**enial of Service: Availability attacks
- **E**levation of Privilege: Authorization attacks

## Contributing

This MCP server is inspired by the [STRIDE GPT project](https://github.com/mrwadams/stride-gpt) but is maintained as a separate codebase. 

Contributions and issues for this MCP server should be submitted to this repository. For the main STRIDE GPT application, please use the main project repository.

## License

Same license as the main STRIDE GPT project.