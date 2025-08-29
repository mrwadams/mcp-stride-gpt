# STRIDE GPT MCP Beta Testing Guide

Welcome to the STRIDE GPT MCP server beta program! Thank you for helping test this leading-edge security analysis tool. This guide will help you get set up and provide effective feedback.

## Quick Start

### 1. Setup (5 minutes)

**Hosted Server (Recommended)**
```bash
# Claude Code
claude mcp add stride-gpt https://mcp.stridegpt.ai/ --transport http

# Claude Desktop - add to claude_desktop_config.json:
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

**Verification**: Start a new conversation and ask: *"What STRIDE GPT tools are available?"*

### 2. Basic Test (10 minutes)

Try this simple threat analysis:

```
Analyze threats for a basic e-commerce web application with user registration, 
product catalog, shopping cart, and Stripe payment processing. 
Uses React frontend, Node.js backend, and PostgreSQL database.
```

**Expected**: You should get a comprehensive threat model with 15-20 threats across all STRIDE categories.

### 3. Advanced Test (15 minutes)

Test MCP server combinations (if you have other MCPs installed):

```
Use GitHub MCP to analyze my repository [your-repo-url], then use STRIDE GPT 
to generate a threat model based on the discovered architecture.
```

## What to Test

### Core Functionality
- [ ] **Basic threat analysis** - Does it generate comprehensive, realistic threats?
- [ ] **STRIDE coverage** - Are all 6 categories (Spoofing, Tampering, etc.) covered?
- [ ] **Risk scoring** - Do DREAD scores make sense and have good justifications?
- [ ] **Mitigations** - Are security recommendations actionable and appropriate?
- [ ] **Attack trees** - Do attack paths make logical sense?
- [ ] **Professional reports** - Is the markdown output well-formatted and executive-ready?

### Integration Testing
- [ ] **GitHub MCP integration** - Repository analysis → threat modeling workflow
- [ ] **Multi-server workflows** - Combining 2+ MCP servers in one conversation
- [ ] **Large applications** - Complex, multi-component systems
- [ ] **Infrastructure threats** - Cloud, containers, Kubernetes scenarios

### Edge Cases
- [ ] **Unusual application types** - Mobile apps, IoT devices, APIs, desktop software
- [ ] **Minimal information** - What happens with vague descriptions?
- [ ] **Multiple threat models** - Running several analyses in one conversation
- [ ] **Error handling** - Invalid inputs, network issues, etc.

## Test Scenarios

### Scenario 1: Web Application Security Review
```
Analyze threats for a healthcare patient portal with:
- User authentication and authorization
- Medical record storage and retrieval
- Appointment scheduling
- Secure messaging between patients and doctors
- Integration with third-party lab systems
- HIPAA compliance requirements
```

### Scenario 2: Cloud Infrastructure Analysis
```
Model security threats for AWS infrastructure with:
- Application Load Balancer
- Auto Scaling Group with EC2 instances
- RDS PostgreSQL database
- S3 buckets for file storage
- CloudFront CDN
- IAM roles and policies
```

### Scenario 3: Container Security Assessment
```
Analyze threats for a microservices architecture with:
- Docker containers running on Kubernetes
- Service mesh (Istio)
- Container registry (ECR)
- Secrets management (Kubernetes secrets)
- Ingress controllers
- Pod-to-pod communication
```

### Scenario 4: DevOps Pipeline Security
```
Model threats for a CI/CD pipeline including:
- GitHub repository with pull requests
- GitHub Actions for CI/CD
- Docker image builds and scanning
- Terraform infrastructure deployment
- Production deployment on AWS EKS
```

## What Good Output Looks Like

### Comprehensive Threats
- **Specificity**: Threats should be specific to your application, not generic
- **Technical depth**: References to actual technologies and attack vectors
- **Business context**: Understanding of business impact and data sensitivity

### Quality Risk Scores
- **Justified ratings**: Each DREAD component should have clear reasoning
- **Appropriate prioritization**: High-risk threats should actually be high-risk
- **Consistent scoring**: Similar threats should have similar scores

### Actionable Mitigations
- **Implementable**: Specific technical controls you can actually deploy
- **Prioritized**: Clear guidance on what to tackle first
- **Defense in depth**: Multiple layers of security controls

## Feedback We Need

### 1. Quality Assessment
- Are the threats realistic and specific to your application?
- Do the risk scores make sense?
- Are mitigations actionable and appropriate?
- How does output quality compare to manual threat modeling?

### 2. Usability Feedback
- Was setup straightforward?
- Is the conversation interface intuitive?
- Are the tool descriptions clear?
- What workflow improvements would you suggest?

### 3. Performance Issues
- Any timeouts or errors?
- Slow response times?
- Inconsistent behavior across conversations?

### 4. Feature Requests
- What's missing from current functionality?
- What additional MCP server integrations would be valuable?
- What output formats would be helpful?

## Providing Feedback

### During Testing
- **Screenshot interesting outputs** (both good and bad examples)
- **Note specific error messages** or unexpected behavior
- **Try edge cases** - the weirder the better for beta testing

### Feedback Channels
- **GitHub Issues**: Technical bugs and feature requests
- **GitHub Discussions**: General feedback, questions, and feature discussions
- **Direct Messages**: Sensitive feedback or detailed discussions

### Feedback Template
```
## Test Scenario
[What application/infrastructure you tested]

## Output Quality (1-5 scale)
- Threat realism: X/5
- Risk scoring accuracy: X/5
- Mitigation usefulness: X/5

## Issues Found
[Any bugs, errors, or unexpected behavior]

## Suggestions
[Feature requests or improvements]

## Overall Impression
[Would you use this in your real security work?]
```

## Advanced Testing

### MCP Server Combinations
If you have other MCP servers installed, try these workflows:

**GitHub + STRIDE GPT**
1. Analyze a repository with GitHub MCP
2. Use findings to inform STRIDE GPT threat modeling

**Terraform + STRIDE GPT**
1. Parse Terraform configurations
2. Model infrastructure-specific threats

**Kubernetes + STRIDE GPT**
1. Analyze K8s manifests and configurations
2. Generate container orchestration threat model

### Large-Scale Testing
- **Enterprise applications** with 10+ components
- **Complex cloud architectures** with multiple services
- **Multi-tenant systems** with shared infrastructure
- **Legacy system modernization** scenarios

## Expected Time Commitment

- **Quick test**: 30 minutes (setup + basic scenarios)
- **Thorough test**: 2-3 hours (comprehensive scenarios + edge cases)
- **Deep dive**: 4+ hours (real-world applications + integrations)

## Beta Testing Timeline

- **Days 1-3**: Initial testing and setup feedback
- **Days 4-7**: Advanced scenarios and integrations
- **Days 8-10**: Edge cases, performance testing, and final feedback

## Getting Help

**Issues during testing?**
- Check the [GitHub repository](https://github.com/mrwadams/mcp-stride-gpt) for documentation
- Review MCP setup guides for your client (Claude Code, Claude Desktop, etc.)
- Contact me directly for urgent issues

**Want to discuss findings?**
- GitHub Discussions for technical conversations
- Direct messages for detailed feedback sessions

Thank you for helping push the boundaries of AI-powered security analysis! Your feedback will directly shape the future of this tool.

---
*This guide will be updated based on initial feedback from beta testers.*