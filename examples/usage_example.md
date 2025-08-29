# STRIDE GPT MCP Usage Examples

## Basic Threat Analysis

```
Human: I need to analyze threats for my e-commerce web application. It uses OAuth 2.0 authentication, is internet-facing, and handles payment card data and PII.

Agent: I'll help you analyze threats using the STRIDE methodology. Let me use the analyze_application_threats tool.

[Tool call: analyze_application_threats]
- app_description: "E-commerce web application with user accounts, product catalog, shopping cart, and payment processing"
- app_type: "Web Application"  
- authentication_methods: ["OAuth 2.0"]
- internet_facing: true
- sensitive_data_types: ["Payment Cards", "PII"]

[Tool result shows comprehensive threat model with 18 threats across all STRIDE categories]
```

## Complete Security Assessment

```
Human: Generate a complete security assessment including mitigations and risk scoring.

Agent: I'll generate a comprehensive security assessment. Let me use multiple tools to analyze your threats, generate mitigations, calculate risk scores, and create a formatted report.

[Tool calls in sequence:]
1. analyze_application_threats (as above)
2. generate_threat_mitigations using the threats from step 1
3. calculate_threat_risk_scores using the threats from step 1  
4. generate_threat_report combining all results

[Result: Complete markdown security assessment report]
```

## Repository Analysis with GitHub MCP

```
Human: Analyze the security of this GitHub repository: https://github.com/user/my-webapp

Agent: I'll analyze the repository using the GitHub MCP server first, then use STRIDE GPT to model threats.

[Using GitHub MCP server to analyze repository structure, dependencies, and tech stack]

[Tool call: analyze_application_threats using information gathered from repository]
- app_description: "React/Node.js web application with Express backend, PostgreSQL database, OAuth authentication..."
- app_type: "Web Application"
- authentication_methods: ["OAuth 2.0", "Session-based"]  
- internet_facing: true
- sensitive_data_types: ["User Data", "Session Data"]

[Result: Comprehensive threat model based on actual repository analysis]
```

## Attack Tree Generation

```
Human: Create an attack tree showing how an attacker could compromise our application.

Agent: I'll generate a comprehensive application-wide attack tree showing common attack vectors.

[Tool call: create_threat_attack_trees]
- threats: [array of all threats from previous analysis - used for context]
- output_format: "both" (structured + Mermaid diagrams)
- max_depth: 3

[Result shows single application-wide attack tree with root goal "Compromise Application", major attack vector categories as main branches, and Mermaid diagram for visualization]
```

## Validation and Enhancement

```
Human: Check if our threat model is complete and suggest improvements.

Agent: Let me validate your threat model and suggest enhancements.

[Tool call: validate_threat_coverage]
- threat_model: [your threats array]
- app_context: {app_type, authentication_methods, internet_facing, sensitive_data_types}

[Result shows STRIDE coverage analysis, completeness score, and specific enhancement suggestions]
```

## Infrastructure-as-Code Security Analysis with Terraform MCP

```
Human: Analyze the security of my Terraform infrastructure configuration.

Agent: I'll analyze your Terraform infrastructure for security threats using both Terraform MCP and STRIDE GPT servers.

[Using Terraform MCP server to parse infrastructure configuration]
- Parse .tf files to understand resource relationships
- Extract cloud resources, networking, IAM policies, security groups
- Identify data flows and trust boundaries

[Tool call: analyze_application_threats using infrastructure context]
- app_description: "AWS infrastructure with VPC, EC2 instances, RDS database, Application Load Balancer, S3 buckets, and IAM roles. Uses Terraform for Infrastructure-as-Code deployment..."
- app_type: "Cloud Infrastructure"
- authentication_methods: ["IAM Roles", "Security Groups", "Network ACLs"]
- internet_facing: true
- sensitive_data_types: ["Database Credentials", "Application Secrets", "Network Traffic"]

[Result: Infrastructure threat model identifying misconfigurations, privilege escalation paths, and security gaps before deployment]
```

## Kubernetes Security Analysis

```
Human: Analyze threats for my Kubernetes application deployment.

Agent: I'll combine Kubernetes MCP server analysis with STRIDE threat modeling for your containerized application.

[Using Kubernetes MCP server to analyze cluster configuration]
- Review deployment manifests, services, ingress rules
- Analyze RBAC policies and service accounts
- Examine network policies and security contexts

[Tool call: analyze_application_threats for containerized environment]
- app_description: "Microservices architecture on Kubernetes with multiple pods, services, ingress controllers, persistent volumes, and service mesh..."
- app_type: "Container Orchestration Platform"
- authentication_methods: ["Service Account Tokens", "RBAC", "Pod Security Standards"]
- internet_facing: true
- sensitive_data_types: ["Service Credentials", "Container Images", "Cluster State"]

[Result: Container-specific threat model covering pod security, network segmentation, and orchestration vulnerabilities]
```

## Multi-Server Security Pipeline

```
Human: Perform comprehensive security analysis using GitHub + Terraform + STRIDE GPT.

Agent: I'll create a complete DevSecOps security analysis pipeline using multiple MCP servers.

[Stage 1: Repository Analysis - GitHub MCP]
- Analyze codebase structure and dependencies
- Review CI/CD workflows and deployment scripts
- Identify application architecture and tech stack

[Stage 2: Infrastructure Analysis - Terraform MCP]
- Parse Terraform configurations for cloud resources
- Analyze infrastructure relationships and dependencies
- Extract security-relevant configurations

[Stage 3: Threat Modeling - STRIDE GPT]
- Generate comprehensive threat model covering both application and infrastructure
- Calculate risk scores for deployment pipeline threats
- Create attack trees showing end-to-end attack vectors

[Stage 4: Security Controls Validation]
- Map existing security controls to identified threats
- Generate actionable mitigations for high-risk gaps
- Create security test cases for CI/CD integration

[Result: End-to-end security analysis from source code to deployed infrastructure]
```

## Container Security Analysis with Docker Hub MCP

```
Human: Analyze the security of my containerized application including base images and deployment.

Agent: I'll analyze your container security using Docker Hub MCP for image analysis and STRIDE GPT for threat modeling.

[Using Docker Hub MCP server to analyze container images]
- Query Docker Hub for image metadata and vulnerability reports
- Analyze base image layers and installed packages
- Review container configuration and exposed ports

[Tool call: analyze_application_threats for containerized application]
- app_description: "Containerized web application using Node.js Alpine base image, running on port 3000, with Redis and PostgreSQL containers. Uses Docker Compose for orchestration..."
- app_type: "Containerized Application"
- authentication_methods: ["JWT Tokens", "Container Registry Auth"]
- internet_facing: true
- sensitive_data_types: ["Container Images", "Registry Credentials", "Application Secrets"]

[Result: Container-specific threat model covering image vulnerabilities, supply chain attacks, and runtime security]
```

## Complete Container Security Pipeline

```
Human: Perform comprehensive container security analysis using Docker Hub + Kubernetes + STRIDE GPT.

Agent: I'll create a complete container security analysis pipeline covering images, orchestration, and threat modeling.

[Stage 1: Image Analysis - Docker Hub MCP]
- Analyze container base images for known vulnerabilities
- Review image layers and installed packages
- Check for hardcoded secrets or misconfigurations

[Stage 2: Orchestration Analysis - Kubernetes MCP]
- Review Kubernetes deployment manifests and services
- Analyze RBAC policies and pod security contexts
- Examine network policies and ingress configurations

[Stage 3: Threat Modeling - STRIDE GPT]
- Generate comprehensive threat model covering container lifecycle
- Calculate risk scores for container-specific vulnerabilities
- Create attack trees showing container escape and privilege escalation paths

[Stage 4: Security Validation]
- Map container security controls to identified threats
- Generate mitigations for high-risk container vulnerabilities
- Create container security test cases for CI/CD integration

[Result: Complete container security assessment from image build to production deployment]
```