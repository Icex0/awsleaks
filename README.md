# AWSleaks

![awsleaks banner](images/awsleaks.png)

AWS security scanner that finds hardcoded secrets and internet-exposed resources across all regions and 30+ AWS services.

## Why AWSleaks?

Many AWS security scanners generate thousands of findings without verifying whether resources are actually exposed — they ignore security groups, policies, ACLs, and other controls that may already block exposure. They also lack automated secret verification, leaving you to manually triage false positives where keywords like "secret" are flagged with no actual credential present.

AWSleaks takes a different approach: it validates exposure against configurations and uses [BetterLeaks](https://github.com/betterleaks/betterleaks) to detect secrets.


## Install

```bash
# Run this from the project root directory
uv tool install --force .
```

## Commands

### `awsleaks secrets` — Scan for hardcoded secrets

Downloads code/configs from AWS services and scans with [BetterLeaks](https://github.com/betterleaks/betterleaks).

**Supported services (22):**

- Lambda (function code)
- CodeCommit (repository contents)
- CodeBuild (project configs & environment variables)
- CodePipeline (pipeline definitions)
- Glue (job scripts)
- Step Functions (state machine definitions)
- ECS (task definitions & environment variables)
- EC2 (user data & launch templates)
- CloudFormation (stack templates)
- Elastic Beanstalk (source bundles & environment configs)
- SageMaker (notebook configs & lifecycle scripts)
- SSM Parameters (plaintext parameters)
- SSM Documents (automation scripts)
- API Gateway (stage variables)
- AppSync (resolver templates)
- Batch (job definitions)
- Amplify (app configs & branch settings)
- S3 (public bucket contents)
- EMR (bootstrap scripts, step configs, cluster configurations)
- AppConfig (hosted configuration profiles)
- AppRunner (runtime environment variables)
- Lightsail (container service environment variables)

```bash
awsleaks secrets --profile my-profile
awsleaks secrets --profile my-profile --services lambda,glue,ecs
awsleaks secrets --profile my-profile --all-regions
awsleaks secrets --profile my-profile --regions eu-west-1,us-east-1
awsleaks secrets --profile my-profile --max-file-size 50   # skip S3 files over 50MB (default: 200MB)
```

### `awsleaks surface` — Discover internet-exposed resources

Enumerates public-facing AWS resources and misconfigurations. Generates nmap scan files for discovered targets.

**Supported checks (21):**

- Security Groups (rules open to 0.0.0.0/0)
- EC2 (public IPs with SG cross-reference for open ports)
- ELB/ALB/NLB (internet-facing load balancers with listener ports)
- RDS (PubliclyAccessible instances with SG cross-reference)
- Redshift (PubliclyAccessible clusters with SG cross-reference)
- S3 (public buckets via access block, policy, and ACL analysis)
- API Gateway (REST + HTTP APIs with resource policy analysis)
- Lambda Function URLs (with resource policy analysis)
- OpenSearch (public endpoints with access policy and fine-grained access control)
- EKS (public API endpoints with CIDR restrictions)
- ECS (public IP services with SG cross-reference)
- EBS Snapshots (publicly shared, encrypted vs unencrypted)
- RDS Snapshots (publicly shared DB and cluster snapshots)
- AMIs (publicly shared images, encrypted vs unencrypted)
- ECR (public repository policies)
- SQS (public queue policies)
- SNS (public topic policies)
- SSM Documents (publicly shared automation scripts)
- Amazon MQ (publicly accessible brokers with SG cross-reference for ActiveMQ, auth-only for RabbitMQ)
- AWS Transfer Family (public SFTP/FTP/FTPS servers)
- Route53 (DNS record collection with subdomain takeover detection via subjack)

```bash
awsleaks surface --profile my-profile
awsleaks surface --profile my-profile --checks ec2,security-groups,rds,s3
awsleaks surface --profile my-profile --all-regions
awsleaks surface --profile my-profile --regions eu-west-1,us-east-1
```

## Permissions

This tool only requires **read-only access**. The AWS managed policy `ReadOnlyAccess` covers all API calls used by both commands, but any custom policy with the relevant `Describe*`, `List*`, and `Get*` permissions will also work. No write permissions are needed.

## Authentication

```bash
# AWS profile (including SSO)
awsleaks secrets --profile my-profile

# Explicit credentials
awsleaks secrets --access-key AKIA... --secret-key wJal...

# Environment variables
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=wJal...
```

### SSO / Federated Users

```bash
aws configure sso
aws sso login --profile my-sso-profile
awsleaks secrets --profile my-sso-profile
```

## Parameters

| Parameter | Description |
|---|---|
| `--profile` | AWS profile name (supports SSO) |
| `--access-key` | AWS Access Key ID |
| `--secret-key` | AWS Secret Access Key |
| `--session-token` | AWS Session Token |
| `--region` | AWS Region (default from profile/env) |
| `--all-regions` | Scan all enabled AWS regions |
| `--regions` | Specific regions, comma or space separated |
| `--services` | (secrets) Services to scan, comma or space separated |
| `--checks` | (surface) Checks to run, comma or space separated |
| `--max-file-size` | (secrets) Max S3 file size in MB to download (default: 200) |

## Output

### Surface scan output

- Generates `hosts.txt` — unique target IPs/hostnames
- Generates `nmap_targets.txt` — nmap commands per target
- Generates `nmap_scan.sh` — ready-to-run scan script
- Generates `route53_domains.txt` — DNS records for subdomain takeover analysis

### Secrets scan output

- Downloads resources to `collected_code/`
- BetterLeaks reports saved to `betterleaks_reports/`
