# awsleaks

AWS security scanner — find hardcoded secrets and internet-exposed resources.

## Install

```bash
uv tool install --force .
```

## Commands

### `awsleaks secrets` — Scan for hardcoded secrets

Downloads code/configs from AWS services and scans with [BetterLeaks](https://github.com/betterleaks/betterleaks).

**Supported services:** Lambda, CodeCommit, CodeBuild, CodePipeline, Glue, Step Functions, ECS, EC2 (user data & launch templates), CloudFormation, Elastic Beanstalk, SageMaker, SSM Parameter Store, API Gateway, AppSync, Batch, Amplify, S3 (public buckets)

```bash
awsleaks secrets --profile my-profile
awsleaks secrets --profile my-profile --services lambda,glue,ecs
awsleaks secrets --profile my-profile --all-regions
awsleaks secrets --profile my-profile --regions eu-west-1,us-east-1
awsleaks secrets --profile my-profile --max-file-size 50   # skip S3 files over 50MB (default: 200MB)
```

### `awsleaks surface` — Discover internet-exposed resources

Enumerates public-facing AWS resources and misconfigurations. Generates nmap scan files for discovered targets.

**Checks:** Security Groups (0.0.0.0/0), EC2 (public IPs + SG cross-reference), ELB/ALB/NLB, RDS, Redshift, S3 (public buckets), API Gateway (REST + HTTP, resource policies), Lambda Function URLs (resource policies), OpenSearch (access policies + fine-grained access control), EKS (public API + CIDR restrictions), ECS (public IPs + SGs), EBS Snapshots (public sharing), RDS Snapshots (public sharing), AMIs (public images), ECR (public repository policies), SQS (public queue policies), SNS (public topic policies)

```bash
awsleaks surface --profile my-profile
awsleaks surface --profile my-profile --checks ec2,security-groups,rds,s3
awsleaks surface --profile my-profile --all-regions
awsleaks surface --profile my-profile --regions eu-west-1,us-east-1
```

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

- Generates `surface_results/hosts.txt` — unique target IPs/hostnames
- Generates `surface_results/nmap_targets.txt` — nmap commands per target
- Generates `surface_results/nmap_scan.sh` — ready-to-run scan script

### Secrets scan output

- Downloads resources to `collected_code/`
- BetterLeaks reports saved to `betterleaks_reports/`
