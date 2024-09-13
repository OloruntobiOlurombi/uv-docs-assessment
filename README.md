# Automated EKS Cluster and Application Deployment Using Terraform and GitHub Actions

## Overview
This documentation outlines the automated deployment of an EKS cluster and a Flask-based application using Terraform and GitHub Actions. The deployment process covers the setup of AWS infrastructure, including VPCs, subnets, and IAM roles, as well as the creation of a secure EKS cluster. Additionally, the documentation details how the Flask application is built, tested, scanned for vulnerabilities, and deployed to the Kubernetes cluster.

## Key Features
- **AWS VPC** setup with public and private subnets.
- **Amazon EKS Cluster** and Node Group deployment for containerized applications.
- **IAM Roles** and Policies for secure access and resource management.
- **Encrypted EBS Volume** for data security.
- **S3 Bucket** with server-side encryption using AWS KMS.
- **SonarCloud** for static code analysis.
- **Snyk** for security vulnerability scanning.
- **GitHub Actions** for CI/CD automation, ensuring a smooth and efficient deployment process.

---

## Setup Steps

### Infrastructure Code

The infrastructure setup is automated through Terraform, with the following code files governing various aspects of the environment.

### 1. **VPC Configuration (`vpc.tf`)**

The code below sets up a VPC with public and private subnets, allowing resources like EKS to communicate internally while securing traffic.

```hcl
resource "aws_vpc" "main" {
  cidr_block       = var.vpc_cidr_block
  instance_tenancy = "default"

  tags = {
    Name = var.tags_vpc
  }
}

resource "aws_subnet" "public_subnet_1" {
  vpc_id     = aws_vpc.main.id
  cidr_block = var.p_s_1_cidr_block
  availability_zone = var.az_a
  map_public_ip_on_launch = true

  tags = {
    Name = var.tags_public_subnet_1
  }
}
# Similar subnet definitions for other public and private subnets...
```

### 2. **EKS Cluster and Node Group (`main.tf`)**

This file manages the creation of the EKS cluster and node groups. It also ensures encryption at rest using AWS KMS.

```hcl
terraform {
  backend "s3" {
    bucket = "regtech-iac"
    key = "terraform.tfstate"
    region = "us-east-1"
    encrypt = true 
  }
}

resource "aws_eks_cluster" "eks_cluster" {
  name     = var.cluster_name
  role_arn = aws_iam_role.eks_cluster_role.arn
  version  = "1.28"
  
  vpc_config {
    subnet_ids = [aws_subnet.public_subnet_1.id, aws_subnet.public_subnet_2.id, aws_subnet.public_subnet_3.id]
  }

  encryption_config {
    provider {
      key_arn = aws_kms_key.eks_encryption_key.arn
    }
    resources = ["secrets"]
  }
}
# EKS node group and EBS volume setup...
```

### 3. **IAM Roles (`iam.tf`)**

IAM roles and policies are defined for both the EKS cluster and worker nodes, ensuring secure access management.

```hcl
resource "aws_iam_role" "eks_cluster_role" {
    name = var.eks_cluster_role_name
    assume_role_policy = jsonencode({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": { "Service": "eks.amazonaws.com" },
                "Action": "sts:AssumeRole"
            }
        ]
    })
}
# IAM roles for node groups and policy attachments...
```

### 4. **Provider Configuration (`provider.tf`)**

This file specifies the required provider and AWS credentials.

```hcl
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region     = var.region
  access_key = var.aws_access_key_id
  secret_key = var.aws_secret_access_key
}
```

### 5. **Variables (`variables.tf`)**

All required input variables for AWS resources, including VPC CIDR blocks and availability zones, are declared here.

```hcl
variable "region" {
  type    = string
  default = "us-east-1"
}
# Other variables like bucket name, CIDR blocks...
```


### 6. **Cloudwatch (`cloudwatch.tf`)**

All required configuration for cloudwatch, cloudtrail and sns are in this file.

```hcl
resource "aws_cloudwatch_log_group" "eks_log_group" {
  name              = "/aws/eks/cluster-logs-regtech"
  retention_in_days = 30
}
# Other variables like bucket name, CIDR blocks...
```

### 7. **Autoscaler (`iam-autoscaler.tf`)**

All required configuration for Autoscaling are in this file.

```hcl
resource "aws_iam_role" "eks_cluster_autoscaler" {
  assume_role_policy = data.aws_iam_policy_document.eks_cluster_autoscaler_assume_role_policy.json
  name               = "eks-cluster-autoscaler"
}
# Other variables like bucket name, CIDR blocks...
```

### 8. **Openid Oidc (`oidc.tf`)**

All required configuration for Openid are in this file.

```hcl
resource "aws_iam_openid_connect_provider" "eks" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.eks_cluster.identity[0].oidc[0].issuer
}
# Other variables like bucket name, CIDR blocks...
```

### 9. **Security Group (`security_groups.tf`)**

All required configuration for Security Groups are in this file.

```hcl
resource "aws_security_group" "main_sg" {
    name = "main_sg"
    description = var.main_sg_description
    vpc_id = aws_vpc.main.id 

    ingress  {
        description = "ssh access"
        from_port = 22
        to_port = 22
        protocol = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }
}
# Other variables like bucket name, CIDR blocks...
```

### 10. **Routing (`routing.tf`)**

All required configuration for routing are in this file.

```hcl
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = var.tags_public_rt
  }
}

# Other variables like bucket name, CIDR blocks...
```
---

## Infrastructure Deployment: EKS Cluster

The infrastructure is deployed using the `eks-setup.yaml` workflow in GitHub Actions. This file automates the provisioning of AWS resources using Terraform.

### GitHub Actions Workflow: `eks-setup.yaml`

**Purpose:**
This workflow deploys the AWS EKS cluster using Terraform.

**Steps:**
1. **AWS Login:** Configures AWS credentials to allow Terraform to interact with AWS.
2. **Terraform Initialization:** Initializes Terraform and its required provider plugins.
3. **Terraform Plan:** Generates a plan of the changes without executing them.
4. **Terraform Apply:** Applies the infrastructure changes to provision the EKS cluster.

```yaml
name: Set up EKS with Terraform

on: push

env:
  AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
  AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
  AWS_REGION: ${{ secrets.AWS_REGION }}
  EKS_CLUSTER_NAME: ${{ secrets.EKS_CLUSTER_NAME }}

jobs:
  LogInToAWS:
    runs-on: ubuntu-latest
    steps:
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ env.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ env.AWS_SECRET_ACCESS_KEY }}
          aws-region: ${{ env.AWS_REGION }}

  TerraformInit:
    runs-on: ubuntu-latest
    needs: LogInToAWS
    steps:
      - name: Initialize Terraform
        run: terraform init

  TerraformPlan:
    runs-on: ubuntu-latest
    needs: TerraformInit
    steps:
      - name: Terraform Plan
        run: terraform plan

  TerraformApply:
    runs-on: ubuntu-latest
    needs: TerraformPlan
    steps:
      - name: Apply Terraform configuration
        run: terraform apply -auto-approve
```

### Key Outputs:
- **EKS Cluster Name:** The name of the provisioned EKS cluster.
- **EKS Cluster Endpoint:** The API endpoint for the Kubernetes cluster.
- **IAM Roles and Security Groups:** Output for access control and resource protection.

---

## Application Deployment: Flask App on EKS

Once the infrastructure is deployed, the Flask application is deployed using the `regtech-app.yaml` GitHub Actions workflow. The process includes linting, static analysis, testing, and finally deploying the Dockerized application to the EKS cluster.

### GitHub Actions Workflow: `regtech-app.yaml`

**Purpose:**
Automates the deployment of a Dockerized Flask application to an EKS cluster.

**Steps:**
1. **Lint and Static Analysis:** Runs SonarCloud for code analysis.
2. **Unit and Integration Tests:** Executes unit tests using `pytest`.
3. **Snyk Security Scan:** Scans for vulnerabilities in the dependencies.
4. **Build and Push Docker Image:** Builds the Docker image and pushes it to Amazon ECR.
5. **Deploy to EKS:** Deploys the Docker image to the EKS cluster using `kubectl`.

```yaml
name: Deploy Flask App to EKS

on:
  push:
    branches:
      - main

env:
  AWS_REGION: ${{ secrets.AWS_REGION }}
  EKS_CLUSTER_NAME: ${{ secrets.EKS_CLUSTER_NAME }}

jobs:
  Lint-and-Static-Analysis:
    name: Linting and Static Analysis (SonarQube)
    runs-on: ubuntu-latest
    steps:
      - name: SonarCloud Scan
        uses: sonarsource/sonarcloud-github-action@master
        with:
          sonar.organization: ${{ secrets.ORGANIZATION_KEY }}
          sonar.projectKey: ${{ secrets.PROJECT_KEY }}

  UnitAndIntegrationTests:
    name: Unit and Integration Tests
    runs-on: ubuntu-latest
    steps:
      - name: Install dependencies and run tests
        run: |
          python -m venv venv
          source venv/bin/activate
          pip install -r requirements.txt
          pytest test_app.py

  Build-and-Push-Docker-Image:
    name: Build and Push Docker Image
    runs-on: ubuntu-latest
    steps:
      - name: Build and tag Docker image
        run: |
          docker build -t regtech-app .
          docker tag regtech-app:latest <ecr-repo-uri>:latest
          docker push <ecr-repo-uri>:latest

  DeployToEKS:
    name: Deploy to EKS
    runs-on: ubuntu-latest
    steps:
      - name: Deploy Flask App to EKS
        run: |
          kubectl apply -f kubernetes/deployment.yaml
```

---

## Monitoring and Alerts Setup

Once the application is deployed, Prometheus and Grafana are set up to monitor the cluster's health and performance. These tools allow for real-time metrics and alerts in case of performance degradation or failures.

**Prometheus:** Captures and stores metrics from the EKS cluster and application.

**Grafana:** Visualizes the metrics and allows setting up alerts for key events, such as memory or CPU spikes.

---

## Security Best Practices

To ensure security, the following measures are taken:

- **Encryption:** All data is encrypted at rest and in transit using AWS KMS and SSL/TLS certificates.

- **IAM Roles:** Only the necessary permissions are granted to IAM roles, following the principle of least privilege.

- **S3 Bucket Policies:** The S3 buckets used for storing Terraform state files are secured with bucket policies and encryption.

---

## Conclusion
This documentation covers the full automation lifecycle of provisioning an EKS cluster using Terraform and deploying a Flask application using Docker and Kubernetes, all integrated with GitHub Actions CI/CD pipelines. It also includes monitoring and security best practices, ensuring a robust and scalable solution for managing infrastructure and application deployments.
