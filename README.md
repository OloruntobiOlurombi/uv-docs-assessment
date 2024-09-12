Automated EKS Cluster and Application Deployment Using Terraform and GitHub Actions
Overview
This documentation covers the automated deployment of an EKS cluster and a Flask-based application using Terraform and GitHub Actions. The process includes setting up the infrastructure, provisioning AWS resources, building and testing the application, performing static code analysis and security scans, and deploying the application to the Kubernetes cluster.
Key Features
AWS VPC setup with public and private subnets.
Amazon EKS Cluster and Node Group deployment for containerized applications.
IAM Roles and Policies for secure access and management.
Encrypted EBS Volume for data security.
S3 Bucket with server-side encryption using AWS KMS.
SonarCloud
Snyk
GitHub Actions for CI/CD automation.

Setup Steps


Infrastructure Code
This section provides the complete code for the infrastructure setup, divided into the respective Terraform files used in this project.

1. VPC Configuration (vpc.tf)
The following code sets up the VPC and subnets for both public and private access.

hcl
Copy code
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

resource "aws_subnet" "public_subnet_2" {
  vpc_id     = aws_vpc.main.id
  cidr_block = var.p_s_2_cidr_block
  availability_zone = var.az_b
  map_public_ip_on_launch = true

  tags = {
    Name = var.tags_public_subnet_2
  }
}

resource "aws_subnet" "public_subnet_3" {
  vpc_id     = aws_vpc.main.id
  cidr_block = var.p_s_3_cidr_block
  availability_zone = var.az_c
  map_public_ip_on_launch = true

  tags = {
    Name = var.tags_public_subnet_3
  }
}

resource "aws_subnet" "private_subnet_1" {
  vpc_id     = aws_vpc.main.id
  cidr_block = var.private_s_1_cidr_block
  availability_zone = var.az_private_a
  map_public_ip_on_launch = false 

  tags = {
    Name = var.tags_private_subnet_1
  }
}

resource "aws_subnet" "private_subnet_2" {
  vpc_id     = aws_vpc.main.id
  cidr_block = var.private_s_2_cidr_block
  availability_zone = var.az_private_b
  map_public_ip_on_launch = false 

  tags = {
    Name = var.tags_private_subnet_2
  }
}

resource "aws_subnet" "private_subnet_3" {
  vpc_id     = aws_vpc.main.id
  cidr_block = var.private_s_3_cidr_block
  availability_zone = var.az_private_c
  map_public_ip_on_launch = false 

  tags = {
    Name = var.tags_private_subnet_3
  }
}
2. EKS Cluster and Node Group (main.tf)
This file handles the setup of the EKS cluster, node groups, and other related resources like encryption and backend configuration.

hcl
Copy code
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
  version = "1.28"
  
  vpc_config {
    subnet_ids = [aws_subnet.public_subnet_1.id, aws_subnet.public_subnet_2.id, aws_subnet.public_subnet_3.id]
  }

  encryption_config {
    provider {
      key_arn = aws_kms_key.eks_encryption_key.arn
    }
    resources = ["secrets"]
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy_attachment,
    aws_iam_role_policy_attachment.eks_service_policy_attachment,
  ]
}

resource "aws_eks_node_group" "eks_node_group" {
  cluster_name    = aws_eks_cluster.eks_cluster.name
  node_group_name = var.node_group_name
  node_role_arn   = aws_iam_role.eks_node_group_role.arn
  subnet_ids      = [aws_subnet.public_subnet_1.id, aws_subnet.public_subnet_2.id, aws_subnet.public_subnet_3.id]

  scaling_config {
    desired_size = 2
    max_size     = 2
    min_size     = 2
  }
  update_config {
    max_unavailable = 1
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_worker_node_policy_attachment,
    aws_iam_role_policy_attachment.eks_cni_policy_attachment,
    aws_iam_role_policy_attachment.ec2_container_registry_readonly,
  ]
}

resource "aws_ebs_volume" "volume_regtech"{
    availability_zone = var.az_a
    size = 40
    encrypted = true
    type = "gp2"
    kms_key_id        = aws_kms_key.ebs_encryption_key.arn
}

resource "aws_s3_bucket" "regtech_iac" {
  bucket = var.bucket_name
}

resource "aws_s3_bucket_server_side_encryption_configuration" "regtech_iac_encrypt_config" {
    bucket = aws_s3_bucket.regtech_iac.bucket
    rule {
        apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.s3_encryption_key.arn  
        sse_algorithm = "aws:kms"
        }
    }
}

output "endpoint" {
  value = aws_eks_cluster.eks_cluster.endpoint
}

output "eks_cluster_name" {
    value = aws_eks_cluster.eks_cluster.name
}
3. IAM Roles (iam.tf)
The iam.tf file defines all necessary IAM roles for the EKS cluster, node groups, CloudWatch, and CloudTrail services, along with required policies.



data "aws_caller_identity" "current" {}

resource "aws_iam_role" "eks_cluster_role" {
    name = var.eks_cluster_role_name

    assume_role_policy = jsonencode({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "eks.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    })
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy_attachment" {
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    role = aws_iam_role.eks_cluster_role.name 
}

resource "aws_iam_role_policy_attachment" "eks_service_policy_attachment" {
  role       = aws_iam_role.eks_cluster_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSServicePolicy"
}

resource "aws_iam_role" "eks_node_group_role" {
    name = var.eks_node_group_role_name

    assume_role_policy = jsonencode({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "ec2.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    })
}

resource "aws_iam_role_policy_attachment" "eks_worker_node_policy_attachment" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eks_node_group_role.name
}

resource "aws_iam_role_policy_attachment" "eks_cni_policy_attachment" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.eks_node_group_role.name
}

resource "aws_iam_role_policy_attachment" "ec2_container_registry_readonly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.eks_node_group_role.name
}
4. Provider Configuration (provider.tf)
This file configures the required provider and AWS region for the Terraform infrastructure.

hcl
Copy code
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
5. Variables (variables.tf)
The variables.tf file defines all necessary input variables such as the AWS region, CIDR blocks, and instance types.


variable "region" {
    type = string 
    default = "us-east-1"
}

variable "bucket_name" {
    type = string 
    default = "regtech-logs"
}

variable "aws_access_key_id" {
    type = string
    default = ""
}

variable "aws_secret_access_key" {
    type = string
    default = ""
}

variable "vpc_cidr_block" {
    type = string 
    default = "10.0.0.0/16"
}

variable "p_s_1_cidr_block" {
    type = string 
    default = "10.0.1.0/24"
}

variable "az_a" {
    type = string 
    default = "us-east-1a"
}

1. Infrastructure Deployment: EKS Cluster
The first part of the process provisions the infrastructure using Terraform. The workflow file eks-setup.yaml automates the EKS cluster setup.

GitHub Actions Workflow: eks-setup.yaml
Purpose:
This file automates the deployment of AWS infrastructure, specifically setting up an EKS cluster using Terraform.

Steps:
AWS Login: Configures AWS credentials to ensure Terraform can interact with AWS.
Terraform Initialization: Initializes Terraform by downloading the necessary provider plugins.
Terraform Plan: Creates a plan of changes without actually making the changes yet.
Terraform Apply: Applies the Terraform configuration, provisioning the EKS cluster.
yaml
Copy code
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
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Initialize Terraform
        run: terraform init

  TerraformPlan:
    runs-on: ubuntu-latest
    needs: TerraformInit
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Terraform Plan
        run: terraform plan

  TerraformApply:
    runs-on: ubuntu-latest
    needs: TerraformPlan
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Apply Terraform configuration
        run: terraform apply -auto-approve
Key Outputs:
EKS Cluster Name: The name of the cluster.
EKS Cluster Endpoint: The API endpoint for the cluster.
Security Groups and IAM Roles associated with the EKS cluster.


2. Application Deployment: Flask App on EKS
The regtech-app.yaml GitHub Actions workflow handles the deployment of the Flask application. This workflow includes linting, static analysis, testing, Docker image building, vulnerability scanning, and deployment to the Kubernetes cluster.

GitHub Actions Workflow: regtech-app.yaml
Purpose:
Automates the deployment of the Flask app using Docker, Kubernetes, and several CI/CD steps such as testing and security scanning.

Steps:
Lint and Static Analysis (SonarCloud): Analyzes the codebase for bugs, code smells, and other issues.
Unit and Integration Tests: Runs unit and integration tests on the application using pytest.
Snyk Vulnerability Scanning: Scans for known vulnerabilities in dependencies using Snyk.
Build and Publish Docker Image: Builds the Flask app Docker image and pushes it to Amazon ECR.
Integration Tests on Docker Image: Tests the application within the Docker container.
Deploy to EKS Cluster: Deploys the Docker image to the EKS cluster.
yaml
Copy code
name: Deploy Flask App to EKS

on:
  push:
    branches:
      - main
  pull_request:
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
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: SonarCloud Scan
        uses: sonarsource/sonarcloud-github-action@master
        with:
          sonar.organization: ${{ secrets.ORGANIZATION_KEY }}
          sonar.projectKey: ${{ secrets.PROJECT_KEY }}

  UnitAndIntegrationTests:
    name: Unit and Integration Tests
    runs-on: ubuntu-latest
    steps:
      - name: Set up Python environment
        uses: actions/setup-python@v4
        with:
          python-version: '3'
      - name: Install dependencies and run tests
        run: |
          python -m venv venv
          source venv/bin/activate
          pip install -r requirements.txt
          pytest test_app.py

  SnykScan:
    name: Security Scan with Snyk
    runs-on: ubuntu-latest
    steps:
      - name: Set up Snyk
        uses: snyk/actions/python-3.10@master
        with:
          snyk_token: ${{ secrets.SNYK_TOKEN }}

  Build-and-Push-Docker-Image:
    name: Build and Push Docker Image
    runs-on: ubuntu-latest
    steps:
      - name: Build and tag Docker image
        run: |
          docker build -t regtech-app .
          docker tag regtech-app:latest <your-ecr-url>
      - name: Push Docker image to ECR
        run: docker push <your-ecr-url>

  DeployToEKS:
    name: Deploy Flask App to EKS
    runs-on: ubuntu-latest
    steps:
      - name: Install kubectl
        run: |
          curl -LO "https://storage.googleapis.com/kubernetes-release/release/stable.txt/bin/linux/amd64/kubectl"
          chmod +x ./kubectl
          sudo mv ./kubectl /usr/local/bin/kubectl
          
      - name: Update kubeconfig and deploy to EKS
        run: |
          aws eks update-kubeconfig --name ${{ env.EKS_CLUSTER_NAME }}
          kubectl apply -f deploy.yml
Key Steps:
SonarCloud Static Analysis: Detects code issues.
Unit Tests: Ensures functionality works as expected.
Snyk Scan: Identifies and mitigates security vulnerabilities.
Docker Build and Push: Builds the application image and stores it in Amazon ECR.
Kubernetes Deployment: Deploys the application to the EKS cluster.
3. Monitoring and Alerts Setup
Once the application is deployed, Prometheus and Grafana are set up to monitor the cluster's health and performance. These tools allow for real-time metrics and alerts in case of performance degradation or failures.

Prometheus: Captures and stores metrics from the EKS cluster and application.
Grafana: Visualizes the metrics and allows setting up alerts for key events, such as memory or CPU spikes.
4. Security Best Practices
To ensure security, the following measures are taken:

Encryption: All data is encrypted at rest and in transit using AWS KMS and SSL/TLS certificates.
IAM Roles: Only the necessary permissions are granted to IAM roles, following the principle of least privilege.
S3 Bucket Policies: The S3 buckets used for storing Terraform state files are secured with bucket policies and encryption.
Conclusion
This documentation covers the full automation lifecycle of provisioning an EKS cluster using Terraform and deploying a Flask application using Docker and Kubernetes, all integrated with GitHub Actions CI/CD pipelines. It also includes monitoring and security best practices, ensuring a robust and scalable solution for managing infrastructure and application deployments.


