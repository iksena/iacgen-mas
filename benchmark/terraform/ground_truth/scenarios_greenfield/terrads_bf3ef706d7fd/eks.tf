####################################################################
#
# Creates the EKS Cluster control plane
#
####################################################################

data "aws_iam_policy_document" "assume_role_eks" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "demo_eks" {
  name               = var.cluster_role_name
  assume_role_policy = data.aws_iam_policy_document.assume_role_eks.json
}

resource "aws_iam_role_policy_attachment" "demo_eks_AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.demo_eks.name
}

# Optionally, enable Security Groups for Pods
# Reference: https://docs.aws.amazon.com/eks/latest/userguide/security-groups-for-pods.html
resource "aws_iam_role_policy_attachment" "demo_eks_AmazonEKSVPCResourceController" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.demo_eks.name
}

resource "aws_kms_key" "demo_eks_secrets" {
  description             = "CMK for EKS cluster secrets envelope encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_iam_role_policy" "demo_eks_kms" {
  name = "demo-eks-secrets-kms"
  role = aws_iam_role.demo_eks.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["kms:Encrypt", "kms:Decrypt", "kms:ListGrants", "kms:DescribeKey"]
      Resource = aws_kms_key.demo_eks_secrets.arn
    }]
  })
}

resource "aws_eks_cluster" "demo_eks" {
  name     = var.cluster_name
  role_arn = aws_iam_role.demo_eks.arn

  vpc_config {
    subnet_ids = [
      aws_subnet.private[0].id,
      aws_subnet.private[1].id,
      aws_subnet.private[2].id
    ]
    endpoint_public_access  = false
    endpoint_private_access = true
  }

  encryption_config {
    resources = ["secrets"]
    provider {
      key_arn = aws_kms_key.demo_eks_secrets.arn
    }
  }

  # Ensure that IAM Role permissions are created before and deleted after EKS Cluster handling.
  # Otherwise, EKS will not be able to properly delete EKS managed EC2 infrastructure such as Security Groups.
  depends_on = [
    aws_iam_role_policy_attachment.demo_eks_AmazonEKSClusterPolicy,
    aws_iam_role_policy_attachment.demo_eks_AmazonEKSVPCResourceController,
    aws_iam_role_policy.demo_eks_kms,
  ]
}

data "aws_eks_cluster" "deme_eks" {
  name = aws_eks_cluster.demo_eks.name
}
