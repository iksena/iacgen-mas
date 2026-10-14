resource "aws_eks_cluster" "this" {
  name     = var.cluster_name
  role_arn = aws_iam_role.this.arn
  count    = var.create_eks ? 1 : 0
  version  = var.cluster_version

  vpc_config {
    subnet_ids = coalescelist(var.control_plane_subnet_ids, var.subnet_ids)
  }

  access_config {
    authentication_mode                         = var.authentication_mode
    bootstrap_cluster_creator_admin_permissions = true
  }


  # Ensure that IAM Role permissions are created before and deleted after EKS Cluster handling.
  # Otherwise, EKS will not be able to properly delete EKS managed EC2 infrastructure such as Security Groups.
  depends_on = [
    aws_iam_role_policy_attachment.AmazonEKSClusterPolicy,
    aws_iam_role_policy_attachment.AmazonEKSVPCResourceController,
  ]
}

