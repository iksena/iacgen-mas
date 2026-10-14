resource "aws_batch_compute_environment" "default" {

  compute_environment_name = "${local.common_tags.Name}"

  compute_resources {
    instance_role = aws_iam_instance_profile.ecs_instance.arn

    allocation_strategy = "BEST_FIT"

    instance_type = var.instance_types

    ec2_configuration {
      # image_id_override omitted (was an undefaulted variable) -- image_type
      # alone already tells AWS Batch to use its own AWS-managed ECS-optimized
      # AMI, so no override is actually needed here. ECS_AL2 (Amazon Linux 2)
      # is end-of-life and rejected by AWS Batch for new compute environments
      # as of this account's real-AWS test (2026-09-15) -- use the current
      # AL2023-based managed AMI instead.
      image_type = "ECS_AL2023"
    }

    max_vcpus = var.max_cpu
    min_vcpus = 0

    security_group_ids = [
      aws_security_group.batch.id
    ]

    subnets = [
      aws_subnet.private.id
    ]

    type = "EC2"

  }

  type         = "MANAGED"
  state        = "ENABLED"

  # For preventing race condition during deletion. See:
  # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/batch_compute_environment
  depends_on = [aws_iam_role_policy_attachment.batch_service]
}


resource "aws_batch_job_queue" "default" {
  name     = "${local.common_tags.Name}-queue"
  state    = "ENABLED"
  priority = 1
  compute_environments = [
    aws_batch_compute_environment.default.arn,
  ]
}
