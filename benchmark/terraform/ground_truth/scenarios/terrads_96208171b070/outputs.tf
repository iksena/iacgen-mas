output "org" {
  description = "aws_organizations_organization resource"
  value       = resource.aws_organizations_organization.org
}

output "ous" {
  description = "map of organizational units - keys are ou paths as string, values are aws_organizations_organizational_unit resources"
  value       = local.ous
}
