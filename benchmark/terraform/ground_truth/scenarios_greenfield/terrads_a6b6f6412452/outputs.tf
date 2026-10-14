output "multi_access_point_status" {
  value = aws_s3control_multi_region_access_point.example.status
  description = "Status of multi_region_access_point"
}
output "multi_access_point_alias" {
  value = aws_s3control_multi_region_access_point.example.alias
  description = "alias of multi_region_access_point"
}
output "multi_access_point_domain_name" {
  value = aws_s3control_multi_region_access_point.example.domain_name
  description = "domain_name of multi_region_access_point"
}

output "multi_access_point_arn" {
  value = aws_s3control_multi_region_access_point.example.arn
  description = "arn of multi_region_access_point"
}