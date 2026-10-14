#----------------------------------------------#
# network-base: outputs                        #
# ./modules/aws/network-base/outputs.tf        #
#----------------------------------------------#

output "public_subnet_output" {
  description = "public subnet output"
  value       = aws_subnet.public_subnet.id
}

output "private_subnet_output" {
  description = "private subnet output"
  value       = aws_subnet.private_subnet.id
}

output "sg_webserver_output" {
  description = "security group webserver output"
  value       = aws_security_group.sg_webserver.id
}

output "sg_rds_output" {
  description = "security group database output"
  value       = aws_security_group.sg_rds.id
}
