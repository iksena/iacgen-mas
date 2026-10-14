output "eip" {
  value = aws_eip.eip.public_ip
}

output "eip_id" {
  value = aws_eip.eip.id
}
output "vpc_id" {
  value = aws_vpc.main.id
}
output "vpc_subnet_id" {
  value = aws_subnet.public_subnet.id
}
