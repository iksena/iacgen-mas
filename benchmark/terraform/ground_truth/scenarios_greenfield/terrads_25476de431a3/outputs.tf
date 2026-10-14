output "s3_region_name" {
  description = "AWS S3 region name"
  value       = data.aws_region.current.name
}

output "s3_bucket_name" {
  description = "AWS S3 bucket name."
  value       = aws_s3_bucket.this.bucket
}

output "s3_bucket_path" {
  description = "AWS S3 bucket path."
  value       = var.s3_folder
}

output "s3_image_name" {
  description = "Image filename."
  value       = var.image_filename
}

output "s3_fqdn_path_url" {
  description = "FQDN path-style S3 URL."
  value       = local.s3_fqdn_path_url
}

output "s3_fqdn_virtual_url" {
  description = "FQDN virtual-hosted–style S3 URL."
  value       = local.s3_fqdn_virtual_url
}

output "aws_access_key_id" {
  description = "AWS Access Key ID."
  value       = var.create_iam_user ? aws_iam_access_key.this[0].id : null
}

output "aws_access_secret" {
  description = "AWS Access Secret."
  value       = var.create_iam_user ? aws_iam_access_key.this[0].secret : null
  sensitive   = true
}

output "zcli_datastore_command_fmt" {
  description = "zCLI command"
  value       = "zcli datastore create <name> [--title=<title>] --dstype=<dstype> [--fqdn=<fqdn>] [--region=<region>] [--apikey=<apikey>] [--apipass=<password>] [--dpath=<dpath>]"
}

output "zcli_datastore_command" {
  description = "zCLI command"
  value       = var.create_iam_user ? "zcli datastore create ${var.zedcloud_datastore_name} --title=${var.zedcloud_datastore_name} --dstype=AWSS3 --fqdn=${local.s3_fqdn_path_url} --region=${data.aws_region.current.name} --apikey=${aws_iam_access_key.this[0].id} --apipass=${aws_iam_access_key.this[0].secret} --dpath=${local.s3_dpath}" : null
  sensitive   = true
}

output "zcli_image_command_fmt" {
  description = "zCLI command"
  value       = "zcli image create <name> --datastore-name=<datastore> --arch=[AMD64|ARM64] --image-format=[raw|qcow|qcow2|vhd|vmdk|ova|vhdx|container] [--image-url=<rel_url>] [--title=<title>] [--type=[Eve|Application|EvePrivate]]"
}

output "zcli_image_command" {
  description = "zCLI command"
  value       = "zcli image create ${var.zedcloud_image_name} --title=${var.zedcloud_image_name} --datastore-name=${var.zedcloud_datastore_name} --arch=AMD64 --image-format=${var.image_format} --image-url=<rel_url> --type=Application"
}