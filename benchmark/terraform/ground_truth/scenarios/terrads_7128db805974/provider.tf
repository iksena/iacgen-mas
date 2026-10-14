# data "aws_caller_identity" "current" {
#   region = "eu-west-1"
# }
provider "aws" {
  region     = "eu-west-1"
}
# terraform {

#   backend "s3" {
#     bucket        = "YOUR-BUCKET-NAME-tf-state-dev"
#     key           = "YOUR_BACKUP_SCHEDULE.tfstate"
#     region        = "YOUR_REGION_BUCKET"
#     encrypt       = true
#   }
#}
