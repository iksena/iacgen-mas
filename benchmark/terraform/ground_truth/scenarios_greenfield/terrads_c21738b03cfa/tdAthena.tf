resource "aws_athena_database" "database_gold" {
  name   = "silver"
  bucket = aws_s3_bucket.lake_silver.id

  encryption_configuration {
    encryption_option = "SSE_KMS"
    kms_key           = aws_kms_key.data_lake.arn
  }
}