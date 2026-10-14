resource "aws_s3_bucket" "s3_frontend_nft_maker_v2" {
  bucket = "s3-frontend-nft-maker-v2-${data.aws_caller_identity.current.account_id}"

}

resource "aws_s3_bucket_public_access_block" "s3_frontend_nft_maker_v2" {
  bucket                  = aws_s3_bucket.s3_frontend_nft_maker_v2.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_kms_key" "s3_frontend_nft_maker_v2" {
  description         = "CMK for s3-frontend-nft-maker-v2 S3 bucket"
  enable_key_rotation = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "s3_frontend_nft_maker_v2" {
  bucket = aws_s3_bucket.s3_frontend_nft_maker_v2.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3_frontend_nft_maker_v2.arn
    }
  }
}

resource "aws_cloudfront_origin_access_identity" "s3_frontend_nft_maker_v2" {
  comment = "OAI for s3-frontend-nft-maker-v2"
}

resource "aws_s3_bucket_policy" "s3_frontend_nft_maker_v2_policy" {
  bucket = aws_s3_bucket.s3_frontend_nft_maker_v2.id
  policy = data.aws_iam_policy_document.s3_frontend_nft_maker_v2_policy_document.json
}

data "aws_iam_policy_document" "s3_frontend_nft_maker_v2_policy_document" {
  statement {

    principals {
      type        = "AWS"
      identifiers = [aws_cloudfront_origin_access_identity.s3_frontend_nft_maker_v2.iam_arn]
    }

    actions = [
      "s3:GetObject",
      "s3:ListBucket",
    ]

    resources = [
      aws_s3_bucket.s3_frontend_nft_maker_v2.arn,
      "${aws_s3_bucket.s3_frontend_nft_maker_v2.arn}/*",
    ]
  }
}

resource "aws_s3_bucket_cors_configuration" "s3_frontend_nft_maker_v2_cors_config" {
  bucket = aws_s3_bucket.s3_frontend_nft_maker_v2.id

  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["PUT", "POST", "GET", "DELETE"]
    allowed_origins = ["*"]
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
  }
}

resource "aws_s3_bucket_website_configuration" "s3_frontend_nft_maker_v2_website_config" {
  bucket = aws_s3_bucket.s3_frontend_nft_maker_v2.id

  index_document {
    suffix = "index.html"
  }

  error_document {
    key = "index.html"
  }
}

resource "aws_wafv2_web_acl" "s3_frontend_nft_maker_v2" {
  name        = "s3-frontend-nft-maker-v2"
  description = "Web ACL for the s3-frontend-nft-maker-v2 CloudFront distribution"
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 0

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesCommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "s3-frontend-nft-maker-v2"
    sampled_requests_enabled   = true
  }
}

resource "aws_cloudfront_distribution" "s3_distribution" {
  origin {
    domain_name = aws_s3_bucket.s3_frontend_nft_maker_v2.bucket_regional_domain_name
    origin_id   = aws_s3_bucket.s3_frontend_nft_maker_v2.id

    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.s3_frontend_nft_maker_v2.cloudfront_access_identity_path
    }
  }

  web_acl_id = aws_wafv2_web_acl.s3_frontend_nft_maker_v2.arn

  enabled             = true
  is_ipv6_enabled     = true
  comment             = "Some comment"
  default_root_object = "index.html"

  # logging_config {
  #   include_cookies = false
  #   bucket          = "mylogs.s3.amazonaws.com"
  #   prefix          = "myprefix"
  # }
  
  # aliases = []

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = aws_s3_bucket.s3_frontend_nft_maker_v2.id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  # Cache behavior with precedence 0
  ordered_cache_behavior {
    path_pattern     = "/content/immutable/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD", "OPTIONS"]
    target_origin_id = aws_s3_bucket.s3_frontend_nft_maker_v2.id

    forwarded_values {
      query_string = false
      headers      = ["Origin"]

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  # Cache behavior with precedence 1
  ordered_cache_behavior {
    path_pattern     = "/content/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = aws_s3_bucket.s3_frontend_nft_maker_v2.id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  price_class = "PriceClass_200"

  restrictions {
    geo_restriction {
      restriction_type = "none"
      # locations        = ["US", "CA", "GB", "DE"]
    }
  }

  tags = {
    Environment = "production"
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}