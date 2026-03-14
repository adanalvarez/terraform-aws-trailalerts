data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# -------------------------------------------------------
# S3 Bucket — private, static site files
# -------------------------------------------------------

resource "aws_s3_bucket" "dashboard_site" {
  bucket = lower("${var.project}-dashboard-${data.aws_caller_identity.current.account_id}")
}

resource "aws_s3_bucket_public_access_block" "dashboard_site" {
  bucket = aws_s3_bucket.dashboard_site.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "dashboard_site" {
  bucket = aws_s3_bucket.dashboard_site.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Upload logo
resource "aws_s3_object" "logo" {
  bucket       = aws_s3_bucket.dashboard_site.id
  key          = "logo.png"
  source       = "${path.module}/../../images/TrailAlerts.png"
  content_type = "image/png"
  etag         = filemd5("${path.module}/../../images/TrailAlerts.png")
}

# Upload index.html with rendered config
resource "aws_s3_object" "index_html" {
  bucket = aws_s3_bucket.dashboard_site.id
  key    = "index.html"
  content = templatefile("${path.module}/site/index.html", {
    cognito_domain       = var.cognito_domain
    cognito_client_id    = var.cognito_spa_client_id
    cognito_user_pool_id = var.cognito_user_pool_id
    aws_region           = data.aws_region.current.id
    project_name         = var.project
  })
  content_type = "text/html"
  etag = md5(templatefile("${path.module}/site/index.html", {
    cognito_domain       = var.cognito_domain
    cognito_client_id    = var.cognito_spa_client_id
    cognito_user_pool_id = var.cognito_user_pool_id
    aws_region           = data.aws_region.current.id
    project_name         = var.project
  }))
}

# -------------------------------------------------------
# CloudFront — HTTPS-only access
# -------------------------------------------------------

resource "aws_cloudfront_origin_access_control" "dashboard" {
  name                              = "${var.project}-dashboard-oac"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_distribution" "dashboard" {
  enabled             = true
  default_root_object = "index.html"
  comment             = "${var.project} Dashboard"
  price_class         = "PriceClass_100" # US, Canada, Europe only (cheapest)

  origin {
    domain_name              = aws_s3_bucket.dashboard_site.bucket_regional_domain_name
    origin_id                = "s3-dashboard"
    origin_access_control_id = aws_cloudfront_origin_access_control.dashboard.id
  }

  # API Gateway origin — strip the https:// scheme and any trailing path
  origin {
    domain_name = replace(replace(var.api_endpoint, "https://", ""), "/", "")
    origin_id   = "api-gateway"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  # /api/* → API Gateway (no caching, pass auth headers)
  ordered_cache_behavior {
    path_pattern           = "/api/*"
    target_origin_id       = "api-gateway"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods         = ["GET", "HEAD"]

    forwarded_values {
      query_string = true
      headers      = ["Authorization", "Content-Type", "Origin", "Accept"]
      cookies {
        forward = "none"
      }
    }

    min_ttl     = 0
    default_ttl = 0
    max_ttl     = 0
  }

  default_cache_behavior {
    target_origin_id       = "s3-dashboard"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    min_ttl     = 0
    default_ttl = 300
    max_ttl     = 3600

    response_headers_policy_id = aws_cloudfront_response_headers_policy.security_headers.id
  }

  # SPA routing: return index.html for 404s (client-side routing)
  custom_error_response {
    error_code            = 403
    response_code         = 200
    response_page_path    = "/index.html"
    error_caching_min_ttl = 0
  }

  custom_error_response {
    error_code            = 404
    response_code         = 200
    response_page_path    = "/index.html"
    error_caching_min_ttl = 0
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  tags = {
    Project     = var.project
    Environment = var.environment
  }
}

# Security response headers
resource "aws_cloudfront_response_headers_policy" "security_headers" {
  name    = "${var.project}-dashboard-security-headers"
  comment = "Security headers for ${var.project} dashboard"

  security_headers_config {
    content_type_options {
      override = true
    }
    frame_options {
      frame_option = "DENY"
      override     = true
    }
    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      preload                    = true
      override                   = true
    }
    xss_protection {
      mode_block = true
      protection = true
      override   = true
    }
    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }
    content_security_policy {
      content_security_policy = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; connect-src 'self' https://cognito-idp.${data.aws_region.current.id}.amazonaws.com; img-src 'self' data:; font-src 'self' https://fonts.gstatic.com;"
      override                = true
    }
  }
}

# -------------------------------------------------------
# S3 Bucket Policy — allow CloudFront OAC only
# -------------------------------------------------------

resource "aws_s3_bucket_policy" "dashboard_site" {
  bucket = aws_s3_bucket.dashboard_site.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowCloudFrontOAC"
        Effect    = "Allow"
        Principal = { Service = "cloudfront.amazonaws.com" }
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.dashboard_site.arn}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = aws_cloudfront_distribution.dashboard.arn
          }
        }
      }
    ]
  })
}
