resource "aws_lb" "main" {
  name                       = "alb"
  internal                   = true
  load_balancer_type         = "application"
  drop_invalid_header_fields = true
  subnets            = aws_subnet.public[*].id
  security_groups    = [aws_security_group.alb.id]
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.listener.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.main.arn
  }
}

resource "aws_lb_target_group" "main" {
  name_prefix = "alb-tg"
  vpc_id      = aws_vpc.main.id
  protocol    = "HTTP"
  port        = var.application_port
  target_type = "ip"

  health_check {
    enabled = true
    path    = var.application_health_check_path
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "tls_private_key" "listener" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "listener" {
  private_key_pem       = tls_private_key.listener.private_key_pem
  dns_names             = ["app.example.internal"]
  validity_period_hours = 8760
  allowed_uses          = ["key_encipherment", "digital_signature", "server_auth"]

  subject {
    common_name = "app.example.internal"
  }
}

# Self-signed certificate imported into ACM so the listener can serve HTTPS without a domain.
resource "aws_acm_certificate" "listener" {
  private_key      = tls_private_key.listener.private_key_pem
  certificate_body = tls_self_signed_cert.listener.cert_pem
}
