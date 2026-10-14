resource "aws_security_group" "alb" {
  name   = "${var.prefix}-alb"
  vpc_id = module.vpc.vpc_id
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [module.vpc.vpc_cidr_block]
  }
}

resource "aws_lb" "main" {
  name                       = "${var.prefix}-alb"
  internal                   = true
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.alb.id]
  subnets                    = module.vpc.public_subnets
  enable_deletion_protection = false
  drop_invalid_header_fields = true
}

resource "aws_lb_target_group" "ip" {
  name                 = "${var.prefix}-tg"
  port                 = 80
  deregistration_delay = 30
  protocol             = "HTTP"
  target_type          = "ip"
  vpc_id               = module.vpc.vpc_id
  health_check {
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 3
    interval            = 30
    path                = "/healthz"
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = "80"
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
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = coalesce(var.certificate_arn, aws_acm_certificate.listener.arn)
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ip.arn
  }
}

resource "tls_private_key" "listener" {
  algorithm = "RSA"
}
resource "tls_self_signed_cert" "listener" {
  private_key_pem       = tls_private_key.listener.private_key_pem
  validity_period_hours = 8760
  allowed_uses          = ["key_encipherment", "digital_signature", "server_auth"]
  subject { common_name = "n8n.example.internal" }
}
resource "aws_acm_certificate" "listener" {
  private_key      = tls_private_key.listener.private_key_pem
  certificate_body = tls_self_signed_cert.listener.cert_pem
}
