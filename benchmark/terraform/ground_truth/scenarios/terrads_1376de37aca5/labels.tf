module "admin-label" {
  source      = "cloudposse/label/null"
  version     = "0.24.1"
  namespace   = var.namespace
  environment = var.environment
  name        = var.admin_name
  tags        = var.tags
  attributes  = var.attributes
}

module "other-label" {
  source      = "cloudposse/label/null"
  version     = "0.24.1"
  namespace   = var.namespace
  environment = var.environment
  name        = var.other_group_name
  tags        = var.tags
  attributes  = var.attributes
}
