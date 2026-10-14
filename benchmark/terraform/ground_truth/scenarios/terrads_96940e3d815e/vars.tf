variable "region" {
  default     = "us-east-1"
  description = "Região default do AWS Academy"
}

variable "user-techlanches" {
  default     = "techlanches"
  description = "Usuário padrão"
}

variable "email-default" {
  default     = "g12.4soat.fiap@outlook.com"
  description = "Email padrão do cognito"
}

variable "password-default" {
  default     = "Test1234@"
  description = "Senha padrão do cognito"
}

variable "secrets-name" {
  default = "lambda-auth-credentials"
}