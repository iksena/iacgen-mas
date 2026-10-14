variable "glueingestionpolicy" {
  description = "Policy IAM para o serviço de ingestão de dados no Glue"
  type        = string
  default     = "glue-ingestion-policy"
}

variable "glueingestionrole" {
  description = "Role IAM para o serviço de ingestão de dados no Glue"
  type        = string
  default     = "glue-ingestion-role"
}

variable "glueJobName" {
  description = "Nome Job Glue"
  type        = string
  default     = "glue-job-extrai-dados"
}

variable "glueJobNameTransforma" {
  description = "Nome Job Glue"
  type        = string
  default     = "glue-job-transforma-dados"
}

variable "python_version" {
  description = "Versão Python do Job Glue"
  type        = string
  default     = "3"
}

variable "bucket_artefact_glue" {
  description = "Bucket S3 Armazenamento Scripts Glue"
  type        = string
  default     = "benchmark-glue-artefacts"
}

variable "bucket_staging_lake" {
  description = "Bucket S3 Armazenamento Dados Camada Staging"
  type        = string
  default     = "benchmark-datalake-staging"
}

variable "bucket_bronze_lake" {
  description = "Bucket S3 Armazenamento Dados Camada Bronze"
  type        = string
  default     = "benchmark-datalake-bronze"
}

variable "bucket_silver_lake" {
  description = "Bucket S3 Armazenamento Dados Camada Bronze"
  type        = string
  default     = "benchmark-datalake-silver"
}

variable "bucket_gold_lake" {
  description = "Bucket S3 Armazenamento Dados Camada Bronze"
  type        = string
  default     = "benchmark-datalake-gold"
}

variable "bucket_log" {
  description = "Bucket S3 Armazenamento os Logs"
  type        = string
  default     = "benchmark-datalake-logs"
}

variable "key_api" {
  description = "Key API Clima"
  type        = string
  default     = "benchmark-placeholder-api-key"
}

variable "Cidade_API_Clima" {
  description = "Cidade para coleta de temperatura API"
  type        = string
  default     = "Sao Paulo"
}

variable "schedulerColetaClima" {
  description = "Schedulaer para Coleta do Clima"
  type        = string
  default     = "cron(0 * * * ? *)"
}

variable "keyTraduz" {
  description = "Key API Tradução Azure"
  type        = string
  default     = "benchmark-placeholder-key"
}
