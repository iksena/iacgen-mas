package intent.tf.row_247

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "vpc": {
   "types": [
    "aws_vpc"
   ],
   "where": [
    {
     "path": [
      "cidr_block"
     ],
     "op": "regex",
     "value": "/16$"
    }
   ]
  },
  "subnets": {
   "types": [
    "aws_subnet"
   ],
   "where": []
  },
  "ifc_eps": {
   "types": [
    "aws_vpc_endpoint"
   ],
   "where": [
    {
     "path": [
      "vpc_endpoint_type"
     ],
     "op": "eq",
     "value": "Interface"
    }
   ]
  },
  "s3_ep": {
   "types": [
    "aws_vpc_endpoint"
   ],
   "where": [
    {
     "path": [
      "vpc_endpoint_type"
     ],
     "op": "eq",
     "value": "Gateway"
    },
    {
     "path": [
      "service_name"
     ],
     "op": "regex",
     "value": "(?i)\\.s3$"
    }
   ]
  },
  "ns": {
   "types": [
    "aws_service_discovery_private_dns_namespace"
   ],
   "where": []
  },
  "sd": {
   "types": [
    "aws_service_discovery_service"
   ],
   "where": []
  },
  "svc": {
   "types": [
    "aws_ecs_service"
   ],
   "where": []
  },
  "taskdef": {
   "types": [
    "aws_ecs_task_definition"
   ],
   "where": []
  },
  "inst": {
   "types": [
    "aws_instance"
   ],
   "where": []
  },
  "nic": {
   "types": [
    "aws_network_interface"
   ],
   "where": []
  },
  "profile": {
   "types": [
    "aws_iam_instance_profile"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "vpc_cidr16",
   "tier": "core",
   "kind": "exists",
   "select": "vpc",
   "quote": "a VPC with a /16 CIDR block",
   "justify": "/16 stated"
  },
  {
   "id": "vpc_dns_hostnames",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_vpc"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "enable_dns_hostnames"
    ],
    "op": "eq",
    "value": true
   },
   "quote": "enabled DNS hostnames"
  },
  {
   "id": "six_subnets",
   "tier": "core",
   "kind": "exists",
   "select": "subnets",
   "min": 6,
   "quote": "three public and three private subnets",
   "justify": "3 public + 3 private = 6"
  },
  {
   "id": "three_azs",
   "tier": "core",
   "kind": "exists",
   "select": "subnets",
   "min": 3,
   "distinct_path": [
    "availability_zone"
   ],
   "quote": "spanning three Availability Zones",
   "justify": "three AZs"
  },
  {
   "id": "subnets_in_us_east_1",
   "tier": "detail",
   "kind": "attr",
   "select": "subnets",
   "cond": {
    "path": [
     "availability_zone"
    ],
    "op": "regex",
    "value": "^us-east-1"
   },
   "quantifier": "all",
   "quote": "in us-east-1"
  },
  {
   "id": "nat_per_az",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_nat_gateway"
    ],
    "where": []
   },
   "min": 3,
   "quote": "one NAT gateway per Availability Zone",
   "justify": "one per AZ across three AZs"
  },
  {
   "id": "s3_gateway_endpoint",
   "tier": "core",
   "kind": "exists",
   "select": "s3_ep",
   "quote": "a gateway VPC endpoint for S3"
  },
  {
   "id": "s3_endpoint_private_rts",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_vpc_endpoint_route_table_association"
      ],
      "where": []
     }
    },
    {
     "kind": "attr",
     "select": "s3_ep",
     "cond": {
      "path": [
       "route_table_ids"
      ],
      "op": "present"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_vpc_endpoint"
       },
       {
        "path": [
         "properties",
         "service_name"
        ],
        "op": "regex",
        "value": "(?i)s3"
       },
       {
        "path": [
         "properties",
         "route_table_ids"
        ],
        "op": "present"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "vpc_endpoint_type"
      ],
      "op": "eq",
      "value": "Gateway"
     }
    }
   ],
   "quote": "attached to the private route tables"
  },
  {
   "id": "ifc_endpoint_ecr_dkr",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_vpc_endpoint"
    ],
    "where": [
     {
      "path": [
       "vpc_endpoint_type"
      ],
      "op": "eq",
      "value": "Interface"
     },
     {
      "path": [
       "service_name"
      ],
      "op": "regex",
      "value": "(?i)\\.ecr\\.dkr$"
     }
    ]
   },
   "quote": "interface endpoints for ECR Docker, ECR API, CloudWatch Logs, Secrets Manager, SSM, and KMS"
  },
  {
   "id": "ifc_endpoint_ecr_api",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_vpc_endpoint"
    ],
    "where": [
     {
      "path": [
       "vpc_endpoint_type"
      ],
      "op": "eq",
      "value": "Interface"
     },
     {
      "path": [
       "service_name"
      ],
      "op": "regex",
      "value": "(?i)\\.ecr\\.api$"
     }
    ]
   },
   "quote": "interface endpoints for ECR Docker, ECR API, CloudWatch Logs, Secrets Manager, SSM, and KMS"
  },
  {
   "id": "ifc_endpoint_logs",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_vpc_endpoint"
    ],
    "where": [
     {
      "path": [
       "vpc_endpoint_type"
      ],
      "op": "eq",
      "value": "Interface"
     },
     {
      "path": [
       "service_name"
      ],
      "op": "regex",
      "value": "(?i)\\.logs$"
     }
    ]
   },
   "quote": "interface endpoints for ECR Docker, ECR API, CloudWatch Logs, Secrets Manager, SSM, and KMS"
  },
  {
   "id": "ifc_endpoint_secretsmanager",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_vpc_endpoint"
    ],
    "where": [
     {
      "path": [
       "vpc_endpoint_type"
      ],
      "op": "eq",
      "value": "Interface"
     },
     {
      "path": [
       "service_name"
      ],
      "op": "regex",
      "value": "(?i)\\.secretsmanager$"
     }
    ]
   },
   "quote": "interface endpoints for ECR Docker, ECR API, CloudWatch Logs, Secrets Manager, SSM, and KMS"
  },
  {
   "id": "ifc_endpoint_ssm",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_vpc_endpoint"
    ],
    "where": [
     {
      "path": [
       "vpc_endpoint_type"
      ],
      "op": "eq",
      "value": "Interface"
     },
     {
      "path": [
       "service_name"
      ],
      "op": "regex",
      "value": "(?i)\\.ssm$"
     }
    ]
   },
   "quote": "interface endpoints for ECR Docker, ECR API, CloudWatch Logs, Secrets Manager, SSM, and KMS"
  },
  {
   "id": "ifc_endpoint_kms",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_vpc_endpoint"
    ],
    "where": [
     {
      "path": [
       "vpc_endpoint_type"
      ],
      "op": "eq",
      "value": "Interface"
     },
     {
      "path": [
       "service_name"
      ],
      "op": "regex",
      "value": "(?i)\\.kms$"
     }
    ]
   },
   "quote": "interface endpoints for ECR Docker, ECR API, CloudWatch Logs, Secrets Manager, SSM, and KMS"
  },
  {
   "id": "endpoint_sg_https",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "ingress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [],
        "op": "port_covers",
        "value": 443
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "present"
       },
       {
        "path": [
         "protocol"
        ],
        "op": "neq",
        "value": "-1"
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "none_eq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_security_group_rule"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "ingress"
       },
       {
        "path": [],
        "op": "port_covers",
        "value": 443
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "present"
       },
       {
        "path": [
         "protocol"
        ],
        "op": "neq",
        "value": "-1"
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "none_eq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [],
        "op": "port_covers",
        "value": 443
       },
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "present"
       },
       {
        "path": [
         "ip_protocol"
        ],
        "op": "neq",
        "value": "-1"
       },
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "neq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    }
   ],
   "quote": "all secured by a security group allowing inbound HTTPS traffic from the VPC CIDR",
   "justify": "HTTPS implies 443; from the VPC CIDR rules out an all-traffic rule (protocol -1) and the any-IP CIDR"
  },
  {
   "id": "endpoints_use_sg",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "ifc_eps",
     "to": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     }
    },
    {
     "kind": "attr",
     "select": "ifc_eps",
     "cond": {
      "path": [
       "security_group_ids",
       "*"
      ],
      "op": "present"
     },
     "quantifier": "all"
    }
   ],
   "quote": "all secured by a security group"
  },
  {
   "id": "cloudmap_namespace",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_service_discovery_private_dns_namespace"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "private-fargate-crowdnews.hands-on.cloud.local"
     }
    ]
   },
   "quote": "a private Cloud Map DNS namespace named \"private-fargate-crowdnews.hands-on.cloud.local\""
  },
  {
   "id": "namespace_in_vpc",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "ns",
     "to": {
      "types": [
       "aws_vpc"
      ],
      "where": []
     }
    },
    {
     "kind": "attr",
     "select": "ns",
     "cond": {
      "path": [
       "vpc"
      ],
      "op": "present"
     }
    }
   ],
   "quote": "within the VPC"
  },
  {
   "id": "ecr_repo",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_ecr_repository"
    ],
    "where": []
   },
   "quote": "an ECR repository"
  },
  {
   "id": "ecr_immutable",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_ecr_repository"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "image_tag_mutability"
    ],
    "op": "eq",
    "value": "IMMUTABLE"
   },
   "quote": "immutable tags"
  },
  {
   "id": "ecr_scan_on_push",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_ecr_repository"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "image_scanning_configuration",
     "*",
     "scan_on_push"
    ],
    "op": "eq",
    "value": true
   },
   "quote": "scan-on-push enabled"
  },
  {
   "id": "log_group",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_cloudwatch_log_group"
    ],
    "where": []
   },
   "quote": "a CloudWatch log group"
  },
  {
   "id": "ecs_cluster",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_ecs_cluster"
    ],
    "where": []
   },
   "quote": "an ECS cluster"
  },
  {
   "id": "taskdef_cpu",
   "tier": "core",
   "kind": "attr",
   "select": "taskdef",
   "cond": {
    "path": [
     "cpu"
    ],
    "op": "eq",
    "value": 512
   },
   "quote": "utilizing 512 CPU units"
  },
  {
   "id": "taskdef_memory",
   "tier": "core",
   "kind": "attr",
   "select": "taskdef",
   "cond": {
    "path": [
     "memory"
    ],
    "op": "eq",
    "value": 1024
   },
   "quote": "1024 memory"
  },
  {
   "id": "taskdef_awsvpc",
   "tier": "core",
   "kind": "attr",
   "select": "taskdef",
   "cond": {
    "path": [
     "network_mode"
    ],
    "op": "eq",
    "value": "awsvpc"
   },
   "quote": "in awsvpc mode"
  },
  {
   "id": "taskdef_fargate",
   "tier": "core",
   "kind": "attr",
   "select": "taskdef",
   "cond": {
    "path": [
     "requires_compatibilities",
     "*"
    ],
    "op": "eq",
    "value": "FARGATE"
   },
   "quote": "a Fargate task definition"
  },
  {
   "id": "container_nginx_image",
   "tier": "detail",
   "kind": "attr",
   "select": {
    "types": [
     "__declared__"
    ],
    "where": [
     {
      "path": [
       "type"
      ],
      "op": "eq",
      "value": "aws_ecs_task_definition"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "container_definitions"
    ],
    "op": "regex",
    "value": "(?i)nginx|local\\.[a-z_]*(container|task)"
   },
   "quote": "to run the NGINX image"
  },
  {
   "id": "container_port_80",
   "tier": "detail",
   "kind": "attr",
   "select": {
    "types": [
     "__declared__"
    ],
    "where": [
     {
      "path": [
       "type"
      ],
      "op": "eq",
      "value": "aws_ecs_task_definition"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "container_definitions"
    ],
    "op": "regex",
    "value": "(?is)containerPort.{0,40}[^0-9]80([^0-9]|$)|local\\.[a-z_]*(container|task)"
   },
   "quote": "on port 80"
  },
  {
   "id": "container_namespace_env",
   "tier": "detail",
   "kind": "attr",
   "select": {
    "types": [
     "__declared__"
    ],
    "where": [
     {
      "path": [
       "type"
      ],
      "op": "eq",
      "value": "aws_ecs_task_definition"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "container_definitions"
    ],
    "op": "regex",
    "value": "(?is)environment.*(namespace|service_discovery)|local\\.[a-z_]*(container|task)"
   },
   "quote": "passing the service discovery namespace ID as an environment variable"
  },
  {
   "id": "service_exists",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "svc",
     "cond": {
      "path": [
       "launch_type"
      ],
      "op": "eq",
      "value": "FARGATE"
     }
    },
    {
     "kind": "attr",
     "select": "svc",
     "cond": {
      "path": [
       "capacity_provider_strategy",
       "*",
       "capacity_provider"
      ],
      "op": "regex",
      "value": "(?i)FARGATE"
     }
    }
   ],
   "quote": "Deploy this as a Fargate service"
  },
  {
   "id": "service_desired_count",
   "tier": "core",
   "kind": "attr",
   "select": "svc",
   "cond": {
    "path": [
     "desired_count"
    ],
    "op": "eq",
    "value": 1
   },
   "quote": "a desired count of 1 task"
  },
  {
   "id": "service_private_subnets",
   "tier": "detail",
   "kind": "ref",
   "from": "svc",
   "to": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "quote": "in the private subnets"
  },
  {
   "id": "service_uses_taskdef",
   "tier": "detail",
   "kind": "ref",
   "from": "svc",
   "to": "taskdef",
   "quote": "Deploy this as a Fargate service"
  },
  {
   "id": "iam_roles",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_iam_role"
    ],
    "where": []
   },
   "min": 2,
   "quote": "dedicated execution and task IAM roles",
   "justify": "execution role and task role = 2"
  },
  {
   "id": "taskdef_uses_roles",
   "tier": "detail",
   "kind": "ref",
   "from": "taskdef",
   "to": {
    "types": [
     "aws_iam_role"
    ],
    "where": []
   },
   "quote": "dedicated execution and task IAM roles"
  },
  {
   "id": "policy_ecr",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ecr:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ecr:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "inline_policy"
      ],
      "op": "regex",
      "value": "(?i)ecr:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "in",
        "value": [
         "aws_iam_policy",
         "aws_iam_role_policy",
         "aws_iam_role",
         "data.aws_iam_policy_document"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)ecr:"
     }
    }
   ],
   "quote": "necessary inline policies for ECR pulls"
  },
  {
   "id": "policy_logs",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)logs:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)logs:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "inline_policy"
      ],
      "op": "regex",
      "value": "(?i)logs:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "in",
        "value": [
         "aws_iam_policy",
         "aws_iam_role_policy",
         "aws_iam_role",
         "data.aws_iam_policy_document"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)logs:"
     }
    }
   ],
   "quote": "logging"
  },
  {
   "id": "policy_params",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ssm:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ssm:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "inline_policy"
      ],
      "op": "regex",
      "value": "(?i)ssm:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "in",
        "value": [
         "aws_iam_policy",
         "aws_iam_role_policy",
         "aws_iam_role",
         "data.aws_iam_policy_document"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)ssm:"
     }
    }
   ],
   "quote": "parameter access"
  },
  {
   "id": "policy_sd",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)servicediscovery:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)servicediscovery:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "inline_policy"
      ],
      "op": "regex",
      "value": "(?i)servicediscovery:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "in",
        "value": [
         "aws_iam_policy",
         "aws_iam_role_policy",
         "aws_iam_role",
         "data.aws_iam_policy_document"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)servicediscovery:"
     }
    }
   ],
   "quote": "service discovery"
  },
  {
   "id": "task_sg_port80",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "ingress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [],
        "op": "port_covers",
        "value": 80
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "present"
       },
       {
        "path": [
         "protocol"
        ],
        "op": "neq",
        "value": "-1"
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "none_eq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_security_group_rule"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "ingress"
       },
       {
        "path": [],
        "op": "port_covers",
        "value": 80
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "present"
       },
       {
        "path": [
         "protocol"
        ],
        "op": "neq",
        "value": "-1"
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "none_eq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [],
        "op": "port_covers",
        "value": 80
       },
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "present"
       },
       {
        "path": [
         "ip_protocol"
        ],
        "op": "neq",
        "value": "-1"
       },
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "neq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    }
   ],
   "quote": "a task security group allowing port 80 ingress from the VPC",
   "justify": "port 80 stated; from the VPC rules out an all-traffic rule (protocol -1) and the any-IP CIDR"
  },
  {
   "id": "service_uses_sg",
   "tier": "detail",
   "kind": "ref",
   "from": "svc",
   "to": {
    "types": [
     "aws_security_group"
    ],
    "where": []
   },
   "quote": "secure it with a task security group"
  },
  {
   "id": "sd_service",
   "tier": "core",
   "kind": "exists",
   "select": "sd",
   "quote": "register it to the Cloud Map namespace"
  },
  {
   "id": "sd_multivalue",
   "tier": "core",
   "kind": "attr",
   "select": "sd",
   "cond": {
    "path": [
     "dns_config",
     "*",
     "routing_policy"
    ],
    "op": "eq",
    "value": "MULTIVALUE"
   },
   "quote": "multivalue A and SRV records"
  },
  {
   "id": "sd_record_a",
   "tier": "core",
   "kind": "attr",
   "select": "sd",
   "cond": {
    "path": [
     "dns_config",
     "*",
     "dns_records",
     "*",
     "type"
    ],
    "op": "eq",
    "value": "A"
   },
   "quote": "multivalue A and SRV records"
  },
  {
   "id": "sd_record_srv",
   "tier": "core",
   "kind": "attr",
   "select": "sd",
   "cond": {
    "path": [
     "dns_config",
     "*",
     "dns_records",
     "*",
     "type"
    ],
    "op": "eq",
    "value": "SRV"
   },
   "quote": "multivalue A and SRV records"
  },
  {
   "id": "sd_ttl",
   "tier": "core",
   "kind": "attr",
   "select": "sd",
   "cond": {
    "path": [
     "dns_config",
     "*",
     "dns_records",
     "*",
     "ttl"
    ],
    "op": "eq",
    "value": 10,
    "every": true
   },
   "quote": "a 10-second TTL"
  },
  {
   "id": "sd_failure_threshold",
   "tier": "core",
   "kind": "attr",
   "select": "sd",
   "cond": {
    "path": [
     "health_check_custom_config",
     "*",
     "failure_threshold"
    ],
    "op": "eq",
    "value": 1
   },
   "quote": "a custom health check failure threshold of 1"
  },
  {
   "id": "sd_in_namespace",
   "tier": "detail",
   "kind": "ref",
   "from": "sd",
   "to": "ns",
   "quote": "register it to the Cloud Map namespace"
  },
  {
   "id": "service_registered_sd",
   "tier": "detail",
   "kind": "ref",
   "from": "svc",
   "to": "sd",
   "quote": "register it to the Cloud Map namespace"
  },
  {
   "id": "ec2_t3micro",
   "tier": "core",
   "kind": "attr",
   "select": "inst",
   "cond": {
    "path": [
     "instance_type"
    ],
    "op": "eq",
    "value": "t3.micro"
   },
   "quote": "launch a t3.micro Amazon Linux 2 EC2 instance"
  },
  {
   "id": "ec2_amazon_linux2",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_ami"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)amzn2"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_ssm_parameter"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)amzn2"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "in",
        "value": [
         "aws_instance",
         "aws_launch_template"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "ami"
      ],
      "op": "regex",
      "value": "(?i)amzn2"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "regex",
      "value": "(?i)amzn2"
     }
    }
   ],
   "quote": "Amazon Linux 2 EC2 instance",
   "justify": "Amazon Linux 2 AMI name is amzn2-ami-*"
  },
  {
   "id": "ec2_custom_nic",
   "tier": "core",
   "kind": "exists",
   "select": "nic",
   "quote": "using a custom network interface"
  },
  {
   "id": "ec2_uses_nic",
   "tier": "detail",
   "kind": "ref",
   "from": "inst",
   "to": "nic",
   "quote": "using a custom network interface"
  },
  {
   "id": "nic_static_ip",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "nic",
     "cond": {
      "path": [
       "private_ips",
       "*"
      ],
      "op": "present"
     }
    },
    {
     "kind": "attr",
     "select": "nic",
     "cond": {
      "path": [
       "private_ip_list",
       "*"
      ],
      "op": "present"
     }
    },
    {
     "kind": "attr",
     "select": "nic",
     "cond": {
      "path": [
       "private_ip"
      ],
      "op": "present"
     }
    }
   ],
   "quote": "with a static private IP"
  },
  {
   "id": "nic_in_subnet",
   "tier": "detail",
   "kind": "ref",
   "from": "nic",
   "to": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "quote": "in the first public subnet"
  },
  {
   "id": "ec2_instance_profile",
   "tier": "core",
   "kind": "exists",
   "select": "profile",
   "quote": "attach an IAM instance profile"
  },
  {
   "id": "ec2_uses_profile",
   "tier": "detail",
   "kind": "ref",
   "from": "inst",
   "to": "profile",
   "quote": "attach an IAM instance profile"
  },
  {
   "id": "ec2_ssm_policy",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy_attachment",
       "aws_iam_role_policy_attachment"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy_arn"
      ],
      "op": "contains",
      "value": "AmazonSSMManagedInstanceCore"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "managed_policy_arns",
       "*"
      ],
      "op": "contains",
      "value": "AmazonSSMManagedInstanceCore"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "in",
        "value": [
         "aws_iam_role_policy_attachment",
         "aws_iam_policy_attachment",
         "aws_iam_role"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "contains",
      "value": "AmazonSSMManagedInstanceCore"
     }
    }
   ],
   "quote": "the AmazonSSMManagedInstanceCore managed policy"
  },
  {
   "id": "jump_sg_all_inbound",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "ingress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "protocol"
        ],
        "op": "eq",
        "value": "-1"
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "present"
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "none_eq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_security_group_rule"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "ingress"
       },
       {
        "path": [
         "protocol"
        ],
        "op": "eq",
        "value": "-1"
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "present"
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "none_eq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [
         "ip_protocol"
        ],
        "op": "eq",
        "value": "-1"
       },
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "present"
       },
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "neq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    }
   ],
   "quote": "a security group allowing all inbound traffic from the VPC",
   "justify": "all inbound traffic = protocol -1; from the VPC rules out the any-IP CIDR"
  },
  {
   "id": "curl_output",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "__output__"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "value"
    ],
    "op": "regex",
    "value": "(?i)curl"
   },
   "quote": "a Terraform output containing the exact curl command"
  },
  {
   "id": "x_ec2_root_encrypted",
   "kind": "attr",
   "select": "inst",
   "cond": {
    "path": [
     "root_block_device",
     "*",
     "encrypted"
    ],
    "op": "eq",
    "value": true
   },
   "tier": "extra"
  },
  {
   "id": "x_ec2_imdsv2",
   "kind": "attr",
   "select": "inst",
   "cond": {
    "path": [
     "metadata_options",
     "*",
     "http_tokens"
    ],
    "op": "eq",
    "value": "required"
   },
   "tier": "extra"
  },
  {
   "id": "x_service_no_public_ip",
   "kind": "attr",
   "select": "svc",
   "cond": {
    "path": [
     "network_configuration",
     "*",
     "assign_public_ip"
    ],
    "op": "falsy"
   },
   "tier": "extra"
  },
  {
   "id": "x_endpoint_private_dns",
   "kind": "attr",
   "select": "ifc_eps",
   "cond": {
    "path": [
     "private_dns_enabled"
    ],
    "op": "eq",
    "value": true
   },
   "quantifier": "all",
   "tier": "extra"
  },
  {
   "id": "extra_type_aws_default_network_acl",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_default_network_acl"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_default_route_table",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_default_route_table"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_default_security_group",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_default_security_group"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_eip",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_eip"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_internet_gateway",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_internet_gateway"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_route",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_route"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_route_table",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_route_table"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_route_table_association",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_route_table_association"
    ],
    "where": []
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
