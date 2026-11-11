package intent.tf.row_238

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "vpc",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_vpc"
    ],
    "where": []
   },
   "quote": "deploy a VPC"
  },
  {
   "id": "vpc_cidr",
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
     "cidr_block"
    ],
    "op": "eq",
    "value": "10.0.0.0/16"
   },
   "quote": "primary CIDR defaulting to \"10.0.0.0/16\""
  },
  {
   "id": "vpc_tenancy",
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
     "instance_tenancy"
    ],
    "op": "eq",
    "value": "default"
   },
   "quote": "instance tenancy defaulting to \"default\""
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
    "op": "truthy"
   },
   "quote": "DNS hostnames enabled by default"
  },
  {
   "id": "vpc_name_default",
   "tier": "core",
   "kind": "any_of",
   "checks": [
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
      "op": "eq",
      "value": "benchmark-vpc"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_vpc"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "benchmark-vpc"
     }
    }
   ],
   "quote": "configurable name defaulting to \"benchmark-vpc\""
  },
  {
   "id": "flow_log_all",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_flow_log"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "traffic_type"
    ],
    "op": "eq",
    "value": "ALL"
   },
   "quote": "Enable VPC Flow Logs for ALL traffic"
  },
  {
   "id": "log_group_name",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_cloudwatch_log_group"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "/aws/vpc-flow-logs/benchmark-vpc"
   },
   "quote": "a dedicated CloudWatch Log Group named \"/aws/vpc-flow-logs/{vpc_name}\"",
   "justify": "vpc_name default is benchmark-vpc"
  },
  {
   "id": "log_group_retention",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_cloudwatch_log_group"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "retention_in_days"
    ],
    "op": "eq",
    "value": 180
   },
   "quote": "a 180-day retention period"
  },
  {
   "id": "flow_log_to_group",
   "tier": "detail",
   "kind": "ref",
   "from": {
    "types": [
     "aws_flow_log"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_cloudwatch_log_group"
    ],
    "where": []
   },
   "quote": "storing logs in a dedicated CloudWatch Log Group"
  },
  {
   "id": "flow_role_name",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_iam_role"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "vpc_flow_logs_benchmark-vpc"
   },
   "quote": "IAM role named \"vpc_flow_logs_{vpc_name}\"",
   "justify": "vpc_name default is benchmark-vpc"
  },
  {
   "id": "flow_policy_stream",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*",
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "logs:CreateLogStream"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)logs:CreateLogStream|(?i)logs:\\*"
       }
      ]
     }
    },
    {
     "kind": "exists",
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties",
         "statement"
        ],
        "op": "regex",
        "value": "(?i)logs:CreateLogStream|logs:\\*"
       }
      ]
     }
    },
    {
     "kind": "exists",
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
        "value": "aws_iam_role_policy"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "(?i)logs:CreateLogStream|logs:\\*"
       }
      ]
     }
    }
   ],
   "quote": "policy granting log stream creation"
  },
  {
   "id": "flow_policy_events",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*",
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "logs:PutLogEvents"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)logs:PutLogEvents|(?i)logs:\\*"
       }
      ]
     }
    },
    {
     "kind": "exists",
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties",
         "statement"
        ],
        "op": "regex",
        "value": "(?i)logs:PutLogEvents|logs:\\*"
       }
      ]
     }
    },
    {
     "kind": "exists",
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
        "value": "aws_iam_role_policy"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "(?i)logs:PutLogEvents|logs:\\*"
       }
      ]
     }
    }
   ],
   "quote": "event delivery"
  },
  {
   "id": "default_sg",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_default_security_group"
    ],
    "where": []
   },
   "quote": "Manage the default VPC security group"
  },
  {
   "id": "two_custom_sgs",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_security_group"
    ],
    "where": []
   },
   "min": 2,
   "quote": "two custom security groups"
  },
  {
   "id": "endpoints_sg_name",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_security_group"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "vpc-endpoints-benchmark-vpc"
   },
   "quote": "named \"vpc-endpoints-{vpc_name}\"",
   "justify": "vpc_name default is benchmark-vpc"
  },
  {
   "id": "endpoints_https_ingress",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
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
        "value": "aws_security_group_rule"
       },
       {
        "path": [
         "properties",
         "type"
        ],
        "op": "eq",
        "value": "ingress"
       },
       {
        "path": [
         "properties",
         "from_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "properties",
         "source_security_group_id"
        ],
        "op": "present"
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
         "source_security_group_id"
        ],
        "op": "present"
       },
       {
        "path": [
         "protocol"
        ],
        "op": "none_eq",
        "value": "-1"
       }
      ]
     }
    },
    {
     "kind": "exists",
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
        "value": "aws_vpc_security_group_ingress_rule"
       },
       {
        "path": [
         "properties",
         "from_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "properties",
         "referenced_security_group_id"
        ],
        "op": "present"
       }
      ]
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
        "value": "aws_security_group"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "ingress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "security_groups",
         "*"
        ],
        "op": "present"
       }
      ]
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
        "value": "aws_security_group"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "dynamic",
       "ingress",
       "content",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "security_groups",
         "*"
        ],
        "op": "present"
       }
      ]
     }
    }
   ],
   "quote": "allowing HTTPS port 443 ingress from",
   "justify": "HTTPS implies port 443"
  },
  {
   "id": "endpoints_https_egress",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
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
        "value": "aws_security_group_rule"
       },
       {
        "path": [
         "properties",
         "type"
        ],
        "op": "eq",
        "value": "egress"
       },
       {
        "path": [
         "properties",
         "from_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "properties",
         "source_security_group_id"
        ],
        "op": "present"
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
        "value": "egress"
       },
       {
        "path": [],
        "op": "port_covers",
        "value": 443
       },
       {
        "path": [
         "source_security_group_id"
        ],
        "op": "present"
       },
       {
        "path": [
         "protocol"
        ],
        "op": "none_eq",
        "value": "-1"
       }
      ]
     }
    },
    {
     "kind": "exists",
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
        "value": "aws_vpc_security_group_egress_rule"
       },
       {
        "path": [
         "properties",
         "from_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "properties",
         "referenced_security_group_id"
        ],
        "op": "present"
       }
      ]
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
        "value": "aws_security_group"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "egress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "security_groups",
         "*"
        ],
        "op": "present"
       }
      ]
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
        "value": "aws_security_group"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "dynamic",
       "egress",
       "content",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "security_groups",
         "*"
        ],
        "op": "present"
       }
      ]
     }
    }
   ],
   "quote": "egress to specified source security group IDs",
   "justify": "HTTPS implies port 443"
  },
  {
   "id": "custom_ingress",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
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
        "value": "aws_security_group_rule"
       },
       {
        "path": [
         "properties",
         "type"
        ],
        "op": "eq",
        "value": "ingress"
       },
       {
        "path": [
         "properties",
         "from_port"
        ],
        "op": "none_eq",
        "value": 443
       },
       {
        "path": [
         "properties",
         "source_security_group_id"
        ],
        "op": "present"
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
         "from_port"
        ],
        "op": "none_eq",
        "value": 443
       },
       {
        "path": [
         "source_security_group_id"
        ],
        "op": "present"
       }
      ]
     }
    },
    {
     "kind": "exists",
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
        "value": "aws_vpc_security_group_ingress_rule"
       },
       {
        "path": [
         "properties",
         "from_port"
        ],
        "op": "none_eq",
        "value": 443
       },
       {
        "path": [
         "properties",
         "referenced_security_group_id"
        ],
        "op": "present"
       }
      ]
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
        "value": "aws_security_group"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "ingress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "from_port"
        ],
        "op": "none_eq",
        "value": 443
       },
       {
        "path": [
         "security_groups",
         "*"
        ],
        "op": "present"
       }
      ]
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
        "value": "aws_security_group"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "dynamic",
       "ingress",
       "content",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "from_port"
        ],
        "op": "none_eq",
        "value": 443
       },
       {
        "path": [
         "security_groups",
         "*"
        ],
        "op": "present"
       }
      ]
     }
    }
   ],
   "quote": "ingress and egress rules mapped specifically to each custom service port and source security group ID combination",
   "justify": "custom service rules are the per-service-port ones, distinct from the HTTPS (443) endpoint rules"
  },
  {
   "id": "custom_egress",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
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
        "value": "aws_security_group_rule"
       },
       {
        "path": [
         "properties",
         "type"
        ],
        "op": "eq",
        "value": "egress"
       },
       {
        "path": [
         "properties",
         "from_port"
        ],
        "op": "none_eq",
        "value": 443
       },
       {
        "path": [
         "properties",
         "source_security_group_id"
        ],
        "op": "present"
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
        "value": "egress"
       },
       {
        "path": [
         "from_port"
        ],
        "op": "none_eq",
        "value": 443
       },
       {
        "path": [
         "source_security_group_id"
        ],
        "op": "present"
       }
      ]
     }
    },
    {
     "kind": "exists",
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
        "value": "aws_vpc_security_group_egress_rule"
       },
       {
        "path": [
         "properties",
         "from_port"
        ],
        "op": "none_eq",
        "value": 443
       },
       {
        "path": [
         "properties",
         "referenced_security_group_id"
        ],
        "op": "present"
       }
      ]
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
        "value": "aws_security_group"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "egress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "from_port"
        ],
        "op": "none_eq",
        "value": 443
       },
       {
        "path": [
         "security_groups",
         "*"
        ],
        "op": "present"
       }
      ]
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
        "value": "aws_security_group"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "dynamic",
       "egress",
       "content",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "from_port"
        ],
        "op": "none_eq",
        "value": 443
       },
       {
        "path": [
         "security_groups",
         "*"
        ],
        "op": "present"
       }
      ]
     }
    }
   ],
   "quote": "ingress and egress rules mapped specifically to each custom service port and source security group ID combination",
   "justify": "custom service rules are the per-service-port ones, distinct from the HTTPS (443) endpoint rules"
  },
  {
   "id": "gateway_endpoints",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
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
         "vpc_endpoint_type"
        ],
        "op": "eq",
        "value": "Gateway"
       }
      ]
     }
    },
    {
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
        "value": "Gateway"
       }
      ]
     }
    }
   ],
   "quote": "Gateway endpoints for \"dynamodb\" and \"s3\""
  },
  {
   "id": "interface_endpoints_logs",
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
       "private_dns_enabled"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "service_name"
      ],
      "op": "regex",
      "value": "(?i)logs$"
     }
    ]
   },
   "quote": "private DNS-enabled Interface endpoints for standard AWS services specified in a set defaulting to [\"logs\"]"
  },
  {
   "id": "custom_interface_endpoints",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
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
         "vpc_endpoint_type"
        ],
        "op": "eq",
        "value": "Interface"
       },
       {
        "path": [
         "properties",
         "private_dns_enabled"
        ],
        "op": "eq",
        "value": false
       }
      ]
     }
    },
    {
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
         "private_dns_enabled"
        ],
        "op": "eq",
        "value": false
       }
      ]
     }
    }
   ],
   "quote": "non-private DNS Interface endpoints for custom endpoint services"
  },
  {
   "id": "ssm_role",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
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
        "value": "aws_iam_role"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "regex",
        "value": "^(ssm_|\\$\\{local\\.ssm)"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "^(ssm_|\\$\\{local\\.ssm)"
       }
      ]
     }
    }
   ],
   "quote": "automatically provision an IAM role and instance profile both named \"ssm_{vpc_name}\"",
   "justify": "ssm_{vpc_name} begins with ssm_; a local named for the ssm role is accepted because locals are invisible"
  },
  {
   "id": "ssm_profile",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
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
        "value": "aws_iam_instance_profile"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "regex",
        "value": "^(ssm_|\\$\\{local\\.ssm)"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_instance_profile"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "^(ssm_|\\$\\{local\\.ssm)"
       }
      ]
     }
    }
   ],
   "quote": "instance profile both named \"ssm_{vpc_name}\"",
   "justify": "ssm_{vpc_name} begins with ssm_; a local named for the ssm role is accepted because locals are invisible"
  },
  {
   "id": "ssm_ec2_trust",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties",
         "statement"
        ],
        "op": "regex",
        "value": "ec2\\.amazonaws\\.com"
       }
      ]
     }
    },
    {
     "kind": "exists",
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
        "value": "aws_iam_role"
       },
       {
        "path": [
         "properties",
         "assume_role_policy"
        ],
        "op": "regex",
        "value": "ec2\\.amazonaws\\.com"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "assume_role_policy"
        ],
        "op": "regex",
        "value": "ec2\\.amazonaws\\.com"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*",
         "principals",
         "*",
         "identifiers",
         "*"
        ],
        "op": "eq",
        "value": "ec2.amazonaws.com"
       }
      ]
     }
    }
   ],
   "quote": "with EC2 trust"
  },
  {
   "id": "ssm_managed_policy",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
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
        "value": "aws_iam_role_policy_attachment"
       },
       {
        "path": [
         "properties",
         "policy_arn"
        ],
        "op": "regex",
        "value": "AmazonSSMManagedInstanceCore"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "AmazonSSMManagedInstanceCore"
       }
      ]
     }
    }
   ],
   "quote": "the \"AmazonSSMManagedInstanceCore\" managed policy attached"
  },
  {
   "id": "ssm_conditional",
   "tier": "detail",
   "kind": "exists",
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
      "value": "aws_iam_role"
     },
     {
      "path": [
       "properties",
       "name"
      ],
      "op": "regex",
      "value": "^(ssm_|\\$\\{local\\.ssm)"
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     }
    ]
   },
   "quote": "if the \"ssm\" service is included in the requested AWS endpoint services set",
   "justify": "ssm_{vpc_name} begins with ssm_; a local named for the ssm role is accepted because locals are invisible"
  },
  {
   "id": "x_vpc_dns_support",
   "tier": "extra",
   "kind": "attr",
   "select": {
    "types": [
     "aws_vpc"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "enable_dns_support"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "x_flow_trust",
   "tier": "extra",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "assume_role_policy"
        ],
        "op": "regex",
        "value": "vpc-flow-logs\\.amazonaws\\.com"
       }
      ]
     }
    },
    {
     "kind": "exists",
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties",
         "statement"
        ],
        "op": "regex",
        "value": "vpc-flow-logs\\.amazonaws\\.com"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "x_flow_policy_describe",
   "tier": "extra",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*",
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "logs:DescribeLogGroups"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)logs:DescribeLogGroups|(?i)logs:\\*"
       }
      ]
     }
    },
    {
     "kind": "exists",
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties",
         "statement"
        ],
        "op": "regex",
        "value": "(?i)logs:DescribeLogGroups|logs:\\*"
       }
      ]
     }
    },
    {
     "kind": "exists",
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
        "value": "aws_iam_role_policy"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "(?i)logs:DescribeLogGroups|logs:\\*"
       }
      ]
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
