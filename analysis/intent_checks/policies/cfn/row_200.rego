package intent.cfn.row_200

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "vpc": {
   "types": [
    "AWS::EC2::VPC"
   ],
   "where": []
  },
  "subnets": {
   "types": [
    "AWS::EC2::Subnet"
   ],
   "where": []
  },
  "flow": {
   "types": [
    "AWS::EC2::FlowLog"
   ],
   "where": []
  },
  "kms": {
   "types": [
    "AWS::KMS::Key"
   ],
   "where": []
  },
  "lg": {
   "types": [
    "AWS::Logs::LogGroup"
   ],
   "where": []
  },
  "sg": {
   "types": [
    "AWS::EC2::SecurityGroup"
   ],
   "where": []
  },
  "sge": {
   "types": [
    "AWS::EC2::SecurityGroupEgress"
   ],
   "where": []
  },
  "role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "ifep": {
   "types": [
    "AWS::EC2::VPCEndpoint"
   ],
   "where": [
    {
     "path": [
      "VpcEndpointType"
     ],
     "op": "eq",
     "value": "Interface"
    }
   ]
  },
  "anyep": {
   "types": [
    "AWS::EC2::VPCEndpoint"
   ],
   "where": []
  },
  "lg_cmk": {
   "types": [
    "AWS::Logs::LogGroup"
   ],
   "where": [
    {
     "path": [
      "KmsKeyId"
     ],
     "op": "regex",
     "value": "(?i)ref|\\$\\{|arn:aws[a-z-]*:kms:"
    }
   ]
  },
  "bucket_cmk": {
   "types": [
    "AWS::S3::Bucket"
   ],
   "where": [
    {
     "path": [
      "BucketEncryption"
     ],
     "op": "regex",
     "value": "aws:kms"
    },
    {
     "path": [
      "BucketEncryption"
     ],
     "op": "regex",
     "value": "KMSMasterKeyID"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "vpc",
   "kind": "exists",
   "tier": "core",
   "quote": "creates a completely isolated private VPC",
   "select": "vpc"
  },
  {
   "id": "no_internet",
   "kind": "all_of",
   "tier": "core",
   "quote": "a completely isolated private VPC for hosting an AI-powered customer support application with no direct internet access",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": []
     },
     "quantifier": "all",
     "cond": {
      "path": [
       "type"
      ],
      "op": "neq",
      "value": "AWS::EC2::InternetGateway"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": []
     },
     "quantifier": "all",
     "cond": {
      "path": [
       "type"
      ],
      "op": "neq",
      "value": "AWS::EC2::NatGateway"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": []
     },
     "quantifier": "all",
     "cond": {
      "path": [
       "type"
      ],
      "op": "neq",
      "value": "AWS::EC2::EgressOnlyInternetGateway"
     }
    }
   ],
   "justify": "no direct internet access means no internet gateway, NAT gateway or egress-only internet gateway"
  },
  {
   "id": "three_subnets",
   "kind": "exists",
   "tier": "core",
   "quote": "three private subnets",
   "justify": "three subnets",
   "select": "subnets",
   "min": 3
  },
  {
   "id": "multi_az",
   "kind": "exists",
   "tier": "core",
   "quote": "The VPC should span multiple availability zones",
   "justify": "multiple AZs means at least two",
   "select": "subnets",
   "distinct_path": [
    "AvailabilityZone"
   ],
   "min": 2
  },
  {
   "id": "ep_bedrock",
   "kind": "exists",
   "tier": "core",
   "quote": "Bedrock for AI inference",
   "justify": "service name suffix for Bedrock for AI inference",
   "select": {
    "types": [
     "AWS::EC2::VPCEndpoint"
    ],
    "where": [
     {
      "path": [
       "ServiceName"
      ],
      "op": "regex",
      "value": "(?i)\\.bedrock(-runtime)?$"
     }
    ]
   }
  },
  {
   "id": "ep_ecr",
   "kind": "exists",
   "tier": "core",
   "quote": "ECR for container image retrieval",
   "justify": "service name suffix for ECR for container image retrieval",
   "select": {
    "types": [
     "AWS::EC2::VPCEndpoint"
    ],
    "where": [
     {
      "path": [
       "ServiceName"
      ],
      "op": "regex",
      "value": "(?i)\\.ecr\\.(api|dkr)$"
     }
    ]
   }
  },
  {
   "id": "ep_logs",
   "kind": "exists",
   "tier": "core",
   "quote": "CloudWatch Logs",
   "justify": "service name suffix for CloudWatch Logs",
   "select": {
    "types": [
     "AWS::EC2::VPCEndpoint"
    ],
    "where": [
     {
      "path": [
       "ServiceName"
      ],
      "op": "regex",
      "value": "(?i)\\.logs$"
     }
    ]
   }
  },
  {
   "id": "ep_monitoring",
   "kind": "exists",
   "tier": "core",
   "quote": "Monitoring for observability",
   "justify": "service name suffix for Monitoring for observability",
   "select": {
    "types": [
     "AWS::EC2::VPCEndpoint"
    ],
    "where": [
     {
      "path": [
       "ServiceName"
      ],
      "op": "regex",
      "value": "(?i)\\.monitoring$"
     }
    ]
   }
  },
  {
   "id": "ep_dynamodb",
   "kind": "exists",
   "tier": "core",
   "quote": "DynamoDB",
   "justify": "service name suffix for DynamoDB",
   "select": {
    "types": [
     "AWS::EC2::VPCEndpoint"
    ],
    "where": [
     {
      "path": [
       "ServiceName"
      ],
      "op": "regex",
      "value": "(?i)\\.dynamodb$"
     }
    ]
   }
  },
  {
   "id": "ep_rds_data",
   "kind": "exists",
   "tier": "core",
   "quote": "RDS Data API",
   "justify": "service name suffix for RDS Data API",
   "select": {
    "types": [
     "AWS::EC2::VPCEndpoint"
    ],
    "where": [
     {
      "path": [
       "ServiceName"
      ],
      "op": "regex",
      "value": "(?i)\\.rds-data$"
     }
    ]
   }
  },
  {
   "id": "ep_secrets",
   "kind": "exists",
   "tier": "core",
   "quote": "Secrets Manager",
   "justify": "service name suffix for Secrets Manager",
   "select": {
    "types": [
     "AWS::EC2::VPCEndpoint"
    ],
    "where": [
     {
      "path": [
       "ServiceName"
      ],
      "op": "regex",
      "value": "(?i)\\.secretsmanager$"
     }
    ]
   }
  },
  {
   "id": "ep_ssm",
   "kind": "exists",
   "tier": "core",
   "quote": "SSM Parameter Store",
   "justify": "service name suffix for SSM Parameter Store",
   "select": {
    "types": [
     "AWS::EC2::VPCEndpoint"
    ],
    "where": [
     {
      "path": [
       "ServiceName"
      ],
      "op": "regex",
      "value": "(?i)\\.ssm$"
     }
    ]
   }
  },
  {
   "id": "ep_kms",
   "kind": "exists",
   "tier": "core",
   "quote": "KMS",
   "justify": "service name suffix for KMS",
   "select": {
    "types": [
     "AWS::EC2::VPCEndpoint"
    ],
    "where": [
     {
      "path": [
       "ServiceName"
      ],
      "op": "regex",
      "value": "(?i)\\.kms$"
     }
    ]
   }
  },
  {
   "id": "ep_s3",
   "kind": "exists",
   "tier": "core",
   "quote": "S3",
   "justify": "service name suffix for S3",
   "select": {
    "types": [
     "AWS::EC2::VPCEndpoint"
    ],
    "where": [
     {
      "path": [
       "ServiceName"
      ],
      "op": "regex",
      "value": "(?i)\\.s3$"
     }
    ]
   }
  },
  {
   "id": "ep_xray",
   "kind": "exists",
   "tier": "core",
   "quote": "X-Ray",
   "justify": "service name suffix for X-Ray",
   "select": {
    "types": [
     "AWS::EC2::VPCEndpoint"
    ],
    "where": [
     {
      "path": [
       "ServiceName"
      ],
      "op": "regex",
      "value": "(?i)\\.xray$"
     }
    ]
   }
  },
  {
   "id": "ep_subnets",
   "kind": "ref",
   "tier": "detail",
   "quote": "include VPC endpoints for AWS services",
   "from": "ifep",
   "to": "subnets",
   "justify": "interface-type VPC endpoints sit in subnets behind a security group"
  },
  {
   "id": "flow_all",
   "kind": "attr",
   "tier": "core",
   "quote": "Enable VPC Flow Logs for all traffic",
   "select": "flow",
   "cond": {
    "path": [
     "TrafficType"
    ],
    "op": "eq",
    "value": "ALL"
   }
  },
  {
   "id": "flow_vpc",
   "kind": "ref",
   "tier": "core",
   "quote": "Enable VPC Flow Logs for all traffic",
   "from": "flow",
   "to": "vpc"
  },
  {
   "id": "kms_rotation",
   "kind": "attr",
   "tier": "core",
   "quote": "a customer-managed KMS key with automatic rotation",
   "select": "kms",
   "cond": {
    "path": [
     "EnableKeyRotation"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "flow_encrypted",
   "kind": "any_of",
   "tier": "core",
   "quote": "Enable VPC Flow Logs for all traffic encrypted with a customer-managed KMS key",
   "checks": [
    {
     "kind": "ref",
     "from": "flow",
     "to": "lg_cmk"
    },
    {
     "kind": "join",
     "from": "flow",
     "from_path": [
      "LogGroupName"
     ],
     "to": "lg_cmk",
     "to_path": [
      "LogGroupName"
     ]
    },
    {
     "kind": "ref",
     "from": "flow",
     "to": "bucket_cmk"
    }
   ]
  },
  {
   "id": "flow_key_cmk",
   "kind": "any_of",
   "tier": "core",
   "quote": "encrypted with a customer-managed KMS key",
   "checks": [
    {
     "kind": "ref",
     "from": "lg",
     "to": "kms"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::S3::Bucket"
      ],
      "where": []
     },
     "to": "kms"
    }
   ]
  },
  {
   "id": "sg_count",
   "kind": "exists",
   "tier": "core",
   "quote": "Create a dedicated security group for each application component (Agent Runtime, MCP Runtime, and Lambda functions)",
   "justify": "three components",
   "select": "sg",
   "min": 3
  },
  {
   "id": "https_egress_only",
   "kind": "any_of",
   "tier": "core",
   "quote": "allows HTTPS-only egress to the VPC endpoints",
   "justify": "HTTPS implies TCP 443",
   "checks": [
    {
     "kind": "attr",
     "select": "sge",
     "quantifier": "all",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "IpProtocol"
        ],
        "op": "eq",
        "value": "tcp"
       },
       {
        "path": [
         "FromPort"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "ToPort"
        ],
        "op": "eq",
        "value": 443
       }
      ]
     }
    },
    {
     "kind": "attr",
     "quantifier": "all",
     "select": {
      "types": [
       "AWS::EC2::SecurityGroup"
      ],
      "where": [
       {
        "path": [
         "SecurityGroupEgress",
         "*",
         "FromPort"
        ],
        "op": "eq",
        "value": 443
       }
      ]
     },
     "cond": {
      "path": [
       "SecurityGroupEgress",
       "*",
       "IpProtocol"
      ],
      "op": "eq",
      "value": "tcp",
      "every": true
     }
    }
   ]
  },
  {
   "id": "https_egress_per_component",
   "kind": "any_of",
   "tier": "core",
   "quote": "allows HTTPS-only egress to the VPC endpoints",
   "justify": "three components each with HTTPS egress",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::EC2::SecurityGroupEgress"
      ],
      "where": [
       {
        "path": [
         "FromPort"
        ],
        "op": "eq",
        "value": 443
       }
      ]
     },
     "min": 3
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::EC2::SecurityGroup"
      ],
      "where": [
       {
        "path": [
         "SecurityGroupEgress",
         "*",
         "FromPort"
        ],
        "op": "eq",
        "value": 443
       }
      ]
     },
     "min": 3
    }
   ]
  },
  {
   "id": "endpoint_sg",
   "kind": "ref",
   "tier": "detail",
   "quote": "HTTPS-only egress to the VPC endpoints",
   "from": "ifep",
   "to": "sg",
   "justify": "interface-type VPC endpoints sit in subnets behind a security group"
  },
  {
   "id": "ddb_direct",
   "kind": "any_of",
   "tier": "detail",
   "quote": "the components that need it also permitted to reach DynamoDB directly",
   "checks": [
    {
     "kind": "attr",
     "select": "sge",
     "cond": {
      "path": [
       "DestinationPrefixListId"
      ],
      "op": "present"
     }
    },
    {
     "kind": "attr",
     "select": "sg",
     "cond": {
      "path": [
       "SecurityGroupEgress",
       "*",
       "DestinationPrefixListId"
      ],
      "op": "present"
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::EC2::VPCEndpoint"
      ],
      "where": [
       {
        "path": [
         "ServiceName"
        ],
        "op": "regex",
        "value": "(?i)\\.dynamodb$"
       },
       {
        "path": [
         "VpcEndpointType"
        ],
        "op": "eq",
        "value": "Interface"
       }
      ]
     }
    }
   ],
   "justify": "a gateway endpoint is reached through its prefix list; a DynamoDB interface endpoint is reached inside the VPC"
  },
  {
   "id": "x_dns",
   "kind": "attr",
   "tier": "extra",
   "select": "vpc",
   "cond": {
    "path": [
     "EnableDnsHostnames"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "x_pdns",
   "kind": "attr",
   "tier": "extra",
   "select": "ifep",
   "quantifier": "all",
   "cond": {
    "path": [
     "PrivateDnsEnabled"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "x_retention",
   "kind": "attr",
   "tier": "extra",
   "select": "lg",
   "cond": {
    "path": [
     "RetentionInDays"
    ],
    "op": "present"
   }
  },
  {
   "id": "x_flow_role",
   "kind": "ref",
   "tier": "extra",
   "from": "flow",
   "to": "role"
  },
  {
   "id": "x_ep_policy",
   "kind": "attr",
   "tier": "extra",
   "select": "anyep",
   "cond": {
    "path": [
     "PolicyDocument"
    ],
    "op": "present"
   }
  },
  {
   "id": "extra_type_aws_ec2_routetable",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::EC2::RouteTable"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_ec2_subnetroutetableassociation",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::EC2::SubnetRouteTableAssociation"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_kms_alias",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::KMS::Alias"
    ],
    "where": []
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
