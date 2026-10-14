# GENERATED from specs/tf/row_186.json by intent_checks/build.py -- do not edit.
package intent.tf.row_186

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "server": {
   "types": [
    "aws_transfer_server"
   ],
   "where": []
  },
  "dserver": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "aws_transfer_server"
    }
   ]
  },
  "transfer_role": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "assume_role_policy"
     ],
     "op": "contains",
     "value": "transfer.amazonaws.com"
    }
   ]
  },
  "duser": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "aws_transfer_user"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "transfer_server",
   "kind": "exists",
   "tier": "core",
   "quote": "a versatile AWS Transfer Family SFTP server solution",
   "select": "server"
  },
  {
   "id": "default_public_endpoint",
   "kind": "attr",
   "tier": "core",
   "quote": "defaulting to \"PUBLIC\"",
   "select": "server",
   "cond": {
    "path": [
     "endpoint_type"
    ],
    "op": "eq",
    "value": "PUBLIC"
   }
  },
  {
   "id": "default_s3_storage",
   "kind": "attr",
   "tier": "core",
   "quote": "with \"S3\" storage",
   "select": "server",
   "cond": {
    "path": [
     "domain"
    ],
    "op": "eq",
    "value": "S3"
   }
  },
  {
   "id": "default_sftp_protocol",
   "kind": "attr",
   "tier": "core",
   "quote": "\"SFTP\" protocols",
   "select": "server",
   "cond": {
    "path": [
     "protocols",
     "*"
    ],
    "op": "eq",
    "value": "SFTP"
   }
  },
  {
   "id": "default_security_policy",
   "kind": "attr",
   "tier": "detail",
   "quote": "custom security policies (defaulting to \"TransferSecurityPolicy-2023-05\")",
   "select": "server",
   "cond": {
    "path": [
     "security_policy_name"
    ],
    "op": "eq",
    "value": "TransferSecurityPolicy-2023-05"
   }
  },
  {
   "id": "endpoint_type_options",
   "kind": "exists",
   "tier": "detail",
   "quote": "The server endpoint type must support \"PUBLIC\", \"VPC\", or \"VPC_ENDPOINT\" modes",
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
      "value": "aws_transfer_server"
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "endpoint_details"
     }
    ]
   },
   "justify": "VPC / VPC_ENDPOINT modes need an endpoint_details block on the server"
  },
  {
   "id": "pet_name_fallback",
   "kind": "exists",
   "tier": "detail",
   "quote": "fallback to a two-word hyphenated random pet name",
   "justify": "two-word hyphenated pet name -> random_pet length 2, separator '-'",
   "select": {
    "types": [
     "random_pet"
    ],
    "where": [
     {
      "path": [
       "length"
      ],
      "op": "eq",
      "value": 2
     },
     {
      "path": [
       "separator"
      ],
      "op": "eq",
      "value": "-"
     }
    ]
   }
  },
  {
   "id": "logging_role_managed_policy",
   "kind": "any_of",
   "tier": "core",
   "quote": "a dynamically provisioned IAM role attached to \"AWSTransferLoggingAccess\"",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment",
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "contains",
        "value": "AWSTransferLoggingAccess"
       }
      ]
     },
     "to": "transfer_role"
    },
    {
     "kind": "attr",
     "select": "transfer_role",
     "cond": {
      "path": [
       "managed_policy_arns",
       "*"
      ],
      "op": "contains",
      "value": "AWSTransferLoggingAccess"
     }
    }
   ]
  },
  {
   "id": "server_uses_logging_role",
   "kind": "ref",
   "tier": "detail",
   "quote": "defaulting logging to a dynamically provisioned IAM role",
   "from": "server",
   "to": "transfer_role"
  },
  {
   "id": "apigw_auth_role",
   "kind": "any_of",
   "tier": "detail",
   "quote": "provision an API Gateway authorization IAM role",
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
         "gate"
        ],
        "op": "regex",
        "value": "(?i)api.?gateway"
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
         "properties"
        ],
        "op": "regex",
        "value": "(?i)api.?gateway"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "apigw_auth_role_logs",
   "kind": "exists",
   "tier": "detail",
   "quote": "with CloudWatch logging permissions",
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
       "aws_iam_role_policy",
       "aws_iam_policy",
       "data.aws_iam_policy_document",
       "aws_iam_role",
       "aws_iam_role_policy_attachment",
       "aws_iam_policy_attachment"
      ]
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "logs:(PutLogEvents|CreateLogStream|\\*)|AmazonAPIGatewayPushToCloudWatchLogs"
     }
    ]
   },
   "justify": "CloudWatch logging permissions -> logs:CreateLogStream/PutLogEvents or the AWS-managed AmazonAPIGatewayPushToCloudWatchLogs policy"
  },
  {
   "id": "cert_and_host_key",
   "kind": "all_of",
   "tier": "detail",
   "quote": "optional FTPS ACM certificates",
   "checks": [
    {
     "kind": "attr",
     "select": "dserver",
     "cond": {
      "path": [
       "properties",
       "certificate"
      ],
      "op": "present"
     }
    },
    {
     "kind": "attr",
     "select": "dserver",
     "cond": {
      "path": [
       "properties",
       "host_key"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "login_banners",
   "kind": "attr",
   "tier": "detail",
   "quote": "custom login banners",
   "select": "dserver",
   "cond": {
    "path": [
     "properties"
    ],
    "op": "regex",
    "value": "authentication_login_banner"
   }
  },
  {
   "id": "structured_log_destinations",
   "kind": "attr",
   "tier": "detail",
   "quote": "structured CloudWatch log destinations",
   "select": "dserver",
   "cond": {
    "path": [
     "properties"
    ],
    "op": "regex",
    "value": "structured_log_destinations"
   }
  },
  {
   "id": "protocol_details",
   "kind": "exists",
   "tier": "detail",
   "quote": "protocol details for AS2, passive IP, set-stat options, or TLS session resumption",
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
      "value": "aws_transfer_server"
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "as2_transports"
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "passive_ip"
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "set_stat_option"
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "tls_session_resumption_mode"
     }
    ]
   }
  },
  {
   "id": "vpc_sg_port22_anywhere",
   "kind": "any_of",
   "tier": "core",
   "quote": "a dedicated security group opening port 22 to 0.0.0.0/0",
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
        "value": "aws_security_group"
       },
       {
        "path": [
         "properties",
         "ingress",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [],
          "op": "port_covers",
          "value": 22
         },
         {
          "path": [
           "cidr_blocks",
           "*"
          ],
          "op": "eq",
          "value": "0.0.0.0/0"
         }
        ]
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
        "op": "in",
        "value": [
         "aws_security_group_rule",
         "aws_vpc_security_group_ingress_rule"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "port_covers",
        "value": 22
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "0\\.0\\.0\\.0/0"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "eip_per_subnet",
   "kind": "exists",
   "tier": "core",
   "quote": "an Elastic IP per specified subnet",
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
      "value": "aws_eip"
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     }
    ]
   },
   "justify": "'per specified subnet' -> a count/for_each-driven aws_eip (the count source is free: subnets, AZs, locals)"
  },
  {
   "id": "route53_cname",
   "kind": "ref",
   "tier": "core",
   "quote": "create a CNAME record mapping a sub-domain",
   "from": {
    "types": [
     "__declared__"
    ],
    "where": [
     {
      "path": [
       "type"
      ],
      "op": "eq",
      "value": "aws_route53_record"
     },
     {
      "path": [
       "properties",
       "type"
      ],
      "op": "eq",
      "value": "CNAME"
     }
    ]
   },
   "to": "dserver"
  },
  {
   "id": "subdomain_default_sftp",
   "kind": "any_of",
   "tier": "detail",
   "quote": "(defaulting to \"sftp\")",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": [
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": "sftp"
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
        "value": "aws_route53_record"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "regex",
        "value": "^sftp\\."
       }
      ]
     }
    }
   ]
  },
  {
   "id": "transfer_user_per_map_entry",
   "kind": "ref",
   "tier": "core",
   "quote": "an AWS Transfer user",
   "from": "duser",
   "to": "dserver"
  },
  {
   "id": "user_role",
   "kind": "ref",
   "tier": "detail",
   "quote": "provision an IAM role and policy",
   "from": "duser",
   "to": {
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
     }
    ]
   }
  },
  {
   "id": "user_policy_s3_access",
   "kind": "exists",
   "tier": "core",
   "quote": "granting list and object access to their specified S3 home directory bucket path",
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
       "aws_iam_role_policy",
       "aws_iam_policy",
       "data.aws_iam_policy_document",
       "aws_iam_role"
      ]
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "s3:(ListBucket|List\\*|\\*)"
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "s3:(GetObject|PutObject|Get\\*|Put\\*|\\*)"
     }
    ]
   },
   "justify": "list and object access -> s3:ListBucket plus s3:GetObject/PutObject"
  },
  {
   "id": "user_home_directory",
   "kind": "attr",
   "tier": "detail",
   "quote": "their specified S3 home directory bucket path",
   "select": "duser",
   "cond": {
    "path": [
     "properties"
    ],
    "op": "regex",
    "value": "home_directory"
   }
  },
  {
   "id": "ssh_keys",
   "kind": "exists",
   "tier": "detail",
   "quote": "associate any matching SSH public keys provided in a secondary user key map",
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
      "value": "aws_transfer_ssh_key"
     }
    ]
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
