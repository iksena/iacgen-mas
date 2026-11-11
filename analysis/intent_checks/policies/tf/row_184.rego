package intent.tf.row_184

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "vpc": {
   "types": [
    "aws_vpc"
   ],
   "where": []
  },
  "subnet": {
   "types": [
    "aws_subnet"
   ],
   "where": []
  },
  "igw": {
   "types": [
    "aws_internet_gateway"
   ],
   "where": []
  },
  "asg": {
   "types": [
    "aws_autoscaling_group"
   ],
   "where": []
  },
  "lt": {
   "types": [
    "aws_launch_template"
   ],
   "where": []
  },
  "bucket": {
   "types": [
    "aws_s3_bucket"
   ],
   "where": []
  },
  "kms": {
   "types": [
    "aws_kms_key"
   ],
   "where": []
  },
  "sse": {
   "types": [
    "aws_s3_bucket_server_side_encryption_configuration"
   ],
   "where": []
  },
  "pab": {
   "types": [
    "aws_s3_bucket_public_access_block"
   ],
   "where": []
  },
  "fisrole": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "assume_role_policy"
     ],
     "op": "contains",
     "value": "fis.amazonaws.com"
    }
   ]
  },
  "ec2role": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "assume_role_policy"
     ],
     "op": "contains",
     "value": "ec2.amazonaws.com"
    }
   ]
  },
  "profile": {
   "types": [
    "aws_iam_instance_profile"
   ],
   "where": []
  },
  "fistpl": {
   "types": [
    "aws_fis_experiment_template"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "vpc",
   "kind": "exists",
   "tier": "core",
   "quote": "a minimal VPC",
   "select": "vpc"
  },
  {
   "id": "subnet",
   "kind": "exists",
   "tier": "core",
   "quote": "a single public subnet",
   "select": "subnet"
  },
  {
   "id": "subnet_single",
   "kind": "exists",
   "tier": "detail",
   "quote": "a single public subnet",
   "justify": "single means one subnet",
   "select": "subnet",
   "max": 1
  },
  {
   "id": "igw",
   "kind": "exists",
   "tier": "core",
   "quote": "internet gateway",
   "select": "igw"
  },
  {
   "id": "igw_vpc",
   "kind": "ref",
   "tier": "detail",
   "quote": "the VPC, subnet, internet gateway, and routing",
   "from": "igw",
   "to": "vpc"
  },
  {
   "id": "routing_via_igw",
   "kind": "any_of",
   "tier": "core",
   "quote": "routing",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_route"
      ],
      "where": []
     },
     "to": "igw"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_route_table"
      ],
      "where": []
     },
     "to": "igw"
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
        "value": "aws_route_table"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "aws_internet_gateway"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "subnet_no_auto_ip",
   "kind": "any_of",
   "tier": "core",
   "quote": "the subnet itself does not auto-assign one",
   "checks": [
    {
     "kind": "attr",
     "select": "subnet",
     "cond": {
      "path": [
       "map_public_ip_on_launch"
      ],
      "op": "falsy"
     }
    },
    {
     "kind": "attr",
     "select": "subnet",
     "cond": {
      "path": [
       "map_public_ip_on_launch"
      ],
      "op": "absent"
     }
    }
   ]
  },
  {
   "id": "asg",
   "kind": "exists",
   "tier": "core",
   "quote": "an Auto Scaling Group of EC2 instances",
   "select": "asg"
  },
  {
   "id": "asg_uses_lt",
   "kind": "any_of",
   "tier": "core",
   "quote": "from a launch template",
   "checks": [
    {
     "kind": "ref",
     "from": "asg",
     "to": "lt"
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
        "value": "aws_autoscaling_group"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "aws_launch_template"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "lt",
   "kind": "exists",
   "tier": "core",
   "quote": "launch template",
   "select": "lt"
  },
  {
   "id": "lt_ecs_ami",
   "tier": "core",
   "quote": "running the latest Amazon ECS-optimized AMI",
   "justify": "the ECS-optimized AMI comes from the /aws/service/ecs SSM parameter or an amzn*-ami-ecs-* image lookup",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "lt",
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
        "value": "data.aws_ssm_parameter"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)/ecs/"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "lt",
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
        "value": "data.aws_ami"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ecs"
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
        "value": "aws_launch_template"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "image_id"
      ],
      "op": "regex",
      "value": "(?i)/ecs/"
     }
    },
    {
     "kind": "attr",
     "select": "lt",
     "cond": {
      "path": [
       "image_id"
      ],
      "op": "regex",
      "value": "(?i)/ecs/"
     }
    }
   ]
  },
  {
   "id": "lt_imdsv2",
   "kind": "attr",
   "tier": "core",
   "quote": "requires IMDSv2",
   "justify": "IMDSv2 means http_tokens required",
   "select": "lt",
   "cond": {
    "path": [
     "metadata_options",
     "*",
     "http_tokens"
    ],
    "op": "eq",
    "value": "required"
   }
  },
  {
   "id": "lt_public_ip",
   "kind": "attr",
   "tier": "core",
   "quote": "gives each instance a public IP",
   "select": "lt",
   "cond": {
    "path": [
     "network_interfaces",
     "*",
     "associate_public_ip_address"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "ssh_admin_cidr",
   "tier": "core",
   "quote": "SSH access restricted to an admin CIDR block",
   "justify": "restricted to an admin CIDR means every SSH ingress rule has a CIDR other than 0.0.0.0/0",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "quantifier": "all",
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
        "value": 22
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "match",
      "value": [
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
     "kind": "attr",
     "quantifier": "all",
     "select": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [],
        "op": "port_covers",
        "value": 22
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "match",
      "value": [
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
        "op": "none_eq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "quantifier": "all",
     "select": {
      "types": [
       "aws_security_group"
      ],
      "where": [
       {
        "path": [
         "ingress",
         "*"
        ],
        "op": "port_covers",
        "value": 22
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "ingress",
         "*",
         "cidr_blocks",
         "*"
        ],
        "op": "present"
       },
       {
        "path": [
         "ingress",
         "*",
         "cidr_blocks",
         "*"
        ],
        "op": "none_eq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "key_pair",
   "kind": "exists",
   "tier": "core",
   "quote": "an accepted SSH public key",
   "select": {
    "types": [
     "aws_key_pair"
    ],
    "where": []
   }
  },
  {
   "id": "fis_api_fault",
   "kind": "attr",
   "tier": "core",
   "quote": "an API-level internal-error fault against EC2's DescribeImages API",
   "select": {
    "types": [
     "aws_fis_experiment_template"
    ],
    "where": [
     {
      "path": [
       "action",
       "*",
       "action_id"
      ],
      "op": "eq",
      "value": "aws:fis:inject-api-internal-error"
     }
    ]
   },
   "cond": {
    "path": [
     "action",
     "*",
     "action_id"
    ],
    "op": "eq",
    "value": "aws:fis:inject-api-internal-error"
   }
  },
  {
   "id": "fis_api_describeimages",
   "kind": "attr",
   "tier": "core",
   "quote": "against EC2's DescribeImages API",
   "select": {
    "types": [
     "aws_fis_experiment_template"
    ],
    "where": [
     {
      "path": [
       "action",
       "*",
       "action_id"
      ],
      "op": "eq",
      "value": "aws:fis:inject-api-internal-error"
     }
    ]
   },
   "cond": {
    "path": [
     "action",
     "*",
     "parameter",
     "*",
     "value"
    ],
    "op": "regex",
    "value": "DescribeImages"
   }
  },
  {
   "id": "fis_api_service_ec2",
   "kind": "attr",
   "tier": "detail",
   "quote": "EC2's DescribeImages API",
   "select": {
    "types": [
     "aws_fis_experiment_template"
    ],
    "where": [
     {
      "path": [
       "action",
       "*",
       "action_id"
      ],
      "op": "eq",
      "value": "aws:fis:inject-api-internal-error"
     }
    ]
   },
   "cond": {
    "path": [
     "action",
     "*",
     "parameter",
     "*",
     "value"
    ],
    "op": "eq",
    "value": "ec2"
   }
  },
  {
   "id": "fis_ebs",
   "kind": "exists",
   "tier": "core",
   "quote": "an EBS volume I/O pause",
   "select": {
    "types": [
     "aws_fis_experiment_template"
    ],
    "where": [
     {
      "path": [
       "action",
       "*",
       "action_id"
      ],
      "op": "eq",
      "value": "aws:ebs:pause-volume-io"
     }
    ]
   }
  },
  {
   "id": "fis_cpu",
   "kind": "any_of",
   "tier": "core",
   "quote": "EC2 CPU stress",
   "justify": "FIS runs CPU stress through the AWSFIS-Run-CPU-Stress SSM document",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_fis_experiment_template"
      ],
      "where": [
       {
        "path": [
         "action",
         "*",
         "action_id"
        ],
        "op": "eq",
        "value": "aws:ssm:send-command"
       },
       {
        "path": [
         "action",
         "*",
         "parameter",
         "*",
         "value"
        ],
        "op": "regex",
        "value": "(?i)cpu-?stress"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_fis_experiment_template"
      ],
      "where": [
       {
        "path": [
         "action",
         "*",
         "action_id"
        ],
        "op": "regex",
        "value": "(?i)cpu"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "fis_terminate",
   "kind": "exists",
   "tier": "core",
   "quote": "EC2 instance termination",
   "select": {
    "types": [
     "aws_fis_experiment_template"
    ],
    "where": [
     {
      "path": [
       "action",
       "*",
       "action_id"
      ],
      "op": "eq",
      "value": "aws:ec2:terminate-instances"
     }
    ]
   }
  },
  {
   "id": "fis_network",
   "kind": "exists",
   "tier": "core",
   "quote": "network connectivity disruption on the subnet",
   "select": {
    "types": [
     "aws_fis_experiment_template"
    ],
    "where": [
     {
      "path": [
       "action",
       "*",
       "action_id"
      ],
      "op": "eq",
      "value": "aws:network:disrupt-connectivity"
     }
    ]
   }
  },
  {
   "id": "fis_network_subnets",
   "kind": "exists",
   "tier": "detail",
   "quote": "network connectivity disruption on the subnet",
   "select": {
    "types": [
     "aws_fis_experiment_template"
    ],
    "where": [
     {
      "path": [
       "action",
       "*",
       "action_id"
      ],
      "op": "eq",
      "value": "aws:network:disrupt-connectivity"
     },
     {
      "path": [
       "target",
       "*",
       "resource_type"
      ],
      "op": "eq",
      "value": "aws:ec2:subnet"
     }
    ]
   }
  },
  {
   "id": "fis_by_tag",
   "kind": "exists",
   "tier": "core",
   "quote": "all targeting resources by tag",
   "justify": "four of the five experiments target EC2 resources, which the ground truth tags; the API fault targets a role by ARN",
   "select": {
    "types": [
     "aws_fis_experiment_template"
    ],
    "where": [
     {
      "path": [
       "target",
       "*",
       "resource_tag",
       "*",
       "key"
      ],
      "op": "present"
     }
    ]
   },
   "min": 4
  },
  {
   "id": "fis_no_autostop",
   "kind": "attr",
   "tier": "core",
   "quote": "none configured to auto-stop",
   "select": "fistpl",
   "cond": {
    "path": [
     "stop_condition",
     "*",
     "source"
    ],
    "op": "eq",
    "value": "none"
   },
   "quantifier": "all"
  },
  {
   "id": "bucket",
   "kind": "exists",
   "tier": "core",
   "quote": "an S3 bucket for FIS experiment logs",
   "select": "bucket"
  },
  {
   "id": "fis_logs_to_bucket",
   "kind": "any_of",
   "tier": "detail",
   "quote": "an S3 bucket for FIS experiment logs",
   "justify": "the log configuration names the bucket",
   "checks": [
    {
     "kind": "ref",
     "from": "fistpl",
     "to": "bucket"
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
        "value": "aws_fis_experiment_template"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "bucket_name"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "pab_all",
   "kind": "all_of",
   "tier": "core",
   "quote": "all public access blocked",
   "checks": [
    {
     "kind": "attr",
     "select": "pab",
     "cond": {
      "path": [
       "block_public_acls"
      ],
      "op": "truthy"
     }
    },
    {
     "kind": "attr",
     "select": "pab",
     "cond": {
      "path": [
       "block_public_policy"
      ],
      "op": "truthy"
     }
    },
    {
     "kind": "attr",
     "select": "pab",
     "cond": {
      "path": [
       "ignore_public_acls"
      ],
      "op": "truthy"
     }
    },
    {
     "kind": "attr",
     "select": "pab",
     "cond": {
      "path": [
       "restrict_public_buckets"
      ],
      "op": "truthy"
     }
    }
   ]
  },
  {
   "id": "sse_kms",
   "kind": "attr",
   "tier": "core",
   "quote": "SSE-KMS encryption",
   "select": "sse",
   "cond": {
    "path": [
     "rule",
     "*",
     "apply_server_side_encryption_by_default",
     "*",
     "sse_algorithm"
    ],
    "op": "eq",
    "value": "aws:kms"
   }
  },
  {
   "id": "kms_cmk",
   "kind": "exists",
   "tier": "core",
   "quote": "a customer-managed key",
   "select": "kms"
  },
  {
   "id": "sse_uses_cmk",
   "kind": "ref",
   "tier": "core",
   "quote": "SSE-KMS encryption using a customer-managed key",
   "from": "sse",
   "to": "kms"
  },
  {
   "id": "kms_allows_log_delivery",
   "tier": "core",
   "quote": "a customer-managed key that AWS log delivery may use",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "kms",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "contains",
      "value": "delivery.logs.amazonaws.com"
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
        "value": "aws_kms_key"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "delivery\\.logs\\.amazonaws\\.com"
       }
      ]
     }
    },
    {
     "kind": "ref",
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
        "value": "aws_kms_key"
       }
      ]
     },
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "delivery\\.logs\\.amazonaws\\.com"
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
        "value": "aws_kms_key_policy"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "delivery\\.logs\\.amazonaws\\.com"
       }
      ]
     }
    },
    {
     "kind": "ref",
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
        "value": "aws_kms_key_policy"
       }
      ]
     },
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "delivery\\.logs\\.amazonaws\\.com"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "bucket_policy",
   "kind": "exists",
   "tier": "core",
   "quote": "a bucket policy allowing AWS log delivery",
   "select": {
    "types": [
     "aws_s3_bucket_policy"
    ],
    "where": []
   }
  },
  {
   "id": "bucket_policy_log_delivery",
   "tier": "core",
   "quote": "a bucket policy allowing AWS log delivery",
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
        "value": "aws_s3_bucket_policy"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "delivery\\.logs\\.amazonaws\\.com"
       }
      ]
     }
    },
    {
     "kind": "ref",
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
        "value": "aws_s3_bucket_policy"
       }
      ]
     },
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "delivery\\.logs\\.amazonaws\\.com"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "fis_role",
   "tier": "core",
   "quote": "the IAM role that FIS assumes to run these experiments",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": "fisrole"
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
        "value": "fis\\.amazonaws\\.com"
       }
      ]
     }
    },
    {
     "kind": "ref",
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
        "value": "aws_iam_role"
       }
      ]
     },
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "fis\\.amazonaws\\.com"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "fis_templates_use_role",
   "kind": "ref",
   "tier": "detail",
   "quote": "the IAM role that FIS assumes to run these experiments",
   "from": "fistpl",
   "to": "fisrole"
  },
  {
   "id": "fis_role_perms",
   "kind": "any_of",
   "tier": "core",
   "quote": "with the necessary fault-injection permissions",
   "justify": "FIS experiment actions are fis:, ec2: and ssm: calls, or the AWSFaultInjectionSimulator managed policies",
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
        "op": "in",
        "value": [
         "aws_iam_role_policy",
         "aws_iam_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)(fis:|ec2:(Terminate|PauseVolume|SendSpot|StopInstances)|ssm:SendCommand)"
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
        "value": "AWSFaultInjectionSimulator"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "ec2_role",
   "tier": "core",
   "quote": "the EC2 instance role and profile",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": "ec2role"
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
     "kind": "ref",
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
        "value": "aws_iam_role"
       }
      ]
     },
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "ec2\\.amazonaws\\.com"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "instance_profile",
   "tier": "core",
   "quote": "the EC2 instance role and profile",
   "kind": "ref",
   "from": "profile",
   "to": "ec2role"
  },
  {
   "id": "instance_ecs_policy",
   "tier": "core",
   "quote": "to run under ECS",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "AmazonEC2ContainerServiceforEC2Role"
       }
      ]
     },
     "to": "ec2role"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "AmazonEC2ContainerServiceforEC2Role"
       }
      ]
     },
     "to": "ec2role"
    },
    {
     "kind": "attr",
     "select": "ec2role",
     "cond": {
      "path": [
       "managed_policy_arns",
       "*"
      ],
      "op": "regex",
      "value": "AmazonEC2ContainerServiceforEC2Role"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)ecs:(RegisterContainerInstance|Poll|DiscoverPollEndpoint|\\*)"
       }
      ]
     },
     "to": "ec2role"
    }
   ],
   "justify": "running under ECS needs the ECS container-instance permissions: the AWS managed policy or the agent's ecs: actions"
  },
  {
   "id": "instance_ssm_policy",
   "tier": "core",
   "quote": "and SSM",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
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
     },
     "to": "ec2role"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy_attachment"
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
     },
     "to": "ec2role"
    },
    {
     "kind": "attr",
     "select": "ec2role",
     "cond": {
      "path": [
       "managed_policy_arns",
       "*"
      ],
      "op": "regex",
      "value": "AmazonSSMManagedInstanceCore"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)(ssm:(UpdateInstanceInformation|\\*)|ssmmessages:)"
       }
      ]
     },
     "to": "ec2role"
    }
   ],
   "justify": "running under SSM needs the managed-instance permissions: the AWS managed policy or ssm:UpdateInstanceInformation / ssmmessages actions"
  },
  {
   "id": "x_kms_rotation",
   "kind": "attr",
   "tier": "extra",
   "select": "kms",
   "cond": {
    "path": [
     "enable_key_rotation"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "x_asg_subnet",
   "kind": "ref",
   "tier": "extra",
   "from": "asg",
   "to": "subnet"
  },
  {
   "id": "x_lt_sg",
   "kind": "ref",
   "tier": "extra",
   "from": "lt",
   "to": {
    "types": [
     "aws_security_group"
    ],
    "where": []
   }
  },
  {
   "id": "lt_uses_profile",
   "kind": "ref",
   "tier": "detail",
   "quote": "the EC2 instance role and profile needed for the instances themselves",
   "from": "lt",
   "to": "profile"
  },
  {
   "id": "x_pab_bucket",
   "kind": "ref",
   "tier": "extra",
   "from": "pab",
   "to": "bucket"
  },
  {
   "id": "x_sg_ssh_tcp",
   "kind": "attr",
   "tier": "extra",
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
     }
    ]
   },
   "cond": {
    "path": [
     "protocol"
    ],
    "op": "eq",
    "value": "tcp"
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
