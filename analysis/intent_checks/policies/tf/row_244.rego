package intent.tf.row_244

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "vpc",
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
    "value": "10.8.0.0/16"
   },
   "quote": "deploy a VPC with CIDR 10.8.0.0/16"
  },
  {
   "id": "dns_support",
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
     "enable_dns_support"
    ],
    "op": "eq",
    "value": true
   },
   "quote": "enabling DNS support and DNS hostnames"
  },
  {
   "id": "dns_hostnames",
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
   "quote": "enabling DNS support and DNS hostnames"
  },
  {
   "id": "subnet",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_subnet"
    ],
    "where": [
     {
      "path": [
       "cidr_block"
      ],
      "op": "eq",
      "value": "10.8.1.0/24"
     }
    ]
   },
   "min": 1,
   "max": 1,
   "quote": "a single private subnet with CIDR 10.8.1.0/24"
  },
  {
   "id": "subnet_only_one",
   "tier": "detail",
   "kind": "exists",
   "select": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "min": 1,
   "max": 1,
   "quote": "a single private subnet",
   "justify": "a single subnet"
  },
  {
   "id": "subnet_private",
   "tier": "detail",
   "kind": "attr",
   "select": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "map_public_ip_on_launch"
    ],
    "op": "none_eq",
    "value": true
   },
   "quantifier": "all",
   "quote": "a single private subnet"
  },
  {
   "id": "subnet_vpc",
   "tier": "detail",
   "kind": "ref",
   "from": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_vpc"
    ],
    "where": []
   },
   "quote": "a single private subnet"
  },
  {
   "id": "subnet_first_az",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
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
        "value": "aws_subnet"
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
        "value": "data.aws_availability_zones"
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
        "value": "aws_subnet"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "availability_zone"
      ],
      "op": "regex",
      "value": "(?i)(\\[0\\]|element\\(|slice\\(|first|names)"
     }
    }
   ],
   "quote": "in the first available availability zone"
  },
  {
   "id": "endpoints_interface",
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
     }
    ]
   },
   "min": 4,
   "quote": "private DNS-enabled interface VPC endpoints",
   "justify": "four services are listed"
  },
  {
   "id": "endpoint_ssm",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_vpc_endpoint"
    ],
    "where": [
     {
      "path": [
       "service_name"
      ],
      "op": "regex",
      "value": "\\.ssm$"
     }
    ]
   },
   "quote": "for ssm"
  },
  {
   "id": "endpoint_ec2messages",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_vpc_endpoint"
    ],
    "where": [
     {
      "path": [
       "service_name"
      ],
      "op": "regex",
      "value": "\\.ec2messages$"
     }
    ]
   },
   "quote": "ec2messages"
  },
  {
   "id": "endpoint_ssmmessages",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_vpc_endpoint"
    ],
    "where": [
     {
      "path": [
       "service_name"
      ],
      "op": "regex",
      "value": "\\.ssmmessages$"
     }
    ]
   },
   "quote": "ssmmessages"
  },
  {
   "id": "endpoint_logs",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_vpc_endpoint"
    ],
    "where": [
     {
      "path": [
       "service_name"
      ],
      "op": "regex",
      "value": "\\.logs$"
     }
    ]
   },
   "quote": "CloudWatch logs"
  },
  {
   "id": "endpoint_private_dns",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_vpc_endpoint"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "private_dns_enabled"
    ],
    "op": "eq",
    "value": true
   },
   "quantifier": "all",
   "quote": "private DNS-enabled interface VPC endpoints"
  },
  {
   "id": "endpoint_auto_accept",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_vpc_endpoint"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "auto_accept"
      ],
      "op": "eq",
      "value": true
     },
     "quantifier": "all"
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_vpc_endpoint"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "auto_accept"
      ],
      "op": "absent"
     },
     "quantifier": "all"
    }
   ],
   "quote": "each auto-accepted",
   "justify": "endpoints to AWS services are accepted automatically when auto_accept is left unset"
  },
  {
   "id": "endpoint_subnet",
   "tier": "detail",
   "kind": "ref",
   "from": {
    "types": [
     "aws_vpc_endpoint"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "quote": "The private subnet must host private DNS-enabled interface VPC endpoints"
  },
  {
   "id": "endpoint_sg_used",
   "tier": "detail",
   "kind": "ref",
   "from": {
    "types": [
     "aws_vpc_endpoint"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_security_group"
    ],
    "where": []
   },
   "quote": "secured by a common service endpoint security group"
  },
  {
   "id": "endpoint_sg_ingress",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_vpc_endpoint"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_security_group"
      ],
      "where": [
       {
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
          "op": "eq",
          "value": "10.8.0.0/16"
         },
         {
          "path": [
           "protocol"
          ],
          "op": "in",
          "value": [
           "tcp",
           "6"
          ]
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
        "op": "eq",
        "value": "10.8.0.0/16"
       },
       {
        "path": [
         "protocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         "6"
        ]
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
        "op": "eq",
        "value": "10.8.0.0/16"
       },
       {
        "path": [
         "ip_protocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         "6"
        ]
       }
      ]
     }
    }
   ],
   "quote": "allows inbound port 443 TCP traffic from the VPC CIDR"
  },
  {
   "id": "endpoint_sg_no_egress",
   "tier": "core",
   "kind": "ref",
   "from": {
    "types": [
     "aws_vpc_endpoint"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_security_group"
    ],
    "where": [
     {
      "path": [
       "egress",
       "*",
       "cidr_blocks",
       "*"
      ],
      "op": "absent"
     },
     {
      "path": [
       "egress",
       "*",
       "ipv6_cidr_blocks",
       "*"
      ],
      "op": "absent"
     },
     {
      "path": [
       "egress",
       "*",
       "security_groups",
       "*"
      ],
      "op": "absent"
     },
     {
      "path": [
       "egress",
       "*",
       "prefix_list_ids",
       "*"
      ],
      "op": "absent"
     },
     {
      "path": [
       "egress",
       "*",
       "self"
      ],
      "op": "none_eq",
      "value": true
     }
    ]
   },
   "quote": "with no egress rules"
  },
  {
   "id": "instance",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_instance"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "instance_type"
    ],
    "op": "eq",
    "value": "t3.small"
   },
   "quote": "a test EC2 instance of type t3.small"
  },
  {
   "id": "instance_subnet",
   "tier": "detail",
   "kind": "ref",
   "from": {
    "types": [
     "aws_instance"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "quote": "running in the private subnet"
  },
  {
   "id": "ami_al2",
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
       "data.aws_ami"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)amzn2"
     }
    }
   ],
   "quote": "the latest Amazon Linux 2 x86_64 EBS-backed AMI",
   "justify": "Amazon Linux 2 images are named amzn2-*"
  },
  {
   "id": "ami_latest",
   "tier": "detail",
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
       "properties",
       "most_recent"
      ],
      "op": "eq",
      "value": true
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
      "value": "(?i)latest"
     }
    }
   ],
   "quote": "the latest Amazon Linux 2"
  },
  {
   "id": "ami_x86",
   "tier": "detail",
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
      "value": "(?i)x86_64"
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
      "value": "(?i)x86_64"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "data.aws_ami"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)x86_64"
     }
    }
   ],
   "quote": "x86_64"
  },
  {
   "id": "ami_ebs",
   "tier": "detail",
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
      "value": "(?i)ebs|gp2|gp3"
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
      "value": "(?i)ebs|gp2|gp3"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "data.aws_ami"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ebs|gp2|gp3"
     }
    }
   ],
   "quote": "EBS-backed"
  },
  {
   "id": "instance_ami_ref",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
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
        "value": "aws_instance"
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
        "value": "data.aws_ami"
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
        "value": "aws_instance"
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
        "value": "data.aws_ssm_parameter"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_instance"
      ],
      "where": []
     },
     "to": {
      "types": [
       "data.aws_ami"
      ],
      "where": []
     }
    }
   ],
   "quote": "the latest Amazon Linux 2 x86_64 EBS-backed AMI"
  },
  {
   "id": "imdsv2",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_instance"
      ],
      "where": []
     },
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
        "value": "aws_instance"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "metadata_options"
      ],
      "op": "contains",
      "value": "required"
     }
    }
   ],
   "quote": "with IMDSv2 required"
  },
  {
   "id": "root_encrypted",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_instance"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "root_block_device",
       "*",
       "encrypted"
      ],
      "op": "eq",
      "value": true
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
        "value": "aws_instance"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "root_block_device"
      ],
      "op": "regex",
      "value": "(?i)encrypted[^a-z]{1,6}true"
     }
    }
   ],
   "quote": "an encrypted root volume"
  },
  {
   "id": "src_dst_check",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_instance"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "source_dest_check"
      ],
      "op": "eq",
      "value": false
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
        "value": "aws_instance"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "source_dest_check"
      ],
      "op": "eq",
      "value": false
     }
    }
   ],
   "quote": "source/destination checks disabled"
  },
  {
   "id": "instance_sg_egress",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_instance"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_security_group"
      ],
      "where": [
       {
        "path": [
         "egress",
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
          "op": "eq",
          "value": "10.8.0.0/16"
         },
         {
          "path": [
           "protocol"
          ],
          "op": "in",
          "value": [
           "tcp",
           "6"
          ]
         }
        ]
       },
       {
        "path": [
         "egress",
         "*",
         "cidr_blocks",
         "*"
        ],
        "op": "eq",
        "value": "10.8.0.0/16",
        "every": true
       },
       {
        "path": [
         "egress",
         "*",
         "ipv6_cidr_blocks",
         "*"
        ],
        "op": "absent"
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
         "cidr_blocks",
         "*"
        ],
        "op": "eq",
        "value": "10.8.0.0/16"
       },
       {
        "path": [
         "protocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         "6"
        ]
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_vpc_security_group_egress_rule"
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
        "op": "eq",
        "value": "10.8.0.0/16"
       },
       {
        "path": [
         "ip_protocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         "6"
        ]
       }
      ]
     }
    }
   ],
   "quote": "an instance security group that allows egress port 443 TCP traffic restricted to the VPC CIDR"
  },
  {
   "id": "instance_sg_no_ingress",
   "tier": "core",
   "kind": "ref",
   "from": {
    "types": [
     "aws_instance"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_security_group"
    ],
    "where": [
     {
      "path": [
       "ingress",
       "*",
       "cidr_blocks",
       "*"
      ],
      "op": "absent"
     },
     {
      "path": [
       "ingress",
       "*",
       "ipv6_cidr_blocks",
       "*"
      ],
      "op": "absent"
     },
     {
      "path": [
       "ingress",
       "*",
       "security_groups",
       "*"
      ],
      "op": "absent"
     },
     {
      "path": [
       "ingress",
       "*",
       "prefix_list_ids",
       "*"
      ],
      "op": "absent"
     },
     {
      "path": [
       "ingress",
       "*",
       "self"
      ],
      "op": "none_eq",
      "value": true
     }
    ]
   },
   "quote": "with no ingress rules"
  },
  {
   "id": "instance_sg_used",
   "tier": "detail",
   "kind": "ref",
   "from": {
    "types": [
     "aws_instance"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_security_group"
    ],
    "where": []
   },
   "quote": "attached to an instance security group"
  },
  {
   "id": "profile",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_iam_instance_profile"
    ],
    "where": []
   },
   "quote": "an IAM instance profile and role"
  },
  {
   "id": "role",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_iam_role"
    ],
    "where": []
   },
   "quote": "an IAM instance profile and role"
  },
  {
   "id": "role_ec2_trust",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
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
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "ec2.amazonaws.com"
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
        "value": "aws_iam_role"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "ec2.amazonaws.com"
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
        "value": "data.aws_iam_policy_document"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "contains",
      "value": "ec2.amazonaws.com"
     }
    }
   ],
   "quote": "an IAM instance profile and role",
   "justify": "an instance role is assumed by the EC2 service"
  },
  {
   "id": "profile_role",
   "tier": "detail",
   "kind": "ref",
   "from": {
    "types": [
     "aws_iam_instance_profile"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_iam_role"
    ],
    "where": []
   },
   "quote": "an IAM instance profile and role"
  },
  {
   "id": "instance_profile_ref",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_instance"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_iam_instance_profile"
      ],
      "where": []
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
        "value": "aws_instance"
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
        "value": "aws_iam_instance_profile"
       }
      ]
     }
    }
   ],
   "quote": "Provide an IAM instance profile"
  },
  {
   "id": "perm_ssm",
   "tier": "core",
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
         "data.aws_iam_policy_document",
         "aws_iam_role"
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
        "value": "aws_iam_role_policy_attachment"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy_arn"
      ],
      "op": "regex",
      "value": "AmazonSSMManagedInstanceCore"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy_arn"
      ],
      "op": "regex",
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
       "managed_policy_arns"
      ],
      "op": "regex",
      "value": "AmazonSSMManagedInstanceCore"
     }
    }
   ],
   "quote": "permissions for SSM"
  },
  {
   "id": "perm_ssmmessages",
   "tier": "core",
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
      "value": "(?i)ssmmessages:"
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
      "value": "(?i)ssmmessages:"
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
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)ssmmessages:"
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
        "value": "aws_iam_role_policy_attachment"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy_arn"
      ],
      "op": "regex",
      "value": "AmazonSSMManagedInstanceCore"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy_arn"
      ],
      "op": "regex",
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
       "managed_policy_arns"
      ],
      "op": "regex",
      "value": "AmazonSSMManagedInstanceCore"
     }
    }
   ],
   "quote": "SSMMessages"
  },
  {
   "id": "perm_ec2messages",
   "tier": "core",
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
      "value": "(?i)ec2messages:"
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
      "value": "(?i)ec2messages:"
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
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)ec2messages:"
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
        "value": "aws_iam_role_policy_attachment"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy_arn"
      ],
      "op": "regex",
      "value": "AmazonSSMManagedInstanceCore"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy_arn"
      ],
      "op": "regex",
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
       "managed_policy_arns"
      ],
      "op": "regex",
      "value": "AmazonSSMManagedInstanceCore"
     }
    }
   ],
   "quote": "EC2Messages"
  },
  {
   "id": "perm_logs",
   "tier": "core",
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
         "data.aws_iam_policy_document",
         "aws_iam_role"
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
        "value": "aws_iam_role_policy_attachment"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy_arn"
      ],
      "op": "regex",
      "value": "CloudWatchAgentServerPolicy|CloudWatchLogs"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy_arn"
      ],
      "op": "regex",
      "value": "CloudWatchAgentServerPolicy|CloudWatchLogs"
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
       "managed_policy_arns"
      ],
      "op": "regex",
      "value": "CloudWatchAgentServerPolicy|CloudWatchLogs"
     }
    }
   ],
   "quote": "CloudWatch Logs"
  },
  {
   "id": "perm_kms",
   "tier": "core",
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
      "value": "(?i)kms:(GenerateDataKey|Generate\\*|\\*)"
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
      "value": "(?i)kms:(GenerateDataKey|Generate\\*|\\*)"
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
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)kms:(GenerateDataKey|Generate\\*|\\*)"
     }
    }
   ],
   "quote": "KMS data key generation"
  },
  {
   "id": "perm_s3",
   "tier": "core",
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
      "value": "(?i)s3:(\\*|[a-z]*object)"
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
      "value": "(?i)s3:(\\*|[a-z]*object)"
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
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)s3:(\\*|[a-z]*object)"
     }
    }
   ],
   "quote": "S3 object actions",
   "justify": "S3 object actions are s3:*Object* (or s3:*)"
  },
  {
   "id": "shortcode_var",
   "tier": "detail",
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
    "value": "bmk"
   },
   "quote": "an application shortcode variable defaulting to \"bmk\""
  },
  {
   "id": "role_prefix",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
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
       "name_prefix"
      ],
      "op": "regex",
      "value": "^bmk"
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
       "name"
      ],
      "op": "regex",
      "value": "^bmk"
     }
    }
   ],
   "quote": "both the IAM role and instance profile names use prefixes based on an application shortcode variable"
  },
  {
   "id": "profile_prefix",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_instance_profile"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name_prefix"
      ],
      "op": "regex",
      "value": "^bmk"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_instance_profile"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "^bmk"
     }
    }
   ],
   "quote": "both the IAM role and instance profile names use prefixes based on an application shortcode variable"
  },
  {
   "id": "x_attach_policy",
   "tier": "extra",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     }
    }
   ]
  },
  {
   "id": "x_endpoint_policy",
   "tier": "extra",
   "kind": "attr",
   "select": {
    "types": [
     "aws_vpc_endpoint"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "policy"
    ],
    "op": "present"
   }
  },
  {
   "id": "x_subnet_no_public",
   "tier": "extra",
   "kind": "attr",
   "select": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "map_public_ip_on_launch"
    ],
    "op": "eq",
    "value": false
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
