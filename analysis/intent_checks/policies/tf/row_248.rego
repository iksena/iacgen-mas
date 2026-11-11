package intent.tf.row_248

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
  "igw": {
   "types": [
    "aws_internet_gateway"
   ],
   "where": []
  },
  "subnet": {
   "types": [
    "aws_subnet"
   ],
   "where": [
    {
     "path": [
      "cidr_block"
     ],
     "op": "regex",
     "value": "/24$"
    }
   ]
  },
  "rt": {
   "types": [
    "aws_route_table"
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
  },
  "role": {
   "types": [
    "aws_iam_role"
   ],
   "where": []
  },
  "out": {
   "types": [
    "__output__"
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
   "quote": "a foundational VPC with a /16 CIDR block"
  },
  {
   "id": "region_us_east_1",
   "tier": "detail",
   "kind": "any_of",
   "quote": "a complete benchmark environment in us-east-1",
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
      "value": "us-east-1"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_subnet"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "availability_zone"
      ],
      "op": "regex",
      "value": "^us-east-1[a-z]$"
     }
    }
   ]
  },
  {
   "id": "igw",
   "tier": "core",
   "kind": "exists",
   "select": "igw",
   "quote": "an internet gateway"
  },
  {
   "id": "igw_in_vpc",
   "tier": "detail",
   "kind": "ref",
   "from": "igw",
   "to": "vpc",
   "quote": "a foundational VPC with a /16 CIDR block and an internet gateway"
  },
  {
   "id": "subnet_cidr24",
   "tier": "core",
   "kind": "exists",
   "select": "subnet",
   "quote": "a public subnet with a /24 CIDR"
  },
  {
   "id": "subnet_no_auto_public_ip",
   "tier": "core",
   "kind": "any_of",
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
   ],
   "quote": "a subnet that does not auto-assign public IPs on launch"
  },
  {
   "id": "default_route_igw",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_route_table"
      ],
      "where": [
       {
        "path": [
         "route",
         "*",
         "cidr_block"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       }
      ]
     },
     "to": "igw"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_route"
      ],
      "where": [
       {
        "path": [
         "destination_cidr_block"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       }
      ]
     },
     "to": "igw"
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
        "value": "aws_route_table"
       },
       {
        "path": [
         "properties",
         "route"
        ],
        "op": "contains",
        "value": "0.0.0.0/0"
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
        "value": "aws_internet_gateway"
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
        "value": "aws_route"
       },
       {
        "path": [
         "properties",
         "destination_cidr_block"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
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
        "value": "aws_internet_gateway"
       }
      ]
     }
    }
   ],
   "quote": "routes all default outbound traffic to the internet gateway",
   "justify": "default route = 0.0.0.0/0"
  },
  {
   "id": "route_to_igw",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "rt",
     "to": "igw"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_route"
      ],
      "where": []
     },
     "to": "igw"
    }
   ],
   "quote": "routes all default outbound traffic to the internet gateway"
  },
  {
   "id": "route_table_assoc",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_route_table_association"
      ],
      "where": []
     },
     "to": "subnet"
    }
   ],
   "quote": "housing a public subnet with a /24 CIDR that routes all default outbound traffic"
  },
  {
   "id": "custom_routes",
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
        "op": "in",
        "value": [
         "aws_route_table",
         "aws_route"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)(dynamic|for_each)"
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
        "value": "aws_route"
       },
       {
        "path": [
         "gated"
        ],
        "op": "truthy"
       }
      ]
     }
    }
   ],
   "quote": "allowing for the injection of custom route definitions"
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
   "quote": "a t3.micro Amazon Linux 2 EC2 instance"
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
      "value": "(?i)ssm:.*amzn2|ami-amazon-linux-latest/amzn2"
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
   "id": "ec2_dedicated_nic",
   "tier": "core",
   "kind": "exists",
   "select": "nic",
   "quote": "attached via a dedicated network interface"
  },
  {
   "id": "ec2_uses_nic",
   "tier": "detail",
   "kind": "ref",
   "from": "inst",
   "to": "nic",
   "quote": "attached via a dedicated network interface"
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
   "quote": "in a subnet that does not auto-assign public IPs on launch"
  },
  {
   "id": "optional_eip",
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
      "value": "aws_eip"
     }
    ]
   },
   "quote": "optionally allocate and associate a static Elastic IP"
  },
  {
   "id": "imdsv2",
   "tier": "core",
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
   "quote": "strictly enforce IMDSv2",
   "justify": "IMDSv2 enforced = http_tokens required"
  },
  {
   "id": "root_volume_20gb",
   "tier": "core",
   "kind": "attr",
   "select": "inst",
   "cond": {
    "path": [
     "root_block_device",
     "*",
     "volume_size"
    ],
    "op": "eq",
    "value": 20
   },
   "quote": "a 20 GB encrypted root volume"
  },
  {
   "id": "root_volume_encrypted",
   "tier": "core",
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
   "quote": "a 20 GB encrypted root volume"
  },
  {
   "id": "optional_key_pair",
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
      "value": "aws_key_pair"
     }
    ]
   },
   "quote": "conditionally generate and attach an SSH key pair"
  },
  {
   "id": "instance_profile",
   "tier": "core",
   "kind": "exists",
   "select": "profile",
   "quote": "an IAM instance profile and role"
  },
  {
   "id": "iam_role",
   "tier": "core",
   "kind": "exists",
   "select": "role",
   "quote": "an IAM instance profile and role"
  },
  {
   "id": "profile_uses_role",
   "tier": "detail",
   "kind": "ref",
   "from": "profile",
   "to": "role",
   "quote": "an IAM instance profile and role"
  },
  {
   "id": "instance_uses_profile",
   "tier": "detail",
   "kind": "ref",
   "from": "inst",
   "to": "profile",
   "quote": "attach an IAM instance profile"
  },
  {
   "id": "trust_ec2",
   "tier": "core",
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
        "op": "in",
        "value": [
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
      "op": "contains",
      "value": "ec2.amazonaws.com"
     }
    }
   ],
   "quote": "trusts both the EC2 and SSM services"
  },
  {
   "id": "trust_ssm",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
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
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "ssm.amazonaws.com"
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
      "op": "contains",
      "value": "ssm.amazonaws.com"
     }
    }
   ],
   "quote": "trusts both the EC2 and SSM services"
  },
  {
   "id": "session_manager_policy",
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
         "aws_iam_role_policy"
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
    }
   ],
   "quote": "a dedicated IAM policy that explicitly grants SSM Session Manager permissions",
   "justify": "Session Manager control/data channel permissions are ssmmessages: actions"
  },
  {
   "id": "sm_control_channel",
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
      "value": "(?i)ssmmessages:(\\*|[A-Za-z]*ControlChannel)"
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
      "value": "(?i)ssmmessages:(\\*|[A-Za-z]*ControlChannel)"
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
      "value": "(?i)ssmmessages:(\\*|[A-Za-z]*ControlChannel)"
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
      "value": "(?i)ssmmessages:(\\*|[A-Za-z]*ControlChannel)"
     }
    }
   ],
   "quote": "permissions for control and data channels"
  },
  {
   "id": "sm_data_channel",
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
      "value": "(?i)ssmmessages:(\\*|[A-Za-z]*DataChannel)"
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
      "value": "(?i)ssmmessages:(\\*|[A-Za-z]*DataChannel)"
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
      "value": "(?i)ssmmessages:(\\*|[A-Za-z]*DataChannel)"
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
      "value": "(?i)ssmmessages:(\\*|[A-Za-z]*DataChannel)"
     }
    }
   ],
   "quote": "permissions for control and data channels"
  },
  {
   "id": "toggle_ssm_managed_policy",
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
        "op": "in",
        "value": [
         "aws_iam_role_policy_attachment",
         "aws_iam_policy_attachment"
        ]
       },
       {
        "path": [
         "gated"
        ],
        "op": "truthy"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy_arn"
      ],
      "op": "contains",
      "value": "AmazonSSMManagedInstanceCore"
     }
    }
   ],
   "quote": "a toggleable option to attach the standard AmazonSSMManagedInstanceCore managed policy"
  },
  {
   "id": "output_instance",
   "tier": "detail",
   "kind": "ref",
   "from": "out",
   "to": {
    "types": [
     "aws_instance"
    ],
    "where": []
   },
   "quote": "the template must output the resulting ARNs and IDs of the EC2 instance, IAM role, instance profile, route table, and subnet"
  },
  {
   "id": "output_role",
   "tier": "detail",
   "kind": "ref",
   "from": "out",
   "to": {
    "types": [
     "aws_iam_role"
    ],
    "where": []
   },
   "quote": "the template must output the resulting ARNs and IDs of the EC2 instance, IAM role, instance profile, route table, and subnet"
  },
  {
   "id": "output_profile",
   "tier": "detail",
   "kind": "ref",
   "from": "out",
   "to": {
    "types": [
     "aws_iam_instance_profile"
    ],
    "where": []
   },
   "quote": "the template must output the resulting ARNs and IDs of the EC2 instance, IAM role, instance profile, route table, and subnet"
  },
  {
   "id": "output_route_table",
   "tier": "detail",
   "kind": "ref",
   "from": "out",
   "to": {
    "types": [
     "aws_route_table"
    ],
    "where": []
   },
   "quote": "the template must output the resulting ARNs and IDs of the EC2 instance, IAM role, instance profile, route table, and subnet"
  },
  {
   "id": "output_subnet",
   "tier": "detail",
   "kind": "ref",
   "from": "out",
   "to": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "quote": "the template must output the resulting ARNs and IDs of the EC2 instance, IAM role, instance profile, route table, and subnet"
  },
  {
   "id": "x_vpc_dns_support",
   "kind": "attr",
   "select": "vpc",
   "cond": {
    "path": [
     "enable_dns_support"
    ],
    "op": "eq",
    "value": true
   },
   "tier": "extra"
  },
  {
   "id": "x_nic_device_index",
   "kind": "attr",
   "select": "inst",
   "cond": {
    "path": [
     "network_interface",
     "*",
     "device_index"
    ],
    "op": "eq",
    "value": 0
   },
   "tier": "extra"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
