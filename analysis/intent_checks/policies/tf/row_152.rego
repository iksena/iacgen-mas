package intent.tf.row_152

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
  "sg": {
   "types": [
    "aws_security_group"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "allow_ssh_http_https"
    }
   ]
  },
  "subnets": {
   "types": [
    "aws_subnet"
   ],
   "where": []
  },
  "inst": {
   "types": [
    "aws_instance"
   ],
   "where": []
  }
 },
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
   "quote": "provision a VPC"
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
   "quote": "a default CIDR block of \"10.0.0.0/16\""
  },
  {
   "id": "vpc_name",
   "tier": "detail",
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
    "value": "VPC_from_Terraform"
   },
   "quote": "named \"VPC_from_Terraform\""
  },
  {
   "id": "vpc_dns_support",
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
    "op": "truthy"
   },
   "quote": "DNS support and DNS hostnames enabled"
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
   "quote": "DNS support and DNS hostnames enabled"
  },
  {
   "id": "vpc_tag",
   "tier": "detail",
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
     "Terraform"
    ],
    "op": "eq",
    "value": "true"
   },
   "quote": "tagged \"Terraform\" set to \"true\""
  },
  {
   "id": "subnets_count",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "min": 3,
   "quote": "Three private subnets must be created"
  },
  {
   "id": "subnet_cidrs",
   "tier": "core",
   "kind": "all_of",
   "checks": [
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
       "cidr_block"
      ],
      "op": "eq",
      "value": "10.0.1.0/24"
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
       "cidr_block"
      ],
      "op": "eq",
      "value": "10.0.2.0/24"
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
       "cidr_block"
      ],
      "op": "eq",
      "value": "10.0.3.0/24"
     }
    }
   ],
   "quote": "using CIDR blocks [\"10.0.1.0/24\", \"10.0.2.0/24\", \"10.0.3.0/24\"]"
  },
  {
   "id": "subnet_azs",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "distinct_path": [
    "availability_zone"
   ],
   "min": 3,
   "quote": "mapped across three availability zones"
  },
  {
   "id": "subnets_in_vpc",
   "tier": "detail",
   "kind": "ref",
   "from": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "to": "vpc",
   "quote": "Three private subnets must be created"
  },
  {
   "id": "subnets_private",
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
   "quote": "Three private subnets must be created"
  },
  {
   "id": "sg",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_security_group"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "allow_ssh_http_https"
     }
    ]
   },
   "quote": "A security group named \"allow_ssh_http_https\""
  },
  {
   "id": "sg_tag",
   "tier": "detail",
   "kind": "attr",
   "select": {
    "types": [
     "aws_security_group"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "allow_ssh_http_https"
     }
    ]
   },
   "cond": {
    "path": [
     "tags"
    ],
    "op": "contains",
    "value": "Terraform_SG_HTTP_HTTPS_SSH"
   },
   "quote": "tagged \"Terraform_SG_HTTP_HTTPS_SSH\""
  },
  {
   "id": "sg_vpc",
   "tier": "core",
   "kind": "ref",
   "from": {
    "types": [
     "aws_security_group"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "allow_ssh_http_https"
     }
    ]
   },
   "to": "vpc",
   "quote": "must be attached to the VPC"
  },
  {
   "id": "sg_ssh",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_security_group"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "allow_ssh_http_https"
       }
      ]
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
        "value": 22
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "eq",
        "value": "10.0.0.0/16"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "sg",
     "from": {
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
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "eq",
        "value": "10.0.0.0/16"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "sg",
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [],
        "op": "port_covers",
        "value": 22
       },
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "eq",
        "value": "10.0.0.0/16"
       }
      ]
     }
    }
   ],
   "quote": "inbound SSH (port 22) restricted strictly to the VPC's CIDR block",
   "justify": "the VPC CIDR is stated as 10.0.0.0/16"
  },
  {
   "id": "sg_http",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_security_group"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "allow_ssh_http_https"
       }
      ]
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
         "protocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         "6"
        ]
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
    },
    {
     "kind": "ref",
     "to": "sg",
     "from": {
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
         "protocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         "6"
        ]
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
    },
    {
     "kind": "ref",
     "to": "sg",
     "from": {
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
         "ip_protocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         "6"
        ]
       },
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    }
   ],
   "quote": "inbound HTTP (port 80) and HTTPS (port 443) from everywhere (\"0.0.0.0/0\")",
   "justify": "HTTP/HTTPS on ports 80/443 are TCP; an all-protocol rule from 0.0.0.0/0 would also open SSH to everywhere"
  },
  {
   "id": "sg_https",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_security_group"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "allow_ssh_http_https"
       }
      ]
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
         "protocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         "6"
        ]
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
    },
    {
     "kind": "ref",
     "to": "sg",
     "from": {
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
         "protocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         "6"
        ]
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
    },
    {
     "kind": "ref",
     "to": "sg",
     "from": {
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
         "ip_protocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         "6"
        ]
       },
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    }
   ],
   "quote": "inbound HTTP (port 80) and HTTPS (port 443) from everywhere (\"0.0.0.0/0\")",
   "justify": "HTTP/HTTPS on ports 80/443 are TCP; an all-protocol rule from 0.0.0.0/0 would also open SSH to everywhere"
  },
  {
   "id": "sg_egress_vpc",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_security_group"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "allow_ssh_http_https"
       }
      ]
     },
     "cond": {
      "path": [
       "egress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "eq",
        "value": "10.0.0.0/16"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "sg",
     "from": {
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
         "cidr_blocks",
         "*"
        ],
        "op": "eq",
        "value": "10.0.0.0/16"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "sg",
     "from": {
      "types": [
       "aws_vpc_security_group_egress_rule"
      ],
      "where": [
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "eq",
        "value": "10.0.0.0/16"
       }
      ]
     }
    }
   ],
   "quote": "egress limited to the VPC's CIDR block"
  },
  {
   "id": "sg_egress_only_vpc",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_security_group"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "allow_ssh_http_https"
       }
      ]
     },
     "cond": {
      "path": [
       "egress",
       "*",
       "cidr_blocks",
       "*"
      ],
      "op": "eq",
      "value": "10.0.0.0/16",
      "every": true
     }
    },
    {
     "kind": "attr",
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
       }
      ]
     },
     "cond": {
      "path": [
       "cidr_blocks",
       "*"
      ],
      "op": "eq",
      "value": "10.0.0.0/16",
      "every": true
     },
     "quantifier": "all"
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_vpc_security_group_egress_rule"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "cidr_ipv4"
      ],
      "op": "eq",
      "value": "10.0.0.0/16",
      "every": true
     },
     "quantifier": "all"
    }
   ],
   "quote": "egress limited to the VPC's CIDR block"
  },
  {
   "id": "instances",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_instance"
    ],
    "where": []
   },
   "min": 3,
   "quote": "deploy a default count of 3 EC2 instances",
   "max": 3,
   "justify": "default count of 3 means exactly 3 instances under defaults"
  },
  {
   "id": "instance_type",
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
    "value": "t2.micro"
   },
   "quantifier": "all",
   "quote": "EC2 instances of type \"t2.micro\""
  },
  {
   "id": "instance_subnets",
   "tier": "core",
   "kind": "ref",
   "from": {
    "types": [
     "aws_instance"
    ],
    "where": []
   },
   "to": "subnets",
   "quote": "distributed across the private subnets"
  },
  {
   "id": "instance_sg",
   "tier": "core",
   "kind": "ref",
   "from": {
    "types": [
     "aws_instance"
    ],
    "where": []
   },
   "to": "sg",
   "quote": "with the security group attached"
  },
  {
   "id": "instance_name",
   "tier": "detail",
   "kind": "attr",
   "select": {
    "types": [
     "aws_instance"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "tags",
     "Name"
    ],
    "op": "eq",
    "value": "Terraform_Instance"
   },
   "quantifier": "all",
   "quote": "named \"Terraform_Instance\""
  },
  {
   "id": "root_encrypted",
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
     "root_block_device",
     "*",
     "encrypted"
    ],
    "op": "truthy"
   },
   "quantifier": "all",
   "quote": "an encrypted 20 GB root volume"
  },
  {
   "id": "root_size",
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
     "root_block_device",
     "*",
     "volume_size"
    ],
    "op": "eq",
    "value": 20
   },
   "quantifier": "all",
   "quote": "an encrypted 20 GB root volume"
  },
  {
   "id": "root_tag",
   "tier": "detail",
   "kind": "any_of",
   "quote": "tagged \"Terraform_EBS_Volume1\"",
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
       "tags"
      ],
      "op": "contains",
      "value": "Terraform_EBS_Volume1"
     },
     "quantifier": "all"
    },
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
       "volume_tags"
      ],
      "op": "contains",
      "value": "Terraform_EBS_Volume1"
     },
     "quantifier": "all"
    }
   ]
  },
  {
   "id": "imdsv2",
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
     "metadata_options",
     "*",
     "http_tokens"
    ],
    "op": "eq",
    "value": "required"
   },
   "quantifier": "all",
   "quote": "IMDSv2 required"
  },
  {
   "id": "x_root_dot",
   "tier": "extra",
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
     "delete_on_termination"
    ],
    "op": "truthy"
   },
   "quantifier": "all"
  },
  {
   "id": "x_endpoint",
   "tier": "extra",
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
     "http_endpoint"
    ],
    "op": "eq",
    "value": "enabled"
   },
   "quantifier": "all"
  },
  {
   "id": "extra_type_aws_eip",
   "kind": "exists",
   "tier": "extra",
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
   }
  },
  {
   "id": "extra_type_aws_internet_gateway",
   "kind": "exists",
   "tier": "extra",
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
      "value": "aws_internet_gateway"
     }
    ]
   }
  },
  {
   "id": "extra_type_aws_nat_gateway",
   "kind": "exists",
   "tier": "extra",
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
      "value": "aws_nat_gateway"
     }
    ]
   }
  },
  {
   "id": "extra_type_aws_route",
   "kind": "exists",
   "tier": "extra",
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
     }
    ]
   }
  },
  {
   "id": "extra_type_aws_route_table",
   "kind": "exists",
   "tier": "extra",
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
     }
    ]
   }
  },
  {
   "id": "extra_type_aws_route_table_association",
   "kind": "exists",
   "tier": "extra",
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
      "value": "aws_route_table_association"
     }
    ]
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
