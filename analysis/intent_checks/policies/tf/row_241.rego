package intent.tf.row_241

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
   "quote": "creates a versatile VPC networking module named \"benchmark-vpc\""
  },
  {
   "id": "vpc_name",
   "tier": "core",
   "kind": "any_of",
   "checks": [
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
       "tags_all",
       "Name"
      ],
      "op": "eq",
      "value": "benchmark-vpc"
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
      "op": "eq",
      "value": "benchmark-vpc"
     }
    }
   ],
   "quote": "named \"benchmark-vpc\""
  },
  {
   "id": "region_default",
   "tier": "detail",
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
      "value": "us-east-1"
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
       "region"
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
      "value": "^us-east-1"
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
       "properties"
      ],
      "op": "regex",
      "value": "us-east-1"
     }
    }
   ],
   "quote": "defaulting to the us-east-1 region"
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
   "quote": "a CIDR block of \"10.0.0.0/16\""
  },
  {
   "id": "igw",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_internet_gateway"
    ],
    "where": []
   },
   "quote": "an Internet Gateway"
  },
  {
   "id": "igw_vpc",
   "tier": "detail",
   "kind": "ref",
   "from": {
    "types": [
     "aws_internet_gateway"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_vpc"
    ],
    "where": []
   },
   "quote": "an Internet Gateway"
  },
  {
   "id": "default_sg_ingress_self",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_default_security_group"
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
         "prefix_list_ids",
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
       }
      ]
     },
     "cond": {
      "path": [
       "ingress",
       "*",
       "self"
      ],
      "op": "truthy",
      "every": true
     }
    },
    {
     "kind": "attr",
     "select": {
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
         "prefix_list_ids",
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
         "self"
        ],
        "op": "truthy",
        "every": true
       }
      ]
     },
     "cond": {
      "path": [
       "ingress",
       "*",
       "self"
      ],
      "op": "truthy",
      "every": true
     }
    }
   ],
   "quote": "a default security group allowing only self-referencing ingress and egress"
  },
  {
   "id": "default_sg_egress_self",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_default_security_group"
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
         "prefix_list_ids",
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
       }
      ]
     },
     "cond": {
      "path": [
       "egress",
       "*",
       "self"
      ],
      "op": "truthy",
      "every": true
     }
    },
    {
     "kind": "attr",
     "select": {
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
         "prefix_list_ids",
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
         "self"
        ],
        "op": "truthy",
        "every": true
       }
      ]
     },
     "cond": {
      "path": [
       "egress",
       "*",
       "self"
      ],
      "op": "truthy",
      "every": true
     }
    }
   ],
   "quote": "a default security group allowing only self-referencing ingress and egress"
  },
  {
   "id": "tls_sg",
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
        "value": "ingress"
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
     "cond": {
      "path": [],
      "op": "port_covers",
      "value": 443
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
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
     },
     "cond": {
      "path": [],
      "op": "port_covers",
      "value": 443
     }
    }
   ],
   "quote": "an additional security group allowing inbound TLS traffic on port 443",
   "justify": "TLS implies port 443"
  },
  {
   "id": "subnets_four",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "min": 4,
   "quote": "the template must provision two public subnets in the first two availability zones and two private subnets"
  },
  {
   "id": "subnet_cidr_1",
   "tier": "core",
   "kind": "exists",
   "quote": "(\"10.0.1.0/24\", \"10.0.2.0/24\", \"10.0.3.0/24\", and \"10.0.4.0/24\")",
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
      "value": "10.0.1.0/24"
     }
    ]
   }
  },
  {
   "id": "subnet_cidr_2",
   "tier": "core",
   "kind": "exists",
   "quote": "(\"10.0.1.0/24\", \"10.0.2.0/24\", \"10.0.3.0/24\", and \"10.0.4.0/24\")",
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
      "value": "10.0.2.0/24"
     }
    ]
   }
  },
  {
   "id": "subnet_cidr_3",
   "tier": "core",
   "kind": "exists",
   "quote": "two private subnets in those same availability zones using the third and fourth CIDR blocks",
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
      "value": "10.0.3.0/24"
     }
    ]
   }
  },
  {
   "id": "subnet_cidr_4",
   "tier": "core",
   "kind": "exists",
   "quote": "two private subnets in those same availability zones using the third and fourth CIDR blocks",
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
      "value": "10.0.4.0/24"
     }
    ]
   }
  },
  {
   "id": "subnets_vpc",
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
   "quote": "flexible public or private subnet layouts"
  },
  {
   "id": "subnet_azs",
   "tier": "core",
   "kind": "exists",
   "quote": "two public subnets in the first two availability zones and two private subnets in those same availability zones",
   "select": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "distinct_path": [
    "availability_zone"
   ],
   "min": 2,
   "max": 2
  },
  {
   "id": "private_toggle",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)priv"
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": true
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
        "value": "aws_subnet"
       },
       {
        "path": [
         "gated"
        ],
        "op": "truthy"
       },
       {
        "path": [
         "gate"
        ],
        "op": "regex",
        "value": "(?i)priv"
       }
      ]
     }
    }
   ],
   "quote": "private subnets are enabled via a boolean toggle defaulting to true"
  },
  {
   "id": "four_public_when_off",
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
        "value": "aws_subnet"
       }
      ]
     },
     "min": 4
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
       "gated"
      ],
      "op": "truthy"
     }
    }
   ],
   "quote": "toggling private subnets to false must instead create four public subnets across four availability zones"
  },
  {
   "id": "nat_gateway",
   "tier": "core",
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
      "value": "aws_nat_gateway"
     }
    ]
   },
   "quote": "deploying redundant NAT Gateways in each public subnet with associated Elastic IPs and private route tables"
  },
  {
   "id": "nat_eip",
   "tier": "core",
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
      "value": "aws_nat_gateway"
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
      "value": "aws_eip"
     }
    ]
   },
   "quote": "redundant NAT Gateways in each public subnet with associated Elastic IPs"
  },
  {
   "id": "nat_public_subnet",
   "tier": "detail",
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
      "value": "aws_nat_gateway"
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
      "value": "aws_subnet"
     }
    ]
   },
   "quote": "NAT Gateways in each public subnet"
  },
  {
   "id": "nat_private_rt",
   "tier": "core",
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
        "value": "aws_route_table"
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
        "value": "aws_nat_gateway"
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
        "value": "aws_nat_gateway"
       }
      ]
     }
    }
   ],
   "quote": "associated Elastic IPs and private route tables"
  },
  {
   "id": "nat_instance",
   "tier": "core",
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
     "instance_type"
    ],
    "op": "eq",
    "value": "m1.small"
   },
   "quote": "deploying redundant NAT EC2 instances (m1.small)"
  },
  {
   "id": "nat_ami",
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
      "value": "(?i)vpc-nat"
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
      "value": "(?i)vpc-nat"
     }
    }
   ],
   "quote": "using Amazon Linux NAT AMIs"
  },
  {
   "id": "nat_instance_public_subnet",
   "tier": "detail",
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
     },
     {
      "path": [
       "properties",
       "instance_type"
      ],
      "op": "eq",
      "value": "m1.small"
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
      "value": "aws_subnet"
     }
    ]
   },
   "quote": "NAT EC2 instances (m1.small) using Amazon Linux NAT AMIs in each public subnet"
  },
  {
   "id": "nat_instance_sg",
   "tier": "detail",
   "kind": "ref",
   "quote": "with custom security group rules",
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
     },
     {
      "path": [
       "properties",
       "instance_type"
      ],
      "op": "eq",
      "value": "m1.small"
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
      "value": "aws_security_group"
     }
    ]
   }
  },
  {
   "id": "nat_instance_route",
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
        "value": "aws_route_table"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)primary_network_interface_id"
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
        "value": "aws_route"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)primary_network_interface_id"
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
        "value": "aws_route_table"
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
        "value": "aws_instance"
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
        "value": "aws_instance"
       }
      ]
     }
    }
   ],
   "quote": "private route tables pointing to their primary network interfaces"
  },
  {
   "id": "egress_only_igw",
   "tier": "core",
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
      "value": "aws_egress_only_internet_gateway"
     }
    ]
   },
   "quote": "creating an Egress-Only Internet Gateway"
  },
  {
   "id": "egress_only_route",
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
        "value": "aws_route"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "destination_ipv6_cidr_block"
      ],
      "op": "eq",
      "value": "::/0"
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
        "value": "aws_route_table"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "::/0"
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
        "value": "aws_route"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "::/0"
     }
    }
   ],
   "quote": "with IPv6 egress routes to ::/0"
  },
  {
   "id": "egress_only_route_ref",
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
        "value": "aws_route"
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
        "value": "aws_egress_only_internet_gateway"
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
        "value": "aws_route_table"
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
        "value": "aws_egress_only_internet_gateway"
       }
      ]
     }
    }
   ],
   "quote": "an Egress-Only Internet Gateway with IPv6 egress routes"
  },
  {
   "id": "strategy_toggles_nat",
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
      "value": "aws_nat_gateway"
     }
    ]
   },
   "cond": {
    "path": [
     "gated"
    ],
    "op": "truthy"
   },
   "quote": "mutually exclusive egress routing strategies controlled by independent boolean toggles"
  },
  {
   "id": "strategy_toggles_instance",
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
      "value": "aws_instance"
     }
    ]
   },
   "cond": {
    "path": [
     "gated"
    ],
    "op": "truthy"
   },
   "quote": "mutually exclusive egress routing strategies controlled by independent boolean toggles"
  },
  {
   "id": "strategy_toggles_eigw",
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
      "value": "aws_egress_only_internet_gateway"
     }
    ]
   },
   "cond": {
    "path": [
     "gated"
    ],
    "op": "truthy"
   },
   "quote": "mutually exclusive egress routing strategies controlled by independent boolean toggles"
  },
  {
   "id": "x_public_route_igw",
   "tier": "extra",
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
     "to": {
      "types": [
       "aws_internet_gateway"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_route"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_internet_gateway"
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
        "value": "aws_route_table"
       }
      ]
     },
     "to": {
      "types": [
       "aws_internet_gateway"
      ],
      "where": []
     }
    }
   ]
  },
  {
   "id": "x_public_assoc",
   "tier": "extra",
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
      "value": "aws_route_table_association"
     }
    ]
   },
   "min": 2
  },
  {
   "id": "x_tls_ingress_open",
   "tier": "extra",
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
     "*",
     "cidr_blocks",
     "*"
    ],
    "op": "eq",
    "value": "0.0.0.0/0"
   }
  },
  {
   "id": "x_nat_instance_no_srcdst",
   "tier": "extra",
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
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
