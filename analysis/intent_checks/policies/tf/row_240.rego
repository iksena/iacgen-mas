package intent.tf.row_240

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
   "quote": "self-contained, customizable VPC network"
  },
  {
   "id": "prefix_default",
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
      "value": "bench"
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
      "value": "bench"
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
      "value": "bench"
     }
    }
   ],
   "quote": "configurable cluster prefix defaulting to \"bench\""
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
    "value": "172.16.0.0/16"
   },
   "quote": "a default VPC CIDR of \"172.16.0.0/16\""
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
    "op": "eq",
    "value": true
   },
   "quote": "with DNS support and DNS hostnames enabled"
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
   "quote": "with DNS support and DNS hostnames enabled"
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
   "id": "keypair",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_key_pair"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "key_name"
    ],
    "op": "eq",
    "value": "benchmark-keypair"
   },
   "quote": "a deployment SSH key pair defaulting to \"benchmark-keypair\""
  },
  {
   "id": "keypair_pubkey",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_key_pair"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "public_key"
      ],
      "op": "regex",
      "value": "^ssh-"
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
        "value": "aws_key_pair"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "public_key"
      ],
      "op": "present"
     }
    }
   ],
   "quote": "with a valid public key string"
  },
  {
   "id": "subnets",
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
      "value": "aws_subnet"
     }
    ]
   },
   "quote": "user-defined public and private subnet objects across specified availability zones"
  },
  {
   "id": "subnets_vpc",
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
      "value": "aws_subnet"
     }
    ]
   },
   "to": {
    "types": [
     "aws_vpc"
    ],
    "where": []
   },
   "quote": "user-defined public and private subnet objects"
  },
  {
   "id": "public_default_route",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_default_route_table"
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
        "value": "aws_default_route_table"
       },
       {
        "path": [
         "properties",
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
       },
       {
        "path": [
         "properties",
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
    }
   ],
   "quote": "configuring a default public route table pointing 0.0.0.0/0 to the Internet Gateway"
  },
  {
   "id": "nat_eip",
   "tier": "core",
   "kind": "ref",
   "quote": "per-subnet Elastic IPs and public NAT Gateways",
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
   }
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
   "quote": "public NAT Gateways"
  },
  {
   "id": "nat_public",
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
        "value": "aws_nat_gateway"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "connectivity_type"
      ],
      "op": "eq",
      "value": "public"
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
        "value": "aws_nat_gateway"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "connectivity_type"
      ],
      "op": "absent"
     }
    }
   ],
   "quote": "public NAT Gateways"
  },
  {
   "id": "private_route_nat",
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
   "quote": "associated with private route tables for private subnets"
  },
  {
   "id": "private_assoc",
   "tier": "detail",
   "kind": "ref",
   "quote": "private route tables for private subnets",
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
      "value": "aws_route_table_association"
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
      "value": "aws_route_table"
     },
     {
      "path": [
       "properties",
       "route"
      ],
      "op": "regex",
      "value": "nat_gateway"
     }
    ]
   }
  },
  {
   "id": "sg_self_ingress",
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
       "*",
       "self"
      ],
      "op": "truthy"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_default_security_group"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "ingress",
       "*",
       "self"
      ],
      "op": "truthy"
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
       }
      ]
     },
     "cond": {
      "path": [
       "self"
      ],
      "op": "truthy"
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
       "ingress"
      ],
      "op": "regex",
      "value": "(?i)self[^a-z]{1,6}true"
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
        "value": "aws_default_security_group"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "ingress"
      ],
      "op": "regex",
      "value": "(?i)self[^a-z]{1,6}true"
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
        "value": "aws_vpc_security_group_ingress_rule"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "referenced_security_group_id"
      ],
      "op": "present"
     }
    }
   ],
   "quote": "a default security group supporting full self-referencing intra-group ingress"
  },
  {
   "id": "sg_egress_vpc_only",
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
       "egress",
       "*",
       "cidr_blocks",
       "*"
      ],
      "op": "eq",
      "value": "172.16.0.0/16",
      "every": true
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_default_security_group"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "egress",
       "*",
       "cidr_blocks",
       "*"
      ],
      "op": "eq",
      "value": "172.16.0.0/16",
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
      "value": "172.16.0.0/16",
      "every": true
     }
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
      "value": "172.16.0.0/16"
     },
     "quantifier": "all"
    }
   ],
   "quote": "outbound traffic only within the VPC CIDR",
   "justify": "VPC CIDR default is 172.16.0.0/16"
  },
  {
   "id": "sg_custom_ingress",
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
        "value": "aws_security_group"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "dynamic",
       "ingress"
      ],
      "op": "regex",
      "value": "(?i)cidr"
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
        "value": "aws_security_group_rule"
       },
       {
        "path": [
         "gated"
        ],
        "op": "truthy"
       },
       {
        "path": [
         "properties",
         "type"
        ],
        "op": "eq",
        "value": "ingress"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "cidr_blocks"
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
        "value": "aws_vpc_security_group_ingress_rule"
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
       "cidr_ipv4"
      ],
      "op": "present"
     }
    }
   ],
   "quote": "custom dynamic ingress CIDR rules"
  },
  {
   "id": "ami",
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
       "data.aws_ami"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "most_recent"
      ],
      "op": "eq",
      "value": true
     }
    }
   ],
   "quote": "retrieve recent AMIs"
  },
  {
   "id": "instances",
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
      "value": "aws_instance"
     }
    ]
   },
   "quote": "provision EBS-optimized EC2 instances"
  },
  {
   "id": "ebs_optimized",
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
     "ebs_optimized"
    ],
    "op": "eq",
    "value": true
   },
   "quote": "EBS-optimized EC2 instances"
  },
  {
   "id": "instance_subnet",
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
   "quote": "attached to subnets via index positioning"
  },
  {
   "id": "instance_root",
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
     "properties",
     "root_block_device"
    ],
    "op": "present"
   },
   "quote": "configurable root volumes"
  },
  {
   "id": "instance_ami_ref",
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
   },
   "quote": "retrieve recent AMIs"
  },
  {
   "id": "node_eip",
   "tier": "detail",
   "kind": "any_of",
   "quote": "optional Elastic IPs",
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
        "value": "aws_eip"
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
        "value": "aws_eip_association"
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
   ]
  },
  {
   "id": "secondary_volume",
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
      "value": "aws_ebs_volume"
     }
    ]
   },
   "quote": "construct attached secondary EBS volumes"
  },
  {
   "id": "volume_attach",
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
      "value": "aws_volume_attachment"
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
      "value": "aws_ebs_volume"
     }
    ]
   },
   "quote": "attached secondary EBS volumes mapped to specified device names"
  },
  {
   "id": "volume_device",
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
      "value": "aws_volume_attachment"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "device_name"
    ],
    "op": "present"
   },
   "quote": "mapped to specified device names and mount points"
  },
  {
   "id": "attach_instance",
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
      "value": "aws_volume_attachment"
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
   },
   "quote": "attached secondary EBS volumes"
  },
  {
   "id": "x_public_subnet_mapping",
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
      "value": "aws_subnet"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "map_public_ip_on_launch"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "x_private_subnet_nomap",
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
      "value": "aws_subnet"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "map_public_ip_on_launch"
    ],
    "op": "eq",
    "value": false
   }
  },
  {
   "id": "x_nat_in_public_subnet",
   "tier": "extra",
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
   }
  },
  {
   "id": "x_eip_depends_igw",
   "tier": "extra",
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
      "value": "aws_eip"
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
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
