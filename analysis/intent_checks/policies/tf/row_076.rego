# GENERATED from specs/tf/row_076.json by intent_checks/build.py -- do not edit.
package intent.tf.row_076

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "sg": {
   "types": [
    "aws_security_group"
   ],
   "where": []
  },
  "nat": {
   "types": [
    "aws_nat_gateway"
   ],
   "where": []
  },
  "ns": {
   "types": [
    "aws_service_discovery_private_dns_namespace"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "service.local"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "vpc",
   "kind": "exists",
   "select": {
    "types": [
     "aws_vpc"
    ],
    "where": []
   },
   "tier": "core",
   "quote": "creates a VPC"
  },
  {
   "id": "four_subnets",
   "kind": "exists",
   "select": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "min": 4,
   "tier": "core",
   "quote": "public and private subnets across two availability zones"
  },
  {
   "id": "subnets_in_vpc",
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
   "tier": "detail",
   "quote": "a VPC with public and private subnets"
  },
  {
   "id": "internet_gateway",
   "kind": "exists",
   "select": {
    "types": [
     "aws_internet_gateway"
    ],
    "where": []
   },
   "tier": "detail",
   "quote": "public and private subnets"
  },
  {
   "id": "single_nat",
   "kind": "exists",
   "select": "nat",
   "min": 1,
   "max": 1,
   "tier": "core",
   "quote": "a single NAT gateway",
   "justify": "\"a single NAT gateway\" states exactly one"
  },
  {
   "id": "nat_in_subnet",
   "kind": "ref",
   "from": "nat",
   "to": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "tier": "detail",
   "quote": "a single NAT gateway"
  },
  {
   "id": "private_route_via_nat",
   "kind": "any_of",
   "tier": "detail",
   "quote": "private subnets across two availability zones and a single NAT gateway",
   "checks": [
    {
     "kind": "ref",
     "to": "nat",
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
     }
    },
    {
     "kind": "ref",
     "to": "nat",
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
     }
    }
   ],
   "justify": "routing private subnets through a NAT gateway implies a default (0.0.0.0/0) route"
  },
  {
   "id": "sg_in_vpc",
   "kind": "ref",
   "from": "sg",
   "to": {
    "types": [
     "aws_vpc"
    ],
    "where": []
   },
   "tier": "detail",
   "quote": "a security group"
  },
  {
   "id": "ssh_from_vpc_only",
   "kind": "any_of",
   "tier": "core",
   "quote": "allows SSH only from within the VPC CIDR",
   "checks": [
    {
     "kind": "ref",
     "to": {
      "types": [
       "aws_vpc",
       "data.aws_vpc"
      ],
      "where": []
     },
     "from": {
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
          "value": 22
         },
         {
          "path": [
           "cidr_blocks",
           "*"
          ],
          "op": "none_eq",
          "value": "0.0.0.0/0"
         },
         {
          "path": [
           "ipv6_cidr_blocks",
           "*"
          ],
          "op": "none_eq",
          "value": "::/0"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "join",
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
       }
      ]
     },
     "from_path": [
      "cidr_blocks",
      "*"
     ],
     "to": {
      "types": [
       "aws_vpc"
      ],
      "where": []
     },
     "to_path": [
      "cidr_block"
     ]
    },
    {
     "kind": "join",
     "from": {
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
     "from_path": [
      "cidr_ipv4"
     ],
     "to": {
      "types": [
       "aws_vpc"
      ],
      "where": []
     },
     "to_path": [
      "cidr_block"
     ]
    },
    {
     "kind": "ref",
     "to": {
      "types": [
       "aws_vpc",
       "data.aws_vpc"
      ],
      "where": []
     },
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
        "op": "none_eq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": {
      "types": [
       "aws_vpc",
       "data.aws_vpc"
      ],
      "where": []
     },
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
        "op": "neq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    }
   ],
   "justify": "SSH implies port 22; \"only from within the VPC CIDR\" implies not 0.0.0.0/0; CIDR matched to the VPC's own cidr_block, never a literal"
  },
  {
   "id": "ingress_http_anywhere",
   "kind": "any_of",
   "tier": "core",
   "quote": "allows HTTP, HTTPS, and application ports 3000 and 5432 from anywhere",
   "checks": [
    {
     "kind": "attr",
     "select": "sg",
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
         "cidr_ipv4"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    }
   ],
   "justify": "HTTP implies port 80; \"from anywhere\" implies 0.0.0.0/0"
  },
  {
   "id": "ingress_https_anywhere",
   "kind": "any_of",
   "tier": "core",
   "quote": "allows HTTP, HTTPS, and application ports 3000 and 5432 from anywhere",
   "checks": [
    {
     "kind": "attr",
     "select": "sg",
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
         "cidr_ipv4"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    }
   ],
   "justify": "HTTPS implies port 443; \"from anywhere\" implies 0.0.0.0/0"
  },
  {
   "id": "ingress_3000_anywhere",
   "kind": "any_of",
   "tier": "core",
   "quote": "application ports 3000 and 5432 from anywhere",
   "checks": [
    {
     "kind": "attr",
     "select": "sg",
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
        "value": 3000
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
        "value": 3000
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
        "value": 3000
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
   "justify": "ports stated; \"from anywhere\" implies 0.0.0.0/0"
  },
  {
   "id": "ingress_5432_anywhere",
   "kind": "any_of",
   "tier": "core",
   "quote": "application ports 3000 and 5432 from anywhere",
   "checks": [
    {
     "kind": "attr",
     "select": "sg",
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
        "value": 5432
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
        "value": 5432
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
        "value": 5432
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
   "justify": "ports stated; \"from anywhere\" implies 0.0.0.0/0"
  },
  {
   "id": "egress_limited_to_vpc",
   "kind": "any_of",
   "tier": "core",
   "quote": "limits outbound traffic to the VPC CIDR",
   "checks": [
    {
     "kind": "ref",
     "to": {
      "types": [
       "aws_vpc",
       "data.aws_vpc"
      ],
      "where": []
     },
     "from": {
      "types": [
       "aws_security_group"
      ],
      "where": [
       {
        "path": [
         "egress"
        ],
        "op": "len_gte",
        "value": 1
       },
       {
        "path": [
         "egress",
         "*",
         "cidr_blocks",
         "*"
        ],
        "op": "none_eq",
        "value": "0.0.0.0/0"
       },
       {
        "path": [
         "egress",
         "*",
         "ipv6_cidr_blocks",
         "*"
        ],
        "op": "none_eq",
        "value": "::/0"
       }
      ]
     }
    },
    {
     "kind": "join",
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
       }
      ]
     },
     "from_path": [
      "cidr_blocks",
      "*"
     ],
     "to": {
      "types": [
       "aws_vpc"
      ],
      "where": []
     },
     "to_path": [
      "cidr_block"
     ]
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "aws_vpc_security_group_egress_rule"
      ],
      "where": []
     },
     "from_path": [
      "cidr_ipv4"
     ],
     "to": {
      "types": [
       "aws_vpc"
      ],
      "where": []
     },
     "to_path": [
      "cidr_block"
     ]
    },
    {
     "kind": "ref",
     "to": {
      "types": [
       "aws_vpc",
       "data.aws_vpc"
      ],
      "where": []
     },
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
        "op": "none_eq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": {
      "types": [
       "aws_vpc",
       "data.aws_vpc"
      ],
      "where": []
     },
     "from": {
      "types": [
       "aws_vpc_security_group_egress_rule"
      ],
      "where": [
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
   "justify": "\"limits outbound traffic to the VPC CIDR\" implies no 0.0.0.0/0 egress; CIDR matched to the VPC's own cidr_block"
  },
  {
   "id": "namespace_named",
   "kind": "exists",
   "select": "ns",
   "tier": "core",
   "quote": "a private Service Discovery DNS namespace named \"service.local\""
  },
  {
   "id": "namespace_in_vpc",
   "kind": "ref",
   "from": "ns",
   "to": {
    "types": [
     "aws_vpc"
    ],
    "where": []
   },
   "tier": "detail",
   "quote": "a private Service Discovery DNS namespace"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
