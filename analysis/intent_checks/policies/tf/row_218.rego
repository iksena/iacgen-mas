package intent.tf.row_218

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "vpc",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_vpc"
    ],
    "where": []
   },
   "quote": "self-contained multi-tier VPC network stack"
  },
  {
   "id": "vpc_cidr_16",
   "kind": "attr",
   "tier": "core",
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
    "op": "regex",
    "value": "/16$"
   },
   "quote": "using a /16 CIDR block",
   "justify": "/16 is stated"
  },
  {
   "id": "igw",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_internet_gateway"
    ],
    "where": []
   },
   "quote": "it must include an internet gateway"
  },
  {
   "id": "igw_attached",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
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
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_internet_gateway_attachment"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_vpc"
      ],
      "where": []
     }
    }
   ],
   "quote": "it must include an internet gateway"
  },
  {
   "id": "subnets_six",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "quote": "one public subnet and two private subnets in each availability zone",
   "min": 6,
   "justify": "two AZs times three subnets"
  },
  {
   "id": "subnets_two_azs",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "quote": "across two availability zones",
   "min": 2,
   "distinct_path": [
    "availability_zone"
   ]
  },
  {
   "id": "public_no_auto_ip",
   "kind": "attr",
   "tier": "core",
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
   "quote": "public subnets do not auto-assign public IPs on launch",
   "quantifier": "all"
  },
  {
   "id": "public_route_igw",
   "kind": "any_of",
   "tier": "core",
   "checks": [
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
    }
   ],
   "quote": "a public route table with a default route to the internet gateway",
   "justify": "default route is 0.0.0.0/0"
  },
  {
   "id": "route_tables_two",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_route_table"
    ],
    "where": []
   },
   "quote": "a public route table with a default route to the internet gateway and a private route table",
   "min": 2,
   "justify": "one public and one private route table"
  },
  {
   "id": "private_rt_no_routes",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_route_table"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "route"
      ],
      "op": "absent"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_route_table"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "route"
      ],
      "op": "len_eq",
      "value": 0
     }
    }
   ],
   "quote": "a private route table with no explicit routes"
  },
  {
   "id": "associations",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_route_table_association"
    ],
    "where": []
   },
   "quote": "each associated to its respective subnets",
   "min": 6
  },
  {
   "id": "security_groups",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_security_group"
    ],
    "where": []
   },
   "quote": "a public security group",
   "min": 2,
   "justify": "a public and a private security group"
  },
  {
   "id": "pub_http_anywhere",
   "kind": "any_of",
   "tier": "core",
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
        "value": 80
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
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
     "kind": "ref",
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
     },
     "to": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [],
        "op": "match",
        "value": [
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
      ]
     },
     "to": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     }
    }
   ],
   "quote": "HTTP from anywhere",
   "justify": "HTTP is port 80, anywhere is 0.0.0.0/0; HTTP/SSH are TCP, so an all-protocol rule does not count"
  },
  {
   "id": "pub_ssh_vpc",
   "kind": "any_of",
   "tier": "core",
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
        "value": 22
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "regex",
        "value": "/16$"
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
     "kind": "ref",
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
          "op": "regex",
          "value": "/16$"
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
     },
     "to": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [],
        "op": "match",
        "value": [
         {
          "path": [],
          "op": "port_covers",
          "value": 22
         },
         {
          "path": [
           "cidr_ipv4"
          ],
          "op": "regex",
          "value": "/16$"
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
      ]
     },
     "to": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     }
    }
   ],
   "quote": "SSH from the VPC CIDR",
   "justify": "SSH is port 22; the VPC CIDR is a /16; HTTP/SSH are TCP, so an all-protocol rule does not count"
  },
  {
   "id": "allow_all_from_vpc",
   "kind": "any_of",
   "tier": "core",
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
        "path": [
         "protocol"
        ],
        "op": "in",
        "value": [
         "-1",
         "all"
        ]
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "regex",
        "value": "/16$"
       }
      ]
     }
    },
    {
     "kind": "ref",
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
        "op": "match",
        "value": [
         {
          "path": [
           "protocol"
          ],
          "op": "in",
          "value": [
           "-1",
           "all"
          ]
         },
         {
          "path": [
           "cidr_blocks",
           "*"
          ],
          "op": "regex",
          "value": "/16$"
         }
        ]
       }
      ]
     },
     "to": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [],
        "op": "match",
        "value": [
         {
          "path": [
           "ip_protocol"
          ],
          "op": "in",
          "value": [
           "-1",
           "all"
          ]
         },
         {
          "path": [
           "cidr_ipv4"
          ],
          "op": "regex",
          "value": "/16$"
         }
        ]
       }
      ]
     },
     "to": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     }
    }
   ],
   "quote": "allows all traffic from the VPC CIDR",
   "justify": "all traffic is protocol -1; the VPC CIDR is a /16"
  },
  {
   "id": "egress_only_vpc",
   "kind": "any_of",
   "tier": "core",
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
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "regex",
        "value": "/16$"
       }
      ]
     },
     "quantifier": "all"
    },
    {
     "kind": "ref",
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
        "op": "regex",
        "value": "/16$"
       }
      ]
     },
     "to": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_vpc_security_group_egress_rule"
      ],
      "where": [
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "regex",
        "value": "/16$"
       }
      ]
     },
     "to": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     }
    }
   ],
   "quote": "outbound traffic only to the VPC CIDR"
  },
  {
   "id": "egress_not_internet",
   "kind": "attr",
   "tier": "core",
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
    "op": "none_eq",
    "value": "0.0.0.0/0"
   },
   "quote": "outbound traffic only to the VPC CIDR",
   "quantifier": "all",
   "justify": "only to the VPC CIDR excludes the internet 0.0.0.0/0"
  },
  {
   "id": "private_sg_all_from_vpc",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
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
        "op": "match",
        "value": [
         {
          "path": [
           "protocol"
          ],
          "op": "in",
          "value": [
           "-1",
           "all"
          ]
         },
         {
          "path": [
           "cidr_blocks",
           "*"
          ],
          "op": "regex",
          "value": "/16$"
         }
        ]
       }
      ]
     },
     "min": 2
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
        "op": "match",
        "value": [
         {
          "path": [
           "protocol"
          ],
          "op": "in",
          "value": [
           "-1",
           "all"
          ]
         },
         {
          "path": [
           "cidr_blocks",
           "*"
          ],
          "op": "regex",
          "value": "/16$"
         }
        ]
       }
      ]
     },
     "min": 2
    },
    {
     "kind": "exists",
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
         "-1",
         "all"
        ]
       },
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "regex",
        "value": "/16$"
       }
      ]
     },
     "min": 2
    }
   ],
   "quote": "and a private security group that allows all traffic from the VPC CIDR",
   "justify": "public and private groups both allow all traffic from the VPC CIDR"
  },
  {
   "id": "x_pubsg_split",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_security_group"
    ],
    "where": []
   },
   "min": 2
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
