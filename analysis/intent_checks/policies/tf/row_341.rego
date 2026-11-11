package intent.tf.row_341

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "vpc_dev",
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
   "quote": "\"dev\" (10.0.0.0/16)"
  },
  {
   "id": "vpc_test",
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
    "value": "172.24.0.0/16"
   },
   "quote": "\"test\" (172.24.0.0/16)"
  },
  {
   "id": "vpc_dev_name",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_vpc"
      ],
      "where": [
       {
        "path": [
         "cidr_block"
        ],
        "op": "eq",
        "value": "10.0.0.0/16"
       }
      ]
     },
     "cond": {
      "path": [
       "tags",
       "Name"
      ],
      "op": "regex",
      "value": "(?i)^dev([-_ ]?vpc)?$"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_vpc"
      ],
      "where": [
       {
        "path": [
         "cidr_block"
        ],
        "op": "eq",
        "value": "10.0.0.0/16"
       }
      ]
     },
     "cond": {
      "path": [
       "tags_all",
       "Name"
      ],
      "op": "regex",
      "value": "(?i)^dev([-_ ]?vpc)?$"
     }
    }
   ],
   "quote": "\"dev\" (10.0.0.0/16)",
   "justify": "a VPC called \"dev\" may carry a Name tag of \"dev\" or \"dev-vpc\""
  },
  {
   "id": "vpc_test_name",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_vpc"
      ],
      "where": [
       {
        "path": [
         "cidr_block"
        ],
        "op": "eq",
        "value": "172.24.0.0/16"
       }
      ]
     },
     "cond": {
      "path": [
       "tags",
       "Name"
      ],
      "op": "regex",
      "value": "(?i)^test([-_ ]?vpc)?$"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_vpc"
      ],
      "where": [
       {
        "path": [
         "cidr_block"
        ],
        "op": "eq",
        "value": "172.24.0.0/16"
       }
      ]
     },
     "cond": {
      "path": [
       "tags_all",
       "Name"
      ],
      "op": "regex",
      "value": "(?i)^test([-_ ]?vpc)?$"
     }
    }
   ],
   "quote": "\"test\" (172.24.0.0/16)",
   "justify": "a VPC called \"test\" may carry a Name tag of \"test\" or \"test-vpc\""
  },
  {
   "id": "dns_hostnames",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_vpc"
    ],
    "where": [
     {
      "path": [
       "cidr_block"
      ],
      "op": "in",
      "value": [
       "10.0.0.0/16",
       "172.24.0.0/16"
      ]
     }
    ]
   },
   "cond": {
    "path": [
     "enable_dns_hostnames"
    ],
    "op": "truthy"
   },
   "quantifier": "all",
   "quote": "with DNS support and hostnames enabled"
  },
  {
   "id": "dns_support",
   "tier": "detail",
   "kind": "attr",
   "select": {
    "types": [
     "aws_vpc"
    ],
    "where": [
     {
      "path": [
       "cidr_block"
      ],
      "op": "in",
      "value": [
       "10.0.0.0/16",
       "172.24.0.0/16"
      ]
     }
    ]
   },
   "cond": {
    "path": [
     "enable_dns_support"
    ],
    "op": "truthy"
   },
   "quantifier": "all",
   "quote": "with DNS support and hostnames enabled"
  },
  {
   "id": "dev_az2",
   "tier": "detail",
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
      "op": "regex",
      "value": "^10\\.0\\."
     }
    ]
   },
   "distinct_path": [
    "availability_zone"
   ],
   "min": 2,
   "quote": "each spanning the first two available availability zones",
   "justify": "two zones are spanned"
  },
  {
   "id": "test_az2",
   "tier": "detail",
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
      "op": "regex",
      "value": "^172\\.24\\."
     }
    ]
   },
   "distinct_path": [
    "availability_zone"
   ],
   "min": 2,
   "quote": "each spanning the first two available availability zones",
   "justify": "two zones are spanned"
  },
  {
   "id": "dev_subnets",
   "tier": "core",
   "kind": "all_of",
   "checks": [
    {
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
        "value": "10.0.101.0/24"
       }
      ]
     }
    },
    {
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
        "value": "10.0.102.0/24"
       }
      ]
     }
    },
    {
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
        "value": "10.0.1.0/24"
       }
      ]
     }
    },
    {
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
        "value": "10.0.2.0/24"
       }
      ]
     }
    }
   ],
   "quote": "two public /24 subnets at the 101 and 102 offsets and two private /24 subnets at the 1 and 2 offsets",
   "justify": "a /24 at offset N inside a /16 is x.y.N.0/24"
  },
  {
   "id": "test_subnets",
   "tier": "core",
   "kind": "all_of",
   "checks": [
    {
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
        "value": "172.24.101.0/24"
       }
      ]
     }
    },
    {
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
        "value": "172.24.102.0/24"
       }
      ]
     }
    },
    {
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
        "value": "172.24.1.0/24"
       }
      ]
     }
    },
    {
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
        "value": "172.24.2.0/24"
       }
      ]
     }
    }
   ],
   "quote": "two public /24 subnets at the 101 and 102 offsets and two private /24 subnets at the 1 and 2 offsets",
   "justify": "a /24 at offset N inside a /16 is x.y.N.0/24"
  },
  {
   "id": "peering",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_vpc_peering_connection"
    ],
    "where": []
   },
   "quote": "Connect them with an auto-accepted VPC peering connection"
  },
  {
   "id": "peering_auto_accept",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_vpc_peering_connection"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "auto_accept"
      ],
      "op": "truthy"
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_vpc_peering_connection_accepter"
      ],
      "where": []
     }
    }
   ],
   "quote": "auto-accepted VPC peering connection"
  },
  {
   "id": "peering_name",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_vpc_peering_connection"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "dev-test-vpc-peer"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_vpc_peering_connection"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "tags_all",
       "Name"
      ],
      "op": "eq",
      "value": "dev-test-vpc-peer"
     }
    }
   ],
   "quote": "named \"dev-test-vpc-peer\""
  },
  {
   "id": "dns_requester",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_vpc_peering_connection"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "requester",
       "*",
       "allow_remote_vpc_dns_resolution"
      ],
      "op": "truthy"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_vpc_peering_connection_options"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "requester",
       "*",
       "allow_remote_vpc_dns_resolution"
      ],
      "op": "truthy"
     }
    }
   ],
   "quote": "allows remote DNS resolution in both directions"
  },
  {
   "id": "dns_accepter",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_vpc_peering_connection"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "accepter",
       "*",
       "allow_remote_vpc_dns_resolution"
      ],
      "op": "truthy"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_vpc_peering_connection_options"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "accepter",
       "*",
       "allow_remote_vpc_dns_resolution"
      ],
      "op": "truthy"
     }
    }
   ],
   "quote": "allows remote DNS resolution in both directions"
  },
  {
   "id": "peer_routes_ref",
   "tier": "core",
   "kind": "any_of",
   "checks": [
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
       "aws_vpc_peering_connection"
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
      "where": []
     },
     "to": {
      "types": [
       "aws_vpc_peering_connection"
      ],
      "where": []
     }
    }
   ],
   "quote": "add routes to the peer VPC's CIDR in each VPC's public and private route tables"
  },
  {
   "id": "peer_routes_count",
   "tier": "detail",
   "kind": "any_of",
   "quote": "add routes to the peer VPC's CIDR in each VPC's public and private route tables",
   "justify": "two VPCs, each with at least one public and one private route table, each routing to the other VPC's stated CIDR",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_route"
      ],
      "where": [
       {
        "path": [
         "destination_cidr_block"
        ],
        "op": "in",
        "value": [
         "10.0.0.0/16",
         "172.24.0.0/16"
        ]
       }
      ]
     },
     "min": 4
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_route"
      ],
      "where": [
       {
        "path": [
         "destination_cidr_block"
        ],
        "op": "absent"
       }
      ]
     },
     "min": 4
    },
    {
     "kind": "exists",
     "select": {
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
        "op": "in",
        "value": [
         "10.0.0.0/16",
         "172.24.0.0/16"
        ]
       }
      ]
     },
     "min": 4
    }
   ]
  },
  {
   "id": "extra_type_aws_default_network_acl",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_default_network_acl"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_default_route_table",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_default_route_table"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_default_security_group",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_default_security_group"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_internet_gateway",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_internet_gateway"
    ],
    "where": []
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
