# GENERATED from specs/tf/row_089.json by intent_checks/build.py -- do not edit.
package intent.tf.row_089

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
     "op": "eq",
     "value": "10.0.0.0/16"
    }
   ]
  },
  "priv": {
   "types": [
    "aws_subnet"
   ],
   "where": [
    {
     "path": [
      "cidr_block"
     ],
     "op": "in",
     "value": [
      "10.0.0.0/20",
      "10.0.16.0/20",
      "10.0.32.0/20"
     ]
    }
   ]
  },
  "pub": {
   "types": [
    "aws_subnet"
   ],
   "where": [
    {
     "path": [
      "cidr_block"
     ],
     "op": "in",
     "value": [
      "10.0.48.0/24",
      "10.0.49.0/24",
      "10.0.50.0/24"
     ]
    }
   ]
  },
  "nat": {
   "types": [
    "aws_nat_gateway"
   ],
   "where": []
  },
  "sg1": {
   "types": [
    "aws_security_group"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "cluster1_additional_sg"
    }
   ]
  },
  "sg2": {
   "types": [
    "aws_security_group"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "cluster2_additional_sg"
    }
   ]
  },
  "vpc_res": {
   "types": [
    "aws_vpc",
    "aws_subnet"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "vpc_cidr",
   "kind": "exists",
   "select": "vpc",
   "tier": "core",
   "quote": "with a CIDR block of \"10.0.0.0/16\""
  },
  {
   "id": "single_nat",
   "kind": "exists",
   "select": "nat",
   "min": 1,
   "max": 1,
   "tier": "core",
   "quote": "configured with a single NAT gateway",
   "justify": "\"a single NAT gateway\" states exactly one"
  },
  {
   "id": "private_subnets_20",
   "kind": "all_of",
   "tier": "core",
   "quote": "three private subnets calculated using a prefix length extension of 4 (e.g., /20 subnets at netnums 0, 1, 2)",
   "checks": [
    {
     "kind": "ref",
     "to": "vpc",
     "from": {
      "types": [
       "aws_subnet"
      ],
      "where": [
       {
        "path": [
         "cidr_block"
        ],
        "op": "eq",
        "value": "10.0.0.0/20"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "vpc",
     "from": {
      "types": [
       "aws_subnet"
      ],
      "where": [
       {
        "path": [
         "cidr_block"
        ],
        "op": "eq",
        "value": "10.0.16.0/20"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "vpc",
     "from": {
      "types": [
       "aws_subnet"
      ],
      "where": [
       {
        "path": [
         "cidr_block"
        ],
        "op": "eq",
        "value": "10.0.32.0/20"
       }
      ]
     }
    }
   ],
   "justify": "prompt gives cidrsubnet(10.0.0.0/16, 4, 0..2) = 10.0.0.0/20, 10.0.16.0/20, 10.0.32.0/20"
  },
  {
   "id": "public_subnets_24",
   "kind": "all_of",
   "tier": "core",
   "quote": "three public subnets calculated using a prefix length extension of 8 starting at offset 48 (e.g., /24 subnets at netnums 48, 49, 50)",
   "checks": [
    {
     "kind": "ref",
     "to": "vpc",
     "from": {
      "types": [
       "aws_subnet"
      ],
      "where": [
       {
        "path": [
         "cidr_block"
        ],
        "op": "eq",
        "value": "10.0.48.0/24"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "vpc",
     "from": {
      "types": [
       "aws_subnet"
      ],
      "where": [
       {
        "path": [
         "cidr_block"
        ],
        "op": "eq",
        "value": "10.0.49.0/24"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "vpc",
     "from": {
      "types": [
       "aws_subnet"
      ],
      "where": [
       {
        "path": [
         "cidr_block"
        ],
        "op": "eq",
        "value": "10.0.50.0/24"
       }
      ]
     }
    }
   ],
   "justify": "prompt gives cidrsubnet(10.0.0.0/16, 8, 48..50) = 10.0.48-50.0/24"
  },
  {
   "id": "private_routed_via_nat",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a single NAT gateway to service three private subnets",
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
   "justify": "a NAT gateway servicing private subnets implies a default 0.0.0.0/0 route"
  },
  {
   "id": "public_elb_tag",
   "kind": "any_of",
   "tier": "detail",
   "quote": "The public subnets must be tagged with \"kubernetes.io/role/elb\" set to 1",
   "checks": [
    {
     "kind": "attr",
     "select": "pub",
     "quantifier": "all",
     "cond": {
      "path": [
       "tags",
       "kubernetes.io/role/elb"
      ],
      "op": "eq",
      "value": "1"
     }
    },
    {
     "kind": "attr",
     "select": "pub",
     "quantifier": "all",
     "cond": {
      "path": [
       "tags_all",
       "kubernetes.io/role/elb"
      ],
      "op": "eq",
      "value": "1"
     }
    }
   ],
   "justify": "selector CIDRs are the prompt-stated public subnets (netnums 48-50)"
  },
  {
   "id": "private_internal_elb_tag",
   "kind": "any_of",
   "tier": "detail",
   "quote": "the private subnets tagged with \"kubernetes.io/role/internal-elb\" set to 1",
   "checks": [
    {
     "kind": "attr",
     "select": "priv",
     "quantifier": "all",
     "cond": {
      "path": [
       "tags",
       "kubernetes.io/role/internal-elb"
      ],
      "op": "eq",
      "value": "1"
     }
    },
    {
     "kind": "attr",
     "select": "priv",
     "quantifier": "all",
     "cond": {
      "path": [
       "tags_all",
       "kubernetes.io/role/internal-elb"
      ],
      "op": "eq",
      "value": "1"
     }
    }
   ],
   "justify": "selector CIDRs are the prompt-stated private subnets (netnums 0-2)"
  },
  {
   "id": "githubrepo_tag",
   "kind": "any_of",
   "tier": "detail",
   "quote": "GithubRepo set to \"github.com/aws-ia/terraform-aws-eks-blueprints\"",
   "checks": [
    {
     "kind": "attr",
     "select": "vpc_res",
     "quantifier": "all",
     "cond": {
      "path": [
       "tags",
       "GithubRepo"
      ],
      "op": "eq",
      "value": "github.com/aws-ia/terraform-aws-eks-blueprints"
     }
    },
    {
     "kind": "attr",
     "select": "vpc_res",
     "quantifier": "all",
     "cond": {
      "path": [
       "tags_all",
       "GithubRepo"
      ],
      "op": "eq",
      "value": "github.com/aws-ia/terraform-aws-eks-blueprints"
     }
    }
   ]
  },
  {
   "id": "blueprint_tag",
   "kind": "any_of",
   "tier": "detail",
   "quote": "tagged with Blueprint matching the VPC name",
   "checks": [
    {
     "kind": "join",
     "from": {
      "types": [
       "aws_subnet",
       "aws_nat_gateway",
       "aws_route_table",
       "aws_internet_gateway"
      ],
      "where": []
     },
     "from_path": [
      "tags",
      "Blueprint"
     ],
     "to": "vpc",
     "to_path": [
      "tags",
      "Name"
     ]
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "aws_subnet",
       "aws_nat_gateway",
       "aws_route_table",
       "aws_internet_gateway"
      ],
      "where": []
     },
     "from_path": [
      "tags_all",
      "Blueprint"
     ],
     "to": "vpc",
     "to_path": [
      "tags_all",
      "Name"
     ]
    }
   ]
  },
  {
   "id": "sg1_named",
   "kind": "exists",
   "select": "sg1",
   "tier": "core",
   "quote": "named \"cluster1_additional_sg\""
  },
  {
   "id": "sg2_named",
   "kind": "exists",
   "select": "sg2",
   "tier": "core",
   "quote": "\"cluster2_additional_sg\""
  },
  {
   "id": "sgs_in_vpc",
   "kind": "all_of",
   "tier": "detail",
   "quote": "two dedicated security groups within the VPC",
   "checks": [
    {
     "kind": "ref",
     "from": "sg1",
     "to": "vpc"
    },
    {
     "kind": "ref",
     "from": "sg2",
     "to": "vpc"
    }
   ]
  },
  {
   "id": "sg1_ingress_from_sg2",
   "kind": "any_of",
   "tier": "core",
   "quote": "ingress and egress rules allowing all protocols only to and from the other cluster's security group",
   "checks": [
    {
     "kind": "ref",
     "to": "sg1",
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [
         "ip_protocol"
        ],
        "op": "eq",
        "value": "-1"
       },
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "absent"
       },
       {
        "path": [
         "cidr_ipv6"
        ],
        "op": "absent"
       },
       {
        "path": [
         "prefix_list_id"
        ],
        "op": "absent"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "sg1",
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
        "op": "absent"
       },
       {
        "path": [
         "ipv6_cidr_blocks",
         "*"
        ],
        "op": "absent"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "sg2",
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
        "value": "cluster1_additional_sg"
       },
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
          "op": "absent"
         }
        ]
       }
      ]
     }
    }
   ]
  },
  {
   "id": "sg2_ingress_from_sg1",
   "kind": "any_of",
   "tier": "core",
   "quote": "ingress and egress rules allowing all protocols only to and from the other cluster's security group",
   "checks": [
    {
     "kind": "ref",
     "to": "sg2",
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [
         "ip_protocol"
        ],
        "op": "eq",
        "value": "-1"
       },
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "absent"
       },
       {
        "path": [
         "cidr_ipv6"
        ],
        "op": "absent"
       },
       {
        "path": [
         "prefix_list_id"
        ],
        "op": "absent"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "sg2",
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
        "op": "absent"
       },
       {
        "path": [
         "ipv6_cidr_blocks",
         "*"
        ],
        "op": "absent"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "sg1",
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
        "value": "cluster2_additional_sg"
       },
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
          "op": "absent"
         }
        ]
       }
      ]
     }
    }
   ]
  },
  {
   "id": "sg1_egress_to_sg2",
   "kind": "any_of",
   "tier": "detail",
   "quote": "ingress and egress rules allowing all protocols only to and from the other cluster's security group",
   "checks": [
    {
     "kind": "ref",
     "to": "sg1",
     "from": {
      "types": [
       "aws_vpc_security_group_egress_rule"
      ],
      "where": [
       {
        "path": [
         "ip_protocol"
        ],
        "op": "eq",
        "value": "-1"
       },
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "absent"
       },
       {
        "path": [
         "cidr_ipv6"
        ],
        "op": "absent"
       },
       {
        "path": [
         "prefix_list_id"
        ],
        "op": "absent"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "sg1",
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
        "op": "absent"
       },
       {
        "path": [
         "ipv6_cidr_blocks",
         "*"
        ],
        "op": "absent"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "sg2",
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
        "value": "cluster1_additional_sg"
       },
       {
        "path": [
         "egress",
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
          "op": "absent"
         }
        ]
       }
      ]
     }
    }
   ]
  },
  {
   "id": "sg2_egress_to_sg1",
   "kind": "any_of",
   "tier": "detail",
   "quote": "ingress and egress rules allowing all protocols only to and from the other cluster's security group",
   "checks": [
    {
     "kind": "ref",
     "to": "sg2",
     "from": {
      "types": [
       "aws_vpc_security_group_egress_rule"
      ],
      "where": [
       {
        "path": [
         "ip_protocol"
        ],
        "op": "eq",
        "value": "-1"
       },
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "absent"
       },
       {
        "path": [
         "cidr_ipv6"
        ],
        "op": "absent"
       },
       {
        "path": [
         "prefix_list_id"
        ],
        "op": "absent"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "sg2",
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
        "op": "absent"
       },
       {
        "path": [
         "ipv6_cidr_blocks",
         "*"
        ],
        "op": "absent"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "sg1",
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
        "value": "cluster2_additional_sg"
       },
       {
        "path": [
         "egress",
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
          "op": "absent"
         }
        ]
       }
      ]
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
