# GENERATED from specs/tf/row_003.json by intent_checks/build.py -- do not edit.
package intent.tf.row_003

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
  "alb_sg": {
   "types": [
    "aws_security_group"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "regex",
     "value": "(?i)(^|[-_])alb([-_]|$)"
    }
   ]
  },
  "app_sg": {
   "types": [
    "aws_security_group"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "regex",
     "value": "(?i)allow[-_]?alb"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "vpc_cidr",
   "kind": "exists",
   "select": "vpc",
   "tier": "core",
   "quote": "inside a new VPC with a 10.0.0.0/16 CIDR block"
  },
  {
   "id": "alb_sg_named",
   "kind": "exists",
   "select": "alb_sg",
   "tier": "core",
   "quote": "The first security group, named \"alb\"",
   "justify": "\"named alb\"/\"allow_alb\": the name may carry a project prefix/suffix"
  },
  {
   "id": "app_sg_named",
   "kind": "exists",
   "select": "app_sg",
   "tier": "core",
   "quote": "The second security group, named \"allow_alb\"",
   "justify": "\"named alb\"/\"allow_alb\": the name may carry a project prefix/suffix"
  },
  {
   "id": "sgs_in_vpc",
   "kind": "all_of",
   "tier": "detail",
   "quote": "inside a new VPC",
   "checks": [
    {
     "kind": "ref",
     "from": "alb_sg",
     "to": "vpc"
    },
    {
     "kind": "ref",
     "from": "app_sg",
     "to": "vpc"
    }
   ]
  },
  {
   "id": "alb_http_from_anywhere",
   "kind": "any_of",
   "tier": "core",
   "quote": "accept inbound HTTP traffic on port 80 from any IP address",
   "checks": [
    {
     "kind": "attr",
     "select": "alb_sg",
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
     "to": "alb_sg",
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
     "to": "alb_sg",
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
   "justify": "\"from any IP address\" implies 0.0.0.0/0"
  },
  {
   "id": "alb_egress_within_vpc",
   "kind": "any_of",
   "tier": "core",
   "quote": "permit outbound traffic only within the VPC CIDR",
   "checks": [
    {
     "kind": "attr",
     "select": "alb_sg",
     "cond": {
      "path": [
       "egress",
       "*",
       "cidr_blocks",
       "*"
      ],
      "op": "eq",
      "value": "10.0.0.0/16"
     }
    },
    {
     "kind": "ref",
     "to": "alb_sg",
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
     "to": "alb_sg",
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
   ]
  },
  {
   "id": "alb_no_open_egress",
   "kind": "attr",
   "select": "alb_sg",
   "tier": "detail",
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
   "quote": "permit outbound traffic only within the VPC CIDR",
   "justify": "\"only within the VPC CIDR\" implies no 0.0.0.0/0 egress"
  },
  {
   "id": "app_http_from_alb_sg",
   "kind": "any_of",
   "tier": "core",
   "quote": "accept inbound HTTP traffic on port 80 exclusively from the ALB security group",
   "checks": [
    {
     "kind": "ref",
     "to": "alb_sg",
     "from": {
      "types": [
       "aws_security_group"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)allow[-_]?alb"
       },
       {
        "path": [
         "ingress",
         "*"
        ],
        "op": "port_covers",
        "value": 80
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "alb_sg",
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
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "alb_sg",
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [],
        "op": "port_covers",
        "value": 80
       }
      ]
     }
    }
   ]
  },
  {
   "id": "app_no_cidr_ingress",
   "kind": "attr",
   "select": "app_sg",
   "tier": "detail",
   "cond": {
    "path": [
     "ingress",
     "*",
     "cidr_blocks",
     "*"
    ],
    "op": "none_eq",
    "value": "0.0.0.0/0"
   },
   "quote": "exclusively from the ALB security group",
   "justify": "\"exclusively from the ALB security group\" implies no 0.0.0.0/0 ingress"
  },
  {
   "id": "app_egress_within_vpc",
   "kind": "any_of",
   "tier": "core",
   "quote": "allowing outbound traffic only within the VPC CIDR",
   "checks": [
    {
     "kind": "attr",
     "select": "app_sg",
     "cond": {
      "path": [
       "egress",
       "*",
       "cidr_blocks",
       "*"
      ],
      "op": "eq",
      "value": "10.0.0.0/16"
     }
    },
    {
     "kind": "ref",
     "to": "app_sg",
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
     "to": "app_sg",
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
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
