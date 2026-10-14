# GENERATED from specs/tf/row_122.json by intent_checks/build.py -- do not edit.
package intent.tf.row_122

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "alb": {
   "types": [
    "aws_lb",
    "aws_alb"
   ],
   "where": [
    {
     "path": [
      "load_balancer_type"
     ],
     "op": "eq",
     "value": "application"
    }
   ]
  },
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
  "subnet": {
   "types": [
    "aws_subnet"
   ],
   "where": []
  },
  "sg": {
   "types": [
    "aws_security_group"
   ],
   "where": []
  },
  "tg": {
   "types": [
    "aws_lb_target_group",
    "aws_alb_target_group"
   ],
   "where": [
    {
     "path": [
      "port"
     ],
     "op": "eq",
     "value": 8080
    },
    {
     "path": [
      "protocol"
     ],
     "op": "eq",
     "value": "HTTP"
    }
   ]
  },
  "https_listener": {
   "types": [
    "aws_lb_listener",
    "aws_alb_listener"
   ],
   "where": [
    {
     "path": [
      "port"
     ],
     "op": "eq",
     "value": 443
    },
    {
     "path": [
      "protocol"
     ],
     "op": "eq",
     "value": "HTTPS"
    }
   ]
  },
  "rule": {
   "types": [
    "aws_lb_listener_rule",
    "aws_alb_listener_rule"
   ],
   "where": []
  },
  "acm": {
   "types": [
    "aws_acm_certificate"
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
   "quote": "within a VPC having the CIDR block \"10.0.0.0/16\""
  },
  {
   "id": "two_subnets_two_azs",
   "kind": "exists",
   "select": "subnet",
   "min": 2,
   "distinct_path": [
    "availability_zone"
   ],
   "tier": "core",
   "quote": "two subnets distributed across the first two available availability zones",
   "justify": "two subnets across two availability zones"
  },
  {
   "id": "subnets_slash24",
   "kind": "attr",
   "select": "subnet",
   "quantifier": "all",
   "tier": "detail",
   "quote": "using calculated /24 CIDR blocks",
   "cond": {
    "path": [
     "cidr_block"
    ],
    "op": "regex",
    "value": "^10\\.0\\.\\d{1,3}\\.0/24$"
   },
   "justify": "/24 blocks carved from the stated 10.0.0.0/16 VPC"
  },
  {
   "id": "internal_alb",
   "kind": "attr",
   "select": "alb",
   "tier": "core",
   "quote": "Deploy an internal Application Load Balancer",
   "cond": {
    "path": [
     "internal"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "alb_drops_invalid_headers",
   "kind": "attr",
   "select": "alb",
   "tier": "core",
   "quote": "drops invalid header fields",
   "cond": {
    "path": [
     "drop_invalid_header_fields"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "alb_uses_security_group",
   "kind": "ref",
   "from": "alb",
   "to": "sg",
   "tier": "detail",
   "quote": "using a security group"
  },
  {
   "id": "sg_ingress_all_within_vpc",
   "kind": "any_of",
   "tier": "core",
   "quote": "allows all ingress and egress traffic within the VPC CIDR",
   "justify": "all traffic = protocol -1; VPC CIDR is the stated 10.0.0.0/16",
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
        "op": "eq",
        "value": "10.0.0.0/16"
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
      "where": []
     },
     "cond": {
      "path": [],
      "op": "match",
      "value": [
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
        "op": "eq",
        "value": "10.0.0.0/16"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": []
     },
     "cond": {
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
        "op": "eq",
        "value": "10.0.0.0/16"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "sg_egress_all_within_vpc",
   "kind": "any_of",
   "tier": "core",
   "quote": "allows all ingress and egress traffic within the VPC CIDR",
   "justify": "all traffic = protocol -1; VPC CIDR is the stated 10.0.0.0/16",
   "checks": [
    {
     "kind": "attr",
     "select": "sg",
     "cond": {
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
        "op": "eq",
        "value": "10.0.0.0/16"
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
      "where": []
     },
     "cond": {
      "path": [],
      "op": "match",
      "value": [
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
        "op": "eq",
        "value": "10.0.0.0/16"
       }
      ]
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
        "op": "eq",
        "value": "10.0.0.0/16"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "http_target_group_8080",
   "kind": "exists",
   "select": "tg",
   "tier": "core",
   "quote": "an HTTP target group on port 8080"
  },
  {
   "id": "health_check_port_path",
   "kind": "attr",
   "select": "tg",
   "tier": "core",
   "quote": "an HTTP health check on port 8081 at path \"/health\"",
   "cond": {
    "path": [
     "health_check",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "port"
      ],
      "op": "eq",
      "value": "8081"
     },
     {
      "path": [
       "path"
      ],
      "op": "eq",
      "value": "/health"
     }
    ]
   }
  },
  {
   "id": "health_check_timings",
   "kind": "attr",
   "select": "tg",
   "tier": "detail",
   "quote": "with an interval of 60 seconds, a timeout of 3 seconds, a matcher of \"200-299\", and healthy/unhealthy thresholds of 3",
   "cond": {
    "path": [
     "health_check",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "interval"
      ],
      "op": "eq",
      "value": 60
     },
     {
      "path": [
       "timeout"
      ],
      "op": "eq",
      "value": 3
     },
     {
      "path": [
       "matcher"
      ],
      "op": "eq",
      "value": "200-299"
     },
     {
      "path": [
       "healthy_threshold"
      ],
      "op": "eq",
      "value": 3
     },
     {
      "path": [
       "unhealthy_threshold"
      ],
      "op": "eq",
      "value": 3
     }
    ]
   }
  },
  {
   "id": "https_listener_443_to_tg",
   "kind": "ref",
   "from": "https_listener",
   "to": "tg",
   "tier": "core",
   "quote": "an HTTPS listener on port 443"
  },
  {
   "id": "listener_on_alb",
   "kind": "ref",
   "from": "https_listener",
   "to": "alb",
   "tier": "detail",
   "quote": "an HTTPS listener on port 443"
  },
  {
   "id": "listener_tls13_policy",
   "kind": "attr",
   "select": "https_listener",
   "tier": "detail",
   "quote": "TLS 1.3 security policy",
   "cond": {
    "path": [
     "ssl_policy"
    ],
    "op": "regex",
    "value": "(?i)tls-?1[._-]?3"
   }
  },
  {
   "id": "self_signed_cert_in_acm",
   "kind": "ref",
   "from": "acm",
   "to": {
    "types": [
     "tls_self_signed_cert"
    ],
    "where": []
   },
   "tier": "core",
   "quote": "self-signed certificate imported into ACM"
  },
  {
   "id": "listener_uses_acm_cert",
   "kind": "ref",
   "from": "https_listener",
   "to": "acm",
   "tier": "detail",
   "quote": "self-signed certificate imported into ACM"
  },
  {
   "id": "listener_rule_static0_prio100",
   "kind": "attr",
   "select": "rule",
   "tier": "core",
   "quote": "forward traffic matching the path pattern \"/static-N/*\" (where N is the rule index, starting at 0) to the target group, starting at priority 100",
   "justify": "with the default count of 1 the single rule is index 0: /static-0/* at priority 100",
   "cond": {
    "path": [],
    "op": "match",
    "value": [
     {
      "path": [
       "priority"
      ],
      "op": "eq",
      "value": 100
     },
     {
      "path": [
       "condition",
       "*",
       "path_pattern",
       "*",
       "values",
       "*"
      ],
      "op": "eq",
      "value": "/static-0/*"
     }
    ]
   }
  },
  {
   "id": "listener_rule_forwards_to_tg",
   "kind": "ref",
   "from": "rule",
   "to": "tg",
   "tier": "detail",
   "quote": "to the target group"
  },
  {
   "id": "listener_rule_count_variable",
   "kind": "all_of",
   "tier": "detail",
   "quote": "governed by a resource count variable defaulting to 1",
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
        "op": "in",
        "value": [
         "aws_lb_listener_rule",
         "aws_alb_listener_rule"
        ]
       },
       {
        "path": [
         "gated"
        ],
        "op": "truthy"
       }
      ]
     }
    },
    {
     "kind": "exists",
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
        "value": "(?i)count"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": 1
       }
      ]
     }
    }
   ]
  },
  {
   "id": "resources_named_benchmark",
   "kind": "all_of",
   "tier": "detail",
   "quote": "All named resources must default to using the resource name \"benchmark\"",
   "checks": [
    {
     "kind": "attr",
     "select": "alb",
     "cond": {
      "path": [
       "name"
      ],
      "op": "contains",
      "value": "benchmark"
     }
    },
    {
     "kind": "attr",
     "select": "tg",
     "cond": {
      "path": [
       "name"
      ],
      "op": "contains",
      "value": "benchmark"
     }
    }
   ]
  },
  {
   "id": "region_variable_default",
   "kind": "exists",
   "tier": "detail",
   "quote": "the region variable must default to \"us-east-1\"",
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
      "value": "(?i)region"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "us-east-1"
     }
    ]
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
