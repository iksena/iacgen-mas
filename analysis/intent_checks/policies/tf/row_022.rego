package intent.tf.row_022

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
     "value": "Example security group"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "vpc",
   "kind": "exists",
   "select": "vpc",
   "tier": "core",
   "quote": "a VPC with a CIDR block of 10.0.0.0/16"
  },
  {
   "id": "security_group",
   "kind": "exists",
   "select": "sg",
   "tier": "core",
   "quote": "a security group named \"Example security group\""
  },
  {
   "id": "sg_in_vpc",
   "kind": "ref",
   "from": "sg",
   "to": "vpc",
   "tier": "core",
   "quote": "Within this VPC, provision a security group"
  },
  {
   "id": "ingress_443",
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
        "value": "Example security group"
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
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
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
         "from_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
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
     },
     "to": "sg"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
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
     },
     "to": "sg"
    }
   ],
   "tier": "core",
   "quote": "allowing incoming TCP traffic on port 443",
   "justify": "any IP address is 0.0.0.0/0, TCP given"
  },
  {
   "id": "ingress_80",
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
        "value": "Example security group"
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
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 80
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
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
         "from_port"
        ],
        "op": "eq",
        "value": 80
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
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
     },
     "to": "sg"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 80
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
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
     },
     "to": "sg"
    }
   ],
   "tier": "core",
   "quote": "port 443 and port 80 from any IP address (0.0.0.0/0)"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
