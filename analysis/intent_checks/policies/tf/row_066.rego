package intent.tf.row_066

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
   "quote": "creates a dedicated VPC (10.0.0.0/16)"
  },
  {
   "id": "vpc_cidr",
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
    "op": "eq",
    "value": "10.0.0.0/16"
   },
   "quote": "creates a dedicated VPC (10.0.0.0/16)"
  },
  {
   "id": "subnet",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "quote": "with a subnet (10.0.0.0/24)"
  },
  {
   "id": "subnet_cidr",
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
     "cidr_block"
    ],
    "op": "eq",
    "value": "10.0.0.0/24"
   },
   "quote": "with a subnet (10.0.0.0/24)"
  },
  {
   "id": "subnet_no_public_ip",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
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
        "value": "10.0.0.0/24"
       }
      ]
     },
     "cond": {
      "path": [
       "map_public_ip_on_launch"
      ],
      "op": "falsy"
     }
    },
    {
     "kind": "attr",
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
        "value": "10.0.0.0/24"
       }
      ]
     },
     "cond": {
      "path": [
       "map_public_ip_on_launch"
      ],
      "op": "absent"
     }
    }
   ],
   "quote": "that does not auto-assign public IP addresses"
  },
  {
   "id": "subnet_in_vpc",
   "kind": "ref",
   "tier": "detail",
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
      "value": "10.0.0.0/24"
     }
    ]
   },
   "to": {
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
   "quote": "with a subnet (10.0.0.0/24)"
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
   "quote": "an internet gateway"
  },
  {
   "id": "igw_in_vpc",
   "kind": "ref",
   "tier": "detail",
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
   "quote": "an internet gateway"
  },
  {
   "id": "default_route_via_igw",
   "kind": "any_of",
   "tier": "core",
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
    }
   ],
   "quote": "a route table sending default traffic through that gateway",
   "justify": "default traffic means 0.0.0.0/0"
  },
  {
   "id": "sg_named",
   "kind": "exists",
   "tier": "core",
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
      "value": "dragondrop-compute-ecs-fargate-sg"
     }
    ]
   },
   "quote": "a security group named \"dragondrop-compute-ecs-fargate-sg\""
  },
  {
   "id": "sg_in_vpc",
   "kind": "ref",
   "tier": "detail",
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
      "value": "dragondrop-compute-ecs-fargate-sg"
     }
    ]
   },
   "to": {
    "types": [
     "aws_vpc"
    ],
    "where": []
   },
   "quote": "a security group named \"dragondrop-compute-ecs-fargate-sg\""
  },
  {
   "id": "egress_vpc_cidr",
   "kind": "any_of",
   "tier": "core",
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
        "value": "dragondrop-compute-ecs-fargate-sg"
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
     },
     "quantifier": "all"
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
   "quote": "allowing outbound access only within the VPC CIDR",
   "justify": "VPC CIDR is 10.0.0.0/16 per the prompt; 'only' means every egress CIDR is the VPC CIDR"
  },
  {
   "id": "vpc_dns_support",
   "kind": "attr",
   "tier": "extra",
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
