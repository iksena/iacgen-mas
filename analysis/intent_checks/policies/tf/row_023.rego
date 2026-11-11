package intent.tf.row_023

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
  "subnet": {
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
  },
  "igw": {
   "types": [
    "aws_internet_gateway"
   ],
   "where": []
  },
  "rt": {
   "types": [
    "aws_route_table"
   ],
   "where": []
  },
  "assoc": {
   "types": [
    "aws_route_table_association"
   ],
   "where": []
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
     "value": "example"
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
   "id": "subnet",
   "kind": "exists",
   "select": "subnet",
   "tier": "core",
   "quote": "a subnet with a CIDR block of 10.0.1.0/24"
  },
  {
   "id": "subnet_in_vpc",
   "kind": "ref",
   "from": "subnet",
   "to": "vpc",
   "tier": "core",
   "quote": "containing a subnet"
  },
  {
   "id": "igw",
   "kind": "exists",
   "select": "igw",
   "tier": "core",
   "quote": "attach an internet gateway to the VPC"
  },
  {
   "id": "igw_attached",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "igw",
     "to": "vpc"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_internet_gateway_attachment"
      ],
      "where": []
     },
     "to": "vpc"
    }
   ],
   "tier": "core",
   "quote": "attach an internet gateway to the VPC"
  },
  {
   "id": "route_table",
   "kind": "exists",
   "select": "rt",
   "tier": "core",
   "quote": "configure a route table"
  },
  {
   "id": "default_route_to_igw",
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
     "to": "igw"
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
     "to": "igw"
    }
   ],
   "tier": "core",
   "quote": "routes all outbound traffic to the internet gateway",
   "justify": "all outbound traffic means the default route 0.0.0.0/0"
  },
  {
   "id": "assoc_to_subnet",
   "kind": "ref",
   "from": "assoc",
   "to": "subnet",
   "tier": "core",
   "quote": "a route table associated with the subnet"
  },
  {
   "id": "assoc_to_route_table",
   "kind": "ref",
   "from": "assoc",
   "to": "rt",
   "tier": "core",
   "quote": "a route table associated with the subnet"
  },
  {
   "id": "security_group",
   "kind": "exists",
   "select": "sg",
   "tier": "core",
   "quote": "a security group named \"example\""
  },
  {
   "id": "sg_description",
   "kind": "attr",
   "select": "sg",
   "cond": {
    "path": [
     "description"
    ],
    "op": "eq",
    "value": "Example security group"
   },
   "tier": "detail",
   "quote": "with the description \"Example security group\""
  },
  {
   "id": "sg_in_vpc",
   "kind": "ref",
   "from": "sg",
   "to": "vpc",
   "tier": "detail",
   "quote": "security group named \"example\""
  },
  {
   "id": "ssh_ingress",
   "kind": "any_of",
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
         "from_port"
        ],
        "op": "eq",
        "value": 22
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 22
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
        "value": "10.0.0.0/16"
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
        "value": 22
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 22
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
        "value": "10.0.0.0/16"
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
        "value": 22
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 22
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
        "value": "10.0.0.0/16"
       }
      ]
     },
     "to": "sg"
    }
   ],
   "tier": "core",
   "quote": "allow inbound SSH traffic on port 22 only from within the VPC CIDR block",
   "justify": "SSH is TCP port 22; the VPC CIDR is 10.0.0.0/16"
  },
  {
   "id": "ingress_only_vpc",
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
        "value": "example"
       },
       {
        "path": [
         "ingress",
         "*",
         "ipv6_cidr_blocks",
         "*"
        ],
        "op": "none_eq",
        "value": "::/0"
       }
      ]
     },
     "cond": {
      "path": [
       "ingress",
       "*",
       "cidr_blocks",
       "*"
      ],
      "op": "eq",
      "value": "10.0.0.0/16",
      "every": true
     }
    },
    {
     "kind": "attr",
     "quantifier": "all",
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
       "cidr_blocks",
       "*"
      ],
      "op": "eq",
      "value": "10.0.0.0/16",
      "every": true
     }
    },
    {
     "kind": "attr",
     "quantifier": "all",
     "select": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "cidr_ipv4"
      ],
      "op": "eq",
      "value": "10.0.0.0/16"
     }
    }
   ],
   "tier": "core",
   "quote": "only from within the VPC CIDR block",
   "justify": "the VPC CIDR is 10.0.0.0/16"
  },
  {
   "id": "egress_only_vpc",
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
        "value": "example"
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
     }
    },
    {
     "kind": "attr",
     "quantifier": "all",
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
     }
    },
    {
     "kind": "attr",
     "quantifier": "all",
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
      "value": "10.0.0.0/16"
     }
    }
   ],
   "tier": "core",
   "quote": "outbound traffic only within the VPC CIDR block",
   "justify": "the VPC CIDR is 10.0.0.0/16"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
