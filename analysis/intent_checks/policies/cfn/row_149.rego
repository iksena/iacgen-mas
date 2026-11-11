package intent.cfn.row_149

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "vpc": {
   "types": [
    "AWS::EC2::VPC"
   ],
   "where": []
  },
  "subnet": {
   "types": [
    "AWS::EC2::Subnet"
   ],
   "where": []
  },
  "igw": {
   "types": [
    "AWS::EC2::InternetGateway"
   ],
   "where": []
  },
  "attach": {
   "types": [
    "AWS::EC2::VPCGatewayAttachment"
   ],
   "where": []
  },
  "rt": {
   "types": [
    "AWS::EC2::RouteTable"
   ],
   "where": []
  },
  "default_route": {
   "types": [
    "AWS::EC2::Route"
   ],
   "where": [
    {
     "path": [
      "DestinationCidrBlock"
     ],
     "op": "eq",
     "value": "0.0.0.0/0"
    }
   ]
  },
  "rt_assoc": {
   "types": [
    "AWS::EC2::SubnetRouteTableAssociation"
   ],
   "where": []
  },
  "nacl": {
   "types": [
    "AWS::EC2::NetworkAcl"
   ],
   "where": []
  },
  "nacl_assoc": {
   "types": [
    "AWS::EC2::SubnetNetworkAclAssociation"
   ],
   "where": []
  },
  "entry": {
   "types": [
    "AWS::EC2::NetworkAclEntry"
   ],
   "where": []
  },
  "cidr_param": {
   "types": [
    "__parameter__"
   ],
   "where": [
    {
     "path": [
      "default"
     ],
     "op": "regex",
     "value": "^172\\.18(\\.0\\.0(/16)?)?$"
    }
   ]
  },
  "octet_param": {
   "types": [
    "__parameter__"
   ],
   "where": [
    {
     "path": [
      "default"
     ],
     "op": "eq",
     "value": "18"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "vpc",
   "tier": "core",
   "kind": "exists",
   "select": "vpc",
   "quote": "creates a basic VPC"
  },
  {
   "id": "vpc_default_cidr",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "vpc",
     "cond": {
      "path": [
       "CidrBlock"
      ],
      "op": "eq",
      "value": "172.18.0.0/16"
     }
    },
    {
     "kind": "attr",
     "select": "vpc",
     "cond": {
      "path": [
       "CidrBlock"
      ],
      "op": "regex",
      "value": "FindInMap.*\\b18\\b"
     }
    }
   ],
   "quote": "defaulting to 172.18.0.0/16",
   "justify": "a mapping keyed by the second octet (default 18) also yields 172.18.0.0/16"
  },
  {
   "id": "cidr_param_allowed",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "cidr_param",
     "cond": {
      "path": [
       "allowed_values",
       "*"
      ],
      "op": "regex",
      "value": "^172\\.(18|19|20|21|22|23)(\\.0\\.0(/16)?)?$",
      "every": true
     }
    },
    {
     "kind": "attr",
     "select": "octet_param",
     "cond": {
      "path": [
       "allowed_values",
       "*"
      ],
      "op": "regex",
      "value": "^(18|19|20|21|22|23)$",
      "every": true
     }
    }
   ],
   "quote": "selectable from a fixed set of /16 ranges between 172.18.0.0/16 and 172.23.0.0/16",
   "justify": "range 172.18-172.23 stated in prompt; second-octet selector 18-23 accepted"
  },
  {
   "id": "cidr_param_six",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "cidr_param",
     "cond": {
      "path": [
       "allowed_values"
      ],
      "op": "len_gte",
      "value": 6
     }
    },
    {
     "kind": "attr",
     "select": "octet_param",
     "cond": {
      "path": [
       "allowed_values"
      ],
      "op": "len_gte",
      "value": 6
     }
    }
   ],
   "quote": "selectable from a fixed set of /16 ranges between 172.18.0.0/16 and 172.23.0.0/16",
   "justify": "172.18 to 172.23 inclusive is six ranges"
  },
  {
   "id": "subnet",
   "tier": "core",
   "kind": "exists",
   "select": "subnet",
   "quote": "with a single public subnet",
   "max": 1,
   "justify": "a single subnet means exactly one"
  },
  {
   "id": "subnet_in_vpc",
   "tier": "core",
   "kind": "ref",
   "from": "subnet",
   "to": "vpc",
   "quote": "with a single public subnet for testing purposes"
  },
  {
   "id": "subnet_in_default_range",
   "tier": "detail",
   "kind": "attr",
   "select": "subnet",
   "cond": {
    "path": [
     "CidrBlock"
    ],
    "op": "regex",
    "value": "172\\.18\\.|FindInMap.*\\b18\\b"
   },
   "quote": "with the public subnet carved out as the corresponding /22 block",
   "justify": "the block corresponding to the default 172.18.0.0/16 range sits inside it; the /22 mask itself is not tested, see notes"
  },
  {
   "id": "igw",
   "tier": "core",
   "kind": "exists",
   "select": "igw",
   "quote": "Attach an internet gateway to the VPC"
  },
  {
   "id": "igw_attached",
   "tier": "core",
   "kind": "ref",
   "from": "attach",
   "to": "igw",
   "quote": "Attach an internet gateway to the VPC"
  },
  {
   "id": "igw_attached_vpc",
   "tier": "core",
   "kind": "ref",
   "from": "attach",
   "to": "vpc",
   "quote": "Attach an internet gateway to the VPC"
  },
  {
   "id": "route_table",
   "tier": "core",
   "kind": "exists",
   "select": "rt",
   "quote": "create a public route table"
  },
  {
   "id": "default_route",
   "tier": "core",
   "kind": "ref",
   "from": "default_route",
   "to": "igw",
   "quote": "a default route to the internet gateway",
   "justify": "default route means 0.0.0.0/0"
  },
  {
   "id": "default_route_in_rt",
   "tier": "core",
   "kind": "ref",
   "from": "default_route",
   "to": "rt",
   "quote": "create a public route table with a default route to the internet gateway",
   "justify": "default route means 0.0.0.0/0"
  },
  {
   "id": "rt_assoc_subnet",
   "tier": "core",
   "kind": "ref",
   "from": "rt_assoc",
   "to": "subnet",
   "quote": "associate it with the subnet"
  },
  {
   "id": "rt_assoc_rt",
   "tier": "core",
   "kind": "ref",
   "from": "rt_assoc",
   "to": "rt",
   "quote": "associate it with the subnet"
  },
  {
   "id": "nacl",
   "tier": "core",
   "kind": "exists",
   "select": "nacl",
   "quote": "create a network ACL for the subnet"
  },
  {
   "id": "nacl_assoc",
   "tier": "core",
   "kind": "ref",
   "from": "nacl_assoc",
   "to": "nacl",
   "quote": "create a network ACL for the subnet"
  },
  {
   "id": "nacl_assoc_subnet",
   "tier": "core",
   "kind": "ref",
   "from": "nacl_assoc",
   "to": "subnet",
   "quote": "create a network ACL for the subnet"
  },
  {
   "id": "nacl_in_tcp",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "entry",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Egress"
        ],
        "op": "none_eq",
        "value": "true"
       },
       {
        "path": [
         "RuleAction"
        ],
        "op": "eq",
        "value": "allow"
       },
       {
        "path": [
         "CidrBlock"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       },
       {
        "path": [
         "Protocol"
        ],
        "op": "in",
        "value": [
         "6",
         "tcp"
        ]
       },
       {
        "path": [
         "PortRange",
         "From"
        ],
        "op": "lte",
        "value": 1
       },
       {
        "path": [
         "PortRange",
         "To"
        ],
        "op": "gte",
        "value": 65535
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "entry",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Egress"
        ],
        "op": "none_eq",
        "value": "true"
       },
       {
        "path": [
         "RuleAction"
        ],
        "op": "eq",
        "value": "allow"
       },
       {
        "path": [
         "CidrBlock"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       },
       {
        "path": [
         "Protocol"
        ],
        "op": "in",
        "value": [
         "-1",
         "all"
        ]
       }
      ]
     }
    }
   ],
   "quote": "a network ACL for the subnet that allows all inbound and outbound TCP and UDP traffic",
   "justify": "all TCP = every port, any source; a range starting at 0 or 1 covers every usable port"
  },
  {
   "id": "nacl_out_tcp",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "entry",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Egress"
        ],
        "op": "eq",
        "value": true
       },
       {
        "path": [
         "RuleAction"
        ],
        "op": "eq",
        "value": "allow"
       },
       {
        "path": [
         "CidrBlock"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       },
       {
        "path": [
         "Protocol"
        ],
        "op": "in",
        "value": [
         "6",
         "tcp"
        ]
       },
       {
        "path": [
         "PortRange",
         "From"
        ],
        "op": "lte",
        "value": 1
       },
       {
        "path": [
         "PortRange",
         "To"
        ],
        "op": "gte",
        "value": 65535
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "entry",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Egress"
        ],
        "op": "eq",
        "value": true
       },
       {
        "path": [
         "RuleAction"
        ],
        "op": "eq",
        "value": "allow"
       },
       {
        "path": [
         "CidrBlock"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       },
       {
        "path": [
         "Protocol"
        ],
        "op": "in",
        "value": [
         "-1",
         "all"
        ]
       }
      ]
     }
    }
   ],
   "quote": "a network ACL for the subnet that allows all inbound and outbound TCP and UDP traffic",
   "justify": "all TCP = every port, any destination; a range starting at 0 or 1 covers every usable port"
  },
  {
   "id": "nacl_in_udp",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "entry",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Egress"
        ],
        "op": "none_eq",
        "value": "true"
       },
       {
        "path": [
         "RuleAction"
        ],
        "op": "eq",
        "value": "allow"
       },
       {
        "path": [
         "CidrBlock"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       },
       {
        "path": [
         "Protocol"
        ],
        "op": "in",
        "value": [
         "17",
         "udp"
        ]
       },
       {
        "path": [
         "PortRange",
         "From"
        ],
        "op": "lte",
        "value": 1
       },
       {
        "path": [
         "PortRange",
         "To"
        ],
        "op": "gte",
        "value": 65535
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "entry",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Egress"
        ],
        "op": "none_eq",
        "value": "true"
       },
       {
        "path": [
         "RuleAction"
        ],
        "op": "eq",
        "value": "allow"
       },
       {
        "path": [
         "CidrBlock"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       },
       {
        "path": [
         "Protocol"
        ],
        "op": "in",
        "value": [
         "-1",
         "all"
        ]
       }
      ]
     }
    }
   ],
   "quote": "a network ACL for the subnet that allows all inbound and outbound TCP and UDP traffic",
   "justify": "all UDP = every port, any source; a range starting at 0 or 1 covers every usable port"
  },
  {
   "id": "nacl_out_udp",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "entry",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Egress"
        ],
        "op": "eq",
        "value": true
       },
       {
        "path": [
         "RuleAction"
        ],
        "op": "eq",
        "value": "allow"
       },
       {
        "path": [
         "CidrBlock"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       },
       {
        "path": [
         "Protocol"
        ],
        "op": "in",
        "value": [
         "17",
         "udp"
        ]
       },
       {
        "path": [
         "PortRange",
         "From"
        ],
        "op": "lte",
        "value": 1
       },
       {
        "path": [
         "PortRange",
         "To"
        ],
        "op": "gte",
        "value": 65535
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "entry",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Egress"
        ],
        "op": "eq",
        "value": true
       },
       {
        "path": [
         "RuleAction"
        ],
        "op": "eq",
        "value": "allow"
       },
       {
        "path": [
         "CidrBlock"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       },
       {
        "path": [
         "Protocol"
        ],
        "op": "in",
        "value": [
         "-1",
         "all"
        ]
       }
      ]
     }
    }
   ],
   "quote": "a network ACL for the subnet that allows all inbound and outbound TCP and UDP traffic",
   "justify": "all UDP = every port, any destination; a range starting at 0 or 1 covers every usable port"
  },
  {
   "id": "tag_vpc",
   "tier": "detail",
   "kind": "attr",
   "select": "vpc",
   "cond": {
    "path": [
     "Tags"
    ],
    "op": "present"
   },
   "quantifier": "all",
   "quote": "tag the VPC, subnet, internet gateway, and route table resources appropriately"
  },
  {
   "id": "tag_subnet",
   "tier": "detail",
   "kind": "attr",
   "select": "subnet",
   "cond": {
    "path": [
     "Tags"
    ],
    "op": "present"
   },
   "quantifier": "all",
   "quote": "tag the VPC, subnet, internet gateway, and route table resources appropriately"
  },
  {
   "id": "tag_igw",
   "tier": "detail",
   "kind": "attr",
   "select": "igw",
   "cond": {
    "path": [
     "Tags"
    ],
    "op": "present"
   },
   "quantifier": "all",
   "quote": "tag the VPC, subnet, internet gateway, and route table resources appropriately"
  },
  {
   "id": "tag_rt",
   "tier": "detail",
   "kind": "attr",
   "select": "rt",
   "cond": {
    "path": [
     "Tags"
    ],
    "op": "present"
   },
   "quantifier": "all",
   "quote": "tag the VPC, subnet, internet gateway, and route table resources appropriately"
  },
  {
   "id": "x_route_depends",
   "tier": "extra",
   "kind": "attr",
   "select": "default_route",
   "cond": {
    "path": [
     "__resource__",
     "DependsOn"
    ],
    "op": "present"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
