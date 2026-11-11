package intent.tf.row_075

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
   "quote": "creates a VPC with CIDR block 192.168.0.0/16"
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
    "value": "192.168.0.0/16"
   },
   "quote": "creates a VPC with CIDR block 192.168.0.0/16"
  },
  {
   "id": "public_subnet_cidr",
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
    "value": "192.168.1.0/24"
   },
   "quote": "a public subnet (192.168.1.0/24)"
  },
  {
   "id": "private_subnet_cidr",
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
    "value": "192.168.4.0/24"
   },
   "quote": "a private subnet (192.168.4.0/24)"
  },
  {
   "id": "two_subnets",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "min": 2,
   "quote": "containing a public subnet (192.168.1.0/24) and a private subnet (192.168.4.0/24)"
  },
  {
   "id": "subnet_in_vpc",
   "kind": "all_of",
   "tier": "detail",
   "quote": "containing a public subnet",
   "checks": [
    {
     "kind": "ref",
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
        "value": "192.168.1.0/24"
       }
      ]
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
       "aws_subnet"
      ],
      "where": [
       {
        "path": [
         "cidr_block"
        ],
        "op": "eq",
        "value": "192.168.4.0/24"
       }
      ]
     },
     "to": {
      "types": [
       "aws_vpc"
      ],
      "where": []
     }
    }
   ]
  },
  {
   "id": "single_az",
   "kind": "any_of",
   "tier": "detail",
   "quote": "in a single availability zone",
   "checks": [
    {
     "kind": "join",
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
        "value": "192.168.1.0/24"
       }
      ]
     },
     "from_path": [
      "availability_zone"
     ],
     "to": {
      "types": [
       "aws_subnet"
      ],
      "where": [
       {
        "path": [
         "cidr_block"
        ],
        "op": "eq",
        "value": "192.168.4.0/24"
       }
      ]
     },
     "to_path": [
      "availability_zone"
     ]
    },
    {
     "kind": "join",
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
        "value": "192.168.1.0/24"
       }
      ]
     },
     "from_path": [
      "availability_zone_id"
     ],
     "to": {
      "types": [
       "aws_subnet"
      ],
      "where": [
       {
        "path": [
         "cidr_block"
        ],
        "op": "eq",
        "value": "192.168.4.0/24"
       }
      ]
     },
     "to_path": [
      "availability_zone_id"
     ]
    }
   ]
  },
  {
   "id": "eip",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_eip"
    ],
    "where": []
   },
   "quote": "plus a standalone Elastic IP"
  },
  {
   "id": "eip_standalone",
   "kind": "all_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_eip"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "instance"
      ],
      "op": "absent"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_eip"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "network_interface"
      ],
      "op": "absent"
     }
    }
   ],
   "quote": "standalone Elastic IP"
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
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
