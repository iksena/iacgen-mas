package intent.tf.row_049

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "vpc": {
   "types": [
    "aws_vpc"
   ],
   "where": []
  },
  "subnets": {
   "types": [
    "aws_subnet"
   ],
   "where": []
  },
  "pub": {
   "types": [
    "aws_subnet"
   ],
   "where": [
    {
     "path": [
      "tags",
      "*"
     ],
     "op": "regex",
     "value": "(?i)public"
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
      "tags",
      "*"
     ],
     "op": "regex",
     "value": "(?i)private"
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
  }
 },
 "checks": [
  {
   "id": "vpc",
   "tier": "core",
   "quote": "creates a self-contained VPC network",
   "kind": "exists",
   "select": "vpc"
  },
  {
   "id": "vpc_named_cluster",
   "tier": "core",
   "quote": "named for a cluster called \"Fast-App\"",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "vpc",
     "cond": {
      "path": [
       "tags",
       "*"
      ],
      "op": "regex",
      "value": "(?i)fast[-_ ]?app"
     }
    },
    {
     "kind": "attr",
     "select": "vpc",
     "cond": {
      "path": [
       "tags_all",
       "*"
      ],
      "op": "regex",
      "value": "(?i)fast[-_ ]?app"
     }
    }
   ]
  },
  {
   "id": "public_subnets",
   "tier": "core",
   "quote": "public and private subnet tiers",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": "pub"
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
         "map_public_ip_on_launch"
        ],
        "op": "eq",
        "value": true
       }
      ]
     }
    }
   ]
  },
  {
   "id": "private_subnets",
   "tier": "core",
   "quote": "public and private subnet tiers",
   "kind": "exists",
   "select": "priv"
  },
  {
   "id": "multiple_azs",
   "tier": "core",
   "quote": "public and private subnet tiers spread across multiple availability zones",
   "kind": "all_of",
   "justify": "multiple availability zones means at least 2 per tier",
   "checks": [
    {
     "kind": "exists",
     "select": "pub",
     "min": 2,
     "distinct_path": [
      "availability_zone"
     ]
    },
    {
     "kind": "exists",
     "select": "priv",
     "min": 2,
     "distinct_path": [
      "availability_zone"
     ]
    }
   ]
  },
  {
   "id": "subnets_in_vpc",
   "tier": "detail",
   "quote": "creates a self-contained VPC network",
   "kind": "ref",
   "from": "subnets",
   "to": "vpc"
  },
  {
   "id": "igw",
   "tier": "core",
   "quote": "an internet gateway",
   "kind": "exists",
   "select": "igw"
  },
  {
   "id": "igw_attached",
   "tier": "detail",
   "quote": "an internet gateway",
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
   ]
  },
  {
   "id": "public_route_table",
   "tier": "core",
   "quote": "a public route table for internet access",
   "kind": "exists",
   "select": "rt"
  },
  {
   "id": "route_via_igw",
   "tier": "core",
   "quote": "a public route table for internet access",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "rt",
     "to": "igw"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_route"
      ],
      "where": []
     },
     "to": "igw"
    }
   ]
  },
  {
   "id": "default_route",
   "tier": "detail",
   "quote": "a public route table for internet access",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "rt",
     "cond": {
      "path": [
       "route",
       "*",
       "cidr_block"
      ],
      "op": "eq",
      "value": "0.0.0.0/0"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_route"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "destination_cidr_block"
      ],
      "op": "eq",
      "value": "0.0.0.0/0"
     }
    }
   ],
   "justify": "internet access implies a 0.0.0.0/0 route"
  },
  {
   "id": "rt_associated",
   "tier": "detail",
   "quote": "a public route table for internet access",
   "kind": "ref",
   "from": {
    "types": [
     "aws_route_table_association"
    ],
    "where": []
   },
   "to": "rt"
  },
  {
   "id": "public_no_auto_ip",
   "tier": "extra",
   "kind": "attr",
   "select": {
    "types": [
     "aws_subnet"
    ],
    "where": [
     {
      "path": [
       "tags",
       "*"
      ],
      "op": "regex",
      "value": "(?i)public"
     }
    ]
   },
   "cond": {
    "path": [
     "map_public_ip_on_launch"
    ],
    "op": "falsy",
    "value": null
   },
   "quantifier": "all"
  },
  {
   "id": "vpc_dns_hostnames",
   "tier": "extra",
   "kind": "attr",
   "select": "vpc",
   "cond": {
    "path": [
     "enable_dns_hostnames"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "vpc_dns_support",
   "tier": "extra",
   "kind": "attr",
   "select": "vpc",
   "cond": {
    "path": [
     "enable_dns_support"
    ],
    "op": "eq",
    "value": true
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
