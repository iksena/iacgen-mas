package intent.tf.row_082

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
  "sub": {
   "types": [
    "aws_subnet"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "vpc",
   "kind": "exists",
   "select": "vpc",
   "tier": "core",
   "quote": "a custom VPC networking stack"
  },
  {
   "id": "vpc_cidr",
   "kind": "attr",
   "select": "vpc",
   "cond": {
    "path": [
     "cidr_block"
    ],
    "op": "eq",
    "value": "10.0.0.0/16"
   },
   "tier": "core",
   "quote": "a VPC CIDR block defaulting to \"10.0.0.0/16\""
  },
  {
   "id": "vpc_name",
   "kind": "attr",
   "select": "vpc",
   "cond": {
    "path": [
     "tags",
     "Name"
    ],
    "op": "eq",
    "value": "terraform-aws-vpc"
   },
   "tier": "core",
   "quote": "The VPC must be tagged with Name \"terraform-aws-vpc\""
  },
  {
   "id": "vpc_dns",
   "kind": "attr",
   "select": "vpc",
   "cond": {
    "path": [
     "enable_dns_hostnames"
    ],
    "op": "truthy"
   },
   "tier": "core",
   "quote": "have DNS hostnames enabled"
  },
  {
   "id": "subnets4",
   "kind": "exists",
   "select": "sub",
   "tier": "core",
   "min": 4,
   "quote": "two public subnets",
   "justify": "two public plus two private subnets"
  },
  {
   "id": "public_cidrs",
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
   "tier": "core",
   "quote": "public subnet CIDR blocks defaulting to [\"10.0.1.0/24\", \"10.0.2.0/24\"]"
  },
  {
   "id": "private_cidrs",
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
        "value": "10.0.3.0/24"
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
        "value": "10.0.4.0/24"
       }
      ]
     }
    }
   ],
   "tier": "core",
   "quote": "private subnet CIDR blocks defaulting to [\"10.0.3.0/24\", \"10.0.4.0/24\"]"
  },
  {
   "id": "public_tags",
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
         "tags",
         "Name"
        ],
        "op": "eq",
        "value": "public-subnet-1"
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
         "tags",
         "Name"
        ],
        "op": "eq",
        "value": "public-subnet-2"
       }
      ]
     }
    }
   ],
   "tier": "detail",
   "quote": "two public subnets tagged as \"public-subnet-1\" and \"public-subnet-2\""
  },
  {
   "id": "private_tags",
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
         "tags",
         "Name"
        ],
        "op": "eq",
        "value": "private-subnet-1"
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
         "tags",
         "Name"
        ],
        "op": "eq",
        "value": "private-subnet-2"
       }
      ]
     }
    }
   ],
   "tier": "detail",
   "quote": "two private subnets tagged as \"private-subnet-1\" and \"private-subnet-2\""
  },
  {
   "id": "subnets_in_vpc",
   "kind": "ref",
   "from": "sub",
   "to": "vpc",
   "tier": "detail",
   "quote": "provisioning two public subnets"
  },
  {
   "id": "two_azs",
   "kind": "exists",
   "select": "sub",
   "distinct_path": [
    "availability_zone"
   ],
   "min": 2,
   "tier": "core",
   "quote": "across two available availability zones"
  },
  {
   "id": "each_subnet_az",
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
        "op": "in",
        "value": [
         "10.0.1.0/24",
         "10.0.2.0/24"
        ]
       }
      ]
     },
     "distinct_path": [
      "availability_zone"
     ],
     "min": 2
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
        "op": "in",
        "value": [
         "10.0.3.0/24",
         "10.0.4.0/24"
        ]
       }
      ]
     },
     "distinct_path": [
      "availability_zone"
     ],
     "min": 2
    }
   ],
   "tier": "detail",
   "quote": "each assigned sequentially to the region's first two available availability zones",
   "justify": "the two public and the two private subnets (stated CIDRs) each span the two AZs"
  },
  {
   "id": "param_region",
   "kind": "exists",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "us-east-1"
     }
    ]
   },
   "tier": "detail",
   "quote": "an AWS region defaulting to \"us-east-1\""
  },
  {
   "id": "param_vpc_cidr",
   "kind": "exists",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "10.0.0.0/16"
     }
    ]
   },
   "tier": "detail",
   "quote": "a VPC CIDR block defaulting to \"10.0.0.0/16\""
  },
  {
   "id": "param_public",
   "kind": "exists",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "default"
      ],
      "op": "regex",
      "value": "10\\.0\\.1\\.0/24.{0,4}10\\.0\\.2\\.0/24"
     }
    ]
   },
   "tier": "detail",
   "quote": "public subnet CIDR blocks defaulting to [\"10.0.1.0/24\", \"10.0.2.0/24\"]"
  },
  {
   "id": "param_private",
   "kind": "exists",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "default"
      ],
      "op": "regex",
      "value": "10\\.0\\.3\\.0/24.{0,4}10\\.0\\.4\\.0/24"
     }
    ]
   },
   "tier": "detail",
   "quote": "private subnet CIDR blocks defaulting to [\"10.0.3.0/24\", \"10.0.4.0/24\"]"
  },
  {
   "id": "vpc_dns_support",
   "kind": "attr",
   "select": "vpc",
   "cond": {
    "path": [
     "enable_dns_support"
    ],
    "op": "truthy"
   },
   "tier": "extra"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
