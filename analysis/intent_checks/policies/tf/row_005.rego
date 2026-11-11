package intent.tf.row_005

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
  }
 },
 "checks": [
  {
   "id": "vpc_cidr",
   "kind": "exists",
   "tier": "core",
   "select": "vpc",
   "quote": "a VPC with a CIDR block of 10.0.0.0/16"
  },
  {
   "id": "subnet_cidr",
   "kind": "exists",
   "tier": "core",
   "select": "subnet",
   "quote": "a public subnet with a CIDR block of 10.0.1.0/24"
  },
  {
   "id": "subnet_in_vpc",
   "kind": "ref",
   "tier": "core",
   "to": "vpc",
   "quote": "a VPC with a CIDR block of 10.0.0.0/16 and a public subnet",
   "from": "subnet"
  },
  {
   "id": "igw_attached",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_internet_gateway"
      ],
      "where": []
     },
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
   "quote": "an internet gateway attached to the VPC"
  },
  {
   "id": "default_route_igw",
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
   "quote": "a route table directing all outbound traffic to the internet gateway",
   "justify": "all outbound traffic means 0.0.0.0/0"
  },
  {
   "id": "assoc_subnet",
   "kind": "ref",
   "tier": "core",
   "to": "subnet",
   "quote": "associated with the public subnet",
   "from": {
    "types": [
     "aws_route_table_association"
    ],
    "where": []
   }
  },
  {
   "id": "assoc_rt",
   "kind": "ref",
   "tier": "core",
   "to": "rt",
   "quote": "a route table directing all outbound traffic to the internet gateway associated with the public subnet",
   "from": {
    "types": [
     "aws_route_table_association"
    ],
    "where": []
   }
  },
  {
   "id": "eip_exists",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_eip"
    ],
    "where": []
   },
   "quote": "an Elastic IP"
  },
  {
   "id": "eip_attached_to_var_instance",
   "kind": "any_of",
   "tier": "core",
   "quote": "an Elastic IP attached to an instance ID configurable via a variable",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_eip"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "instance"
      ],
      "op": "regex",
      "value": "^$|var\\."
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_eip_association"
       },
       {
        "path": [
         "properties",
         "instance_id"
        ],
        "op": "regex",
        "value": "^$|var\\."
       }
      ]
     },
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_eip"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "instance_var_default_empty",
   "kind": "exists",
   "tier": "detail",
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
      "value": ""
     }
    ]
   },
   "quote": "an instance ID configurable via a variable that defaults to an empty string"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
