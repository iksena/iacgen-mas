package intent.cfn.row_201

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
  "subnets": {
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
  "att": {
   "types": [
    "AWS::EC2::VPCGatewayAttachment"
   ],
   "where": []
  },
  "nat": {
   "types": [
    "AWS::EC2::NatGateway"
   ],
   "where": []
  },
  "eip": {
   "types": [
    "AWS::EC2::EIP"
   ],
   "where": []
  },
  "sg": {
   "types": [
    "AWS::EC2::SecurityGroup"
   ],
   "where": []
  },
  "igw_route": {
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
    },
    {
     "path": [
      "GatewayId"
     ],
     "op": "present"
    }
   ]
  },
  "nat_route": {
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
    },
    {
     "path": [
      "NatGatewayId"
     ],
     "op": "present"
    }
   ]
  },
  "outs": {
   "types": [
    "__output__"
   ],
   "where": []
  },
  "params": {
   "types": [
    "__parameter__"
   ],
   "where": []
  },
  "ingress_res": {
   "types": [
    "AWS::EC2::SecurityGroupIngress"
   ],
   "where": [
    {
     "path": [
      "CidrIp"
     ],
     "op": "eq",
     "value": "0.0.0.0/0"
    },
    {
     "path": [
      "IpProtocol"
     ],
     "op": "eq",
     "value": "tcp"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "vpc_exists",
   "kind": "exists",
   "tier": "core",
   "quote": "creates a VPC, with a parameterized CIDR block",
   "select": "vpc"
  },
  {
   "id": "cidr_and_name_parameters",
   "kind": "all_of",
   "tier": "detail",
   "quote": "with a parameterized CIDR block and a name used to tag resources",
   "justify": "VPC CIDR plus six subnet CIDR parameters (each with its own CIDR parameter), and one more for the name",
   "checks": [
    {
     "kind": "exists",
     "min": 7,
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
        "value": "^[0-9.]+/[0-9]+$"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "min": 8,
     "select": "params"
    }
   ]
  },
  {
   "id": "six_subnets",
   "kind": "exists",
   "tier": "core",
   "quote": "three public subnets and three private subnets",
   "select": "subnets",
   "min": 6
  },
  {
   "id": "subnet_cidrs_distinct",
   "kind": "exists",
   "tier": "detail",
   "quote": "each with its own CIDR parameter",
   "justify": "six subnets each with its own CIDR",
   "select": "subnets",
   "distinct_path": [
    "CidrBlock"
   ],
   "min": 6
  },
  {
   "id": "three_azs",
   "kind": "exists",
   "tier": "core",
   "quote": "spread across three Availability Zones",
   "select": "subnets",
   "distinct_path": [
    "AvailabilityZone"
   ],
   "min": 3
  },
  {
   "id": "subnets_in_vpc",
   "kind": "ref",
   "tier": "detail",
   "quote": "three public subnets and three private subnets",
   "from": "subnets",
   "to": "vpc"
  },
  {
   "id": "igw_exists",
   "kind": "exists",
   "tier": "core",
   "quote": "an Internet Gateway attached to the VPC",
   "select": "igw"
  },
  {
   "id": "igw_attached",
   "kind": "all_of",
   "tier": "core",
   "quote": "an Internet Gateway attached to the VPC",
   "checks": [
    {
     "kind": "ref",
     "from": "att",
     "to": "igw"
    },
    {
     "kind": "ref",
     "from": "att",
     "to": "vpc"
    }
   ]
  },
  {
   "id": "public_default_route",
   "kind": "ref",
   "tier": "core",
   "quote": "a public route table routing to it",
   "justify": "routing to the internet gateway means a default route 0.0.0.0/0",
   "from": "igw_route",
   "to": "igw"
  },
  {
   "id": "three_nat_gateways",
   "kind": "exists",
   "tier": "core",
   "quote": "a NAT Gateway with its own Elastic IP in each public subnet",
   "select": "nat",
   "min": 3
  },
  {
   "id": "nat_distinct_subnets",
   "kind": "exists",
   "tier": "detail",
   "quote": "in each public subnet",
   "select": "nat",
   "distinct_path": [
    "SubnetId"
   ],
   "min": 3
  },
  {
   "id": "three_eips",
   "kind": "exists",
   "tier": "core",
   "quote": "with its own Elastic IP",
   "justify": "one Elastic IP per NAT Gateway, three NATs",
   "select": "eip",
   "min": 3
  },
  {
   "id": "nat_uses_eip",
   "kind": "all_of",
   "tier": "detail",
   "quote": "a NAT Gateway with its own Elastic IP",
   "justify": "one Elastic IP per NAT Gateway, three NATs",
   "checks": [
    {
     "kind": "ref",
     "from": "nat",
     "to": "eip"
    },
    {
     "kind": "exists",
     "select": "nat",
     "distinct_path": [
      "AllocationId"
     ],
     "min": 3
    }
   ]
  },
  {
   "id": "private_route_tables_via_nat",
   "kind": "all_of",
   "tier": "core",
   "quote": "through per-Availability-Zone private route tables",
   "justify": "one route table and one NAT per AZ",
   "checks": [
    {
     "kind": "exists",
     "select": "nat_route",
     "distinct_path": [
      "RouteTableId"
     ],
     "min": 3
    },
    {
     "kind": "exists",
     "select": "nat_route",
     "distinct_path": [
      "NatGatewayId"
     ],
     "min": 3
    }
   ]
  },
  {
   "id": "private_subnets_elb_tag",
   "kind": "exists",
   "tier": "core",
   "quote": "Tag the private subnets appropriately for internal load balancer discovery",
   "justify": "internal load balancer discovery means the kubernetes.io/role/internal-elb tag on the three private subnets",
   "select": {
    "types": [
     "AWS::EC2::Subnet"
    ],
    "where": [
     {
      "path": [
       "Tags",
       "*",
       "Key"
      ],
      "op": "eq",
      "value": "kubernetes.io/role/internal-elb"
     }
    ]
   },
   "min": 3
  },
  {
   "id": "two_security_groups",
   "kind": "exists",
   "tier": "core",
   "quote": "a security group intended for the EKS control plane to communicate with worker nodes",
   "justify": "control-plane group plus a second group",
   "select": "sg",
   "min": 2
  },
  {
   "id": "sgs_in_vpc",
   "kind": "ref",
   "tier": "detail",
   "quote": "a security group intended for the EKS control plane",
   "from": "sg",
   "to": "vpc"
  },
  {
   "id": "http_open",
   "kind": "any_of",
   "tier": "core",
   "quote": "including HTTP, HTTPS",
   "justify": "HTTP implies TCP port 80; to the internet implies 0.0.0.0/0",
   "checks": [
    {
     "kind": "attr",
     "select": "sg",
     "cond": {
      "path": [
       "SecurityGroupIngress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "IpProtocol"
        ],
        "op": "eq",
        "value": "tcp"
       },
       {
        "path": [],
        "op": "port_covers",
        "value": 80
       },
       {
        "path": [
         "CidrIp"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "ingress_res",
     "cond": {
      "path": [],
      "op": "port_covers",
      "value": 80
     }
    }
   ]
  },
  {
   "id": "https_open",
   "kind": "any_of",
   "tier": "core",
   "quote": "including HTTP, HTTPS",
   "justify": "HTTPS implies TCP port 443; to the internet implies 0.0.0.0/0",
   "checks": [
    {
     "kind": "attr",
     "select": "sg",
     "cond": {
      "path": [
       "SecurityGroupIngress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "IpProtocol"
        ],
        "op": "eq",
        "value": "tcp"
       },
       {
        "path": [],
        "op": "port_covers",
        "value": 443
       },
       {
        "path": [
         "CidrIp"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "ingress_res",
     "cond": {
      "path": [],
      "op": "port_covers",
      "value": 443
     }
    }
   ]
  },
  {
   "id": "custom_ports_open",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a handful of custom TCP ports used by an ingress or service mesh gateway, to the internet",
   "justify": "a handful means at least two custom TCP ports other than 80 and 443, open to 0.0.0.0/0; with HTTP and HTTPS that is at least four rules",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::EC2::SecurityGroup"
      ],
      "where": [
       {
        "path": [
         "SecurityGroupIngress"
        ],
        "op": "len_gte",
        "value": 4
       },
       {
        "path": [
         "SecurityGroupIngress",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "IpProtocol"
          ],
          "op": "eq",
          "value": "tcp"
         },
         {
          "path": [
           "CidrIp"
          ],
          "op": "eq",
          "value": "0.0.0.0/0"
         },
         {
          "path": [
           "FromPort"
          ],
          "op": "neq",
          "value": 80
         },
         {
          "path": [
           "FromPort"
          ],
          "op": "neq",
          "value": 443
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "exists",
     "min": 2,
     "select": {
      "types": [
       "AWS::EC2::SecurityGroupIngress"
      ],
      "where": [
       {
        "path": [
         "CidrIp"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       },
       {
        "path": [
         "IpProtocol"
        ],
        "op": "eq",
        "value": "tcp"
       },
       {
        "path": [
         "FromPort"
        ],
        "op": "neq",
        "value": 80
       },
       {
        "path": [
         "FromPort"
        ],
        "op": "neq",
        "value": 443
       }
      ]
     }
    }
   ]
  },
  {
   "id": "output_vpc_id",
   "kind": "ref",
   "tier": "core",
   "quote": "Expose the VPC ID",
   "from": "outs",
   "to": "vpc"
  },
  {
   "id": "output_sg_ids",
   "kind": "ref",
   "tier": "core",
   "quote": "the security group IDs",
   "from": "outs",
   "to": "sg"
  },
  {
   "id": "output_subnet_ids",
   "kind": "any_of",
   "tier": "core",
   "quote": "the list of all subnet IDs as stack outputs",
   "justify": "all six subnets: one list output, a public and a private list, or one output per subnet",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "__output__"
      ],
      "where": [
       {
        "path": [
         "value"
        ],
        "op": "regex",
        "value": "(?s)((\"ref\"|\\$\\{).*){6}"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "min": 2,
     "select": {
      "types": [
       "__output__"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)subnet"
       },
       {
        "path": [
         "value"
        ],
        "op": "regex",
        "value": "(?s)((\"ref\"|\\$\\{).*){3}"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "min": 6,
     "select": {
      "types": [
       "__output__"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)subnet"
       },
       {
        "path": [
         "value",
         "ref"
        ],
        "op": "present"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "x_dns_support",
   "kind": "attr",
   "tier": "extra",
   "select": "vpc",
   "cond": {
    "path": [
     "EnableDnsSupport"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "x_dns_hostnames",
   "kind": "attr",
   "tier": "extra",
   "select": "vpc",
   "cond": {
    "path": [
     "EnableDnsHostnames"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "x_eip_vpc",
   "kind": "attr",
   "tier": "extra",
   "select": "eip",
   "cond": {
    "path": [
     "Domain"
    ],
    "op": "eq",
    "value": "vpc"
   },
   "quantifier": "all"
  },
  {
   "id": "extra_type_aws_ec2_routetable",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::EC2::RouteTable"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_ec2_subnetroutetableassociation",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::EC2::SubnetRouteTableAssociation"
    ],
    "where": []
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
