package intent.cfn.row_087

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
  "rt": {
   "types": [
    "AWS::EC2::RouteTable"
   ],
   "where": []
  },
  "vpc_users": {
   "types": [
    "AWS::EC2::VPC"
   ],
   "where": [
    {
     "path": [
      "CidrBlock"
     ],
     "op": "eq",
     "value": "10.50.0.0/16"
    }
   ]
  },
  "vpc_fog": {
   "types": [
    "AWS::EC2::VPC"
   ],
   "where": [
    {
     "path": [
      "CidrBlock"
     ],
     "op": "eq",
     "value": "10.60.0.0/16"
    }
   ]
  },
  "s3gw": {
   "types": [
    "AWS::EC2::VPCEndpoint"
   ],
   "where": [
    {
     "path": [
      "ServiceName"
     ],
     "op": "regex",
     "value": "\\.s3$"
    },
    {
     "path": [
      "VpcEndpointType"
     ],
     "op": "none_eq",
     "value": "Interface"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "two_vpcs",
   "kind": "exists",
   "tier": "core",
   "quote": "creates two separate, self-contained VPCs",
   "select": "vpc",
   "min": 2
  },
  {
   "id": "users_vpc_cidr",
   "kind": "exists",
   "tier": "core",
   "quote": "CIDR blocks of 10.50.0.0/16 and 10.60.0.0/16 respectively",
   "select": "vpc_users"
  },
  {
   "id": "fog_vpc_cidr",
   "kind": "exists",
   "tier": "core",
   "quote": "CIDR blocks of 10.50.0.0/16 and 10.60.0.0/16 respectively",
   "select": "vpc_fog"
  },
  {
   "id": "users_subnet",
   "kind": "ref",
   "tier": "core",
   "quote": "each with one subnet and route table",
   "from": "subnet",
   "to": "vpc_users"
  },
  {
   "id": "fog_subnet",
   "kind": "ref",
   "tier": "core",
   "quote": "each with one subnet and route table",
   "from": "subnet",
   "to": "vpc_fog"
  },
  {
   "id": "users_route_table",
   "kind": "ref",
   "tier": "detail",
   "quote": "each with one subnet and route table",
   "from": "rt",
   "to": "vpc_users"
  },
  {
   "id": "fog_route_table",
   "kind": "ref",
   "tier": "detail",
   "quote": "each with one subnet and route table",
   "from": "rt",
   "to": "vpc_fog"
  },
  {
   "id": "one_subnet_and_route_table_each",
   "kind": "all_of",
   "tier": "detail",
   "quote": "each with one subnet and route table",
   "checks": [
    {
     "kind": "exists",
     "select": "subnet",
     "min": 2,
     "max": 2
    },
    {
     "kind": "exists",
     "select": "rt",
     "min": 2,
     "max": 2
    }
   ],
   "justify": "two VPCs with one of each make two"
  },
  {
   "id": "subnets_have_az",
   "kind": "attr",
   "tier": "detail",
   "quote": "placed in the first available availability zone in the region",
   "select": "subnet",
   "quantifier": "all",
   "cond": {
    "path": [
     "AvailabilityZone"
    ],
    "op": "regex",
    "value": "\\da$"
   },
   "justify": "the first AZ of a region ends in a; Fn::Select 0 of Fn::GetAZs resolves to it"
  },
  {
   "id": "users_s3_gateway",
   "kind": "ref",
   "tier": "core",
   "quote": "private connectivity to Amazon S3 through a gateway VPC endpoint",
   "from": "s3gw",
   "to": "vpc_users"
  },
  {
   "id": "fog_s3_gateway",
   "kind": "ref",
   "tier": "core",
   "quote": "private connectivity to Amazon S3 through a gateway VPC endpoint",
   "from": "s3gw",
   "to": "vpc_fog"
  },
  {
   "id": "s3_endpoint_in_route_table",
   "kind": "attr",
   "tier": "detail",
   "quote": "in their own route table",
   "select": "s3gw",
   "quantifier": "all",
   "cond": {
    "path": [
     "RouteTableIds",
     "*",
     "ref"
    ],
    "op": "present"
   }
  },
  {
   "id": "users_kms_interface",
   "kind": "ref",
   "tier": "core",
   "quote": "private connectivity to AWS Key Management Service through an interface VPC endpoint",
   "from": {
    "types": [
     "AWS::EC2::VPCEndpoint"
    ],
    "where": [
     {
      "path": [
       "ServiceName"
      ],
      "op": "regex",
      "value": "\\.kms$"
     },
     {
      "path": [
       "VpcEndpointType"
      ],
      "op": "eq",
      "value": "Interface"
     }
    ]
   },
   "to": "vpc_users",
   "justify": "AWS Key Management Service is the kms service endpoint"
  },
  {
   "id": "fog_kms_interface",
   "kind": "ref",
   "tier": "core",
   "quote": "private connectivity to AWS Key Management Service through an interface VPC endpoint",
   "from": {
    "types": [
     "AWS::EC2::VPCEndpoint"
    ],
    "where": [
     {
      "path": [
       "ServiceName"
      ],
      "op": "regex",
      "value": "\\.kms$"
     },
     {
      "path": [
       "VpcEndpointType"
      ],
      "op": "eq",
      "value": "Interface"
     }
    ]
   },
   "to": "vpc_fog",
   "justify": "AWS Key Management Service is the kms service endpoint"
  },
  {
   "id": "interface_endpoints_in_subnet",
   "kind": "attr",
   "tier": "detail",
   "quote": "through an interface VPC endpoint in their subnet",
   "select": {
    "types": [
     "AWS::EC2::VPCEndpoint"
    ],
    "where": [
     {
      "path": [
       "VpcEndpointType"
      ],
      "op": "eq",
      "value": "Interface"
     }
    ]
   },
   "quantifier": "all",
   "cond": {
    "path": [
     "SubnetIds",
     "*",
     "ref"
    ],
    "op": "present"
   }
  },
  {
   "id": "fog_secretsmanager",
   "kind": "ref",
   "tier": "core",
   "quote": "AWS Secrets Manager",
   "from": {
    "types": [
     "AWS::EC2::VPCEndpoint"
    ],
    "where": [
     {
      "path": [
       "ServiceName"
      ],
      "op": "regex",
      "value": "\\.secretsmanager$"
     },
     {
      "path": [
       "VpcEndpointType"
      ],
      "op": "eq",
      "value": "Interface"
     }
    ]
   },
   "to": "vpc_fog"
  },
  {
   "id": "fog_events",
   "kind": "ref",
   "tier": "core",
   "quote": "Amazon EventBridge",
   "from": {
    "types": [
     "AWS::EC2::VPCEndpoint"
    ],
    "where": [
     {
      "path": [
       "ServiceName"
      ],
      "op": "regex",
      "value": "\\.events$"
     },
     {
      "path": [
       "VpcEndpointType"
      ],
      "op": "eq",
      "value": "Interface"
     }
    ]
   },
   "to": "vpc_fog"
  },
  {
   "id": "fog_sts",
   "kind": "ref",
   "tier": "core",
   "quote": "AWS STS",
   "from": {
    "types": [
     "AWS::EC2::VPCEndpoint"
    ],
    "where": [
     {
      "path": [
       "ServiceName"
      ],
      "op": "regex",
      "value": "\\.sts$"
     },
     {
      "path": [
       "VpcEndpointType"
      ],
      "op": "eq",
      "value": "Interface"
     }
    ]
   },
   "to": "vpc_fog"
  },
  {
   "id": "fog_lambda",
   "kind": "ref",
   "tier": "core",
   "quote": "AWS Lambda through interface VPC endpoints",
   "from": {
    "types": [
     "AWS::EC2::VPCEndpoint"
    ],
    "where": [
     {
      "path": [
       "ServiceName"
      ],
      "op": "regex",
      "value": "\\.lambda$"
     },
     {
      "path": [
       "VpcEndpointType"
      ],
      "op": "eq",
      "value": "Interface"
     }
    ]
   },
   "to": "vpc_fog"
  },
  {
   "id": "x_vpc_dns_support",
   "kind": "attr",
   "tier": "extra",
   "select": "vpc",
   "quantifier": "all",
   "cond": {
    "path": [
     "EnableDnsSupport"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "x_vpc_dns_hostnames",
   "kind": "attr",
   "tier": "extra",
   "select": "vpc",
   "quantifier": "all",
   "cond": {
    "path": [
     "EnableDnsHostnames"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "x_subnet_route_table_association",
   "kind": "ref",
   "tier": "extra",
   "from": {
    "types": [
     "AWS::EC2::SubnetRouteTableAssociation"
    ],
    "where": []
   },
   "to": "subnet"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
