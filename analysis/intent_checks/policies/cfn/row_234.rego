package intent.cfn.row_234

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
  "ssm": {
   "types": [
    "AWS::SSM::Parameter"
   ],
   "where": []
  },
  "p1": {
   "types": [
    "AWS::SSM::Parameter"
   ],
   "where": [
    {
     "path": [
      "Value"
     ],
     "op": "eq",
     "value": "Modified value - version 2"
    }
   ]
  },
  "p2": {
   "types": [
    "AWS::SSM::Parameter"
   ],
   "where": [
    {
     "path": [
      "Value"
     ],
     "op": "eq",
     "value": "Additional param value (version 1)"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "vpc",
   "kind": "exists",
   "tier": "core",
   "quote": "creates a VPC",
   "select": "vpc"
  },
  {
   "id": "vpc_cidr",
   "kind": "attr",
   "tier": "core",
   "quote": "\"10.0.0.0/16\" CIDR block",
   "select": "vpc",
   "cond": {
    "path": [
     "CidrBlock"
    ],
    "op": "eq",
    "value": "10.0.0.0/16"
   }
  },
  {
   "id": "vpc_dns_support",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::EC2::VPC"
    ],
    "where": [
     {
      "path": [
       "EnableDnsSupport"
      ],
      "op": "none_eq",
      "value": false
     }
    ]
   },
   "tier": "core",
   "quote": "with DNS support and hostnames enabled",
   "justify": "DNS support is on unless set to false"
  },
  {
   "id": "vpc_dns_hostnames",
   "kind": "attr",
   "tier": "core",
   "quote": "with DNS support and hostnames enabled",
   "select": "vpc",
   "cond": {
    "path": [
     "EnableDnsHostnames"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "vpc_name_tag",
   "kind": "attr",
   "select": "vpc",
   "cond": {
    "path": [
     "Tags",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "Key"
      ],
      "op": "eq",
      "value": "Name"
     },
     {
      "path": [
       "Value"
      ],
      "op": "regex",
      "value": "(?i).+-VPC-V1$"
     }
    ]
   },
   "tier": "detail",
   "quote": "tagged with Name \"{StackName}-VPC-V1\""
  },
  {
   "id": "two_ssm_params",
   "kind": "exists",
   "tier": "core",
   "quote": "two standard tier SSM String parameters",
   "select": "ssm",
   "min": 2
  },
  {
   "id": "ssm_type_string",
   "kind": "attr",
   "tier": "detail",
   "quote": "SSM String parameters",
   "select": "ssm",
   "quantifier": "all",
   "cond": {
    "path": [
     "Type"
    ],
    "op": "eq",
    "value": "String"
   }
  },
  {
   "id": "ssm_tier_standard",
   "kind": "exists",
   "min": 2,
   "select": {
    "types": [
     "AWS::SSM::Parameter"
    ],
    "where": [
     {
      "path": [
       "Tier"
      ],
      "op": "none_eq",
      "value": "Advanced"
     },
     {
      "path": [
       "Tier"
      ],
      "op": "none_eq",
      "value": "Intelligent-Tiering"
     }
    ]
   },
   "tier": "detail",
   "quote": "standard tier SSM String parameters",
   "justify": "Standard is also the default tier when Tier is omitted"
  },
  {
   "id": "param_one_value",
   "kind": "exists",
   "tier": "core",
   "quote": "named \"{StackName}-SSM-Param-One\" with value \"Modified value - version 2\"",
   "select": "p1"
  },
  {
   "id": "param_one_name",
   "kind": "attr",
   "select": "p1",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "regex",
    "value": "(?i).+-SSM-Param-One$"
   },
   "tier": "detail",
   "quote": "named \"{StackName}-SSM-Param-One\""
  },
  {
   "id": "param_two_value",
   "kind": "exists",
   "tier": "core",
   "quote": "with value \"Additional param value (version 1)\"",
   "select": "p2"
  },
  {
   "id": "param_two_name",
   "kind": "attr",
   "select": "p2",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "regex",
    "value": "(?i).+-SSM-Param-Two$"
   },
   "tier": "detail",
   "quote": "\"{StackName}-SSM-Param-Two\""
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
