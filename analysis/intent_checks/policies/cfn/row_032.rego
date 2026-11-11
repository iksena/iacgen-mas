package intent.cfn.row_032

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
  }
 },
 "checks": [
  {
   "id": "vpc",
   "kind": "exists",
   "select": "vpc",
   "tier": "core",
   "quote": "creates a VPC"
  },
  {
   "id": "cidr16",
   "kind": "attr",
   "select": "vpc",
   "cond": {
    "path": [
     "CidrBlock"
    ],
    "op": "regex",
    "value": "/16$"
   },
   "tier": "core",
   "quote": "a VPC with a /16 CIDR block"
  },
  {
   "id": "dns_support",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "vpc",
     "cond": {
      "path": [
       "EnableDnsSupport"
      ],
      "op": "truthy"
     }
    },
    {
     "kind": "attr",
     "select": "vpc",
     "cond": {
      "path": [
       "EnableDnsSupport"
      ],
      "op": "absent"
     }
    }
   ],
   "quote": "DNS support and DNS hostnames enabled",
   "justify": "DNS support is on by default when EnableDnsSupport is omitted"
  },
  {
   "id": "dns_hostnames",
   "kind": "attr",
   "select": "vpc",
   "cond": {
    "path": [
     "EnableDnsHostnames"
    ],
    "op": "truthy"
   },
   "tier": "core",
   "quote": "DNS support and DNS hostnames enabled"
  },
  {
   "id": "vpc_tag_v1",
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
      "value": "(?i)stack"
     },
     {
      "path": [
       "Value"
      ],
      "op": "regex",
      "value": "(?i)(^|[^a-z])(v|version)[ _:.-]*(1|one)([^0-9]|$)"
     }
    ]
   },
   "tier": "detail",
   "quote": "tagged with a name that includes the stack name and indicates version 1",
   "justify": "a Name tag; the adapter resolves AWS::StackName to a string containing stack; version 1 marker such as V1 or version 1"
  },
  {
   "id": "ssm",
   "kind": "exists",
   "select": "ssm",
   "tier": "core",
   "quote": "an SSM parameter with a placeholder string value"
  },
  {
   "id": "ssm_string",
   "kind": "attr",
   "select": "ssm",
   "cond": {
    "path": [
     "Type"
    ],
    "op": "eq",
    "value": "String"
   },
   "tier": "core",
   "quote": "The SSM parameter should be of type String"
  },
  {
   "id": "ssm_standard",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "ssm",
     "cond": {
      "path": [
       "Tier"
      ],
      "op": "eq",
      "value": "Standard"
     }
    },
    {
     "kind": "attr",
     "select": "ssm",
     "cond": {
      "path": [
       "Tier"
      ],
      "op": "absent"
     }
    }
   ],
   "quote": "standard tier",
   "justify": "Standard is the default tier when Tier is omitted"
  },
  {
   "id": "ssm_name_stack",
   "kind": "attr",
   "select": "ssm",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "regex",
    "value": "(?i)stack"
   },
   "tier": "detail",
   "quote": "with a name that includes the stack name",
   "justify": "adapter resolves AWS::StackName to a string containing stack"
  },
  {
   "id": "ssm_value_v1",
   "kind": "attr",
   "select": "ssm",
   "cond": {
    "path": [
     "Value"
    ],
    "op": "regex",
    "value": "(?i)(^|[^a-z])(v|version)[ _:.-]*(1|one)([^0-9]|$)"
   },
   "tier": "detail",
   "quote": "a value that indicates version 1",
   "justify": "version 1 marker"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
