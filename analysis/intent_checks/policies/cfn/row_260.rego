package intent.cfn.row_260

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "lg": {
   "types": [
    "AWS::Logs::LogGroup"
   ],
   "where": []
  },
  "vpc": {
   "types": [
    "AWS::EC2::VPC"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "log_group",
   "kind": "exists",
   "tier": "core",
   "quote": "a CloudWatch log group",
   "select": "lg"
  },
  {
   "id": "vpc",
   "kind": "exists",
   "tier": "core",
   "quote": "a virtual private cloud",
   "select": "vpc"
  },
  {
   "id": "vpc_cidr",
   "kind": "attr",
   "tier": "core",
   "quote": "the 10.0.0.0/24 address range",
   "select": "vpc",
   "cond": {
    "path": [
     "CidrBlock"
    ],
    "op": "eq",
    "value": "10.0.0.0/24"
   }
  },
  {
   "id": "vpc_after_log_group",
   "kind": "join",
   "tier": "core",
   "quote": "the VPC is explicitly created only after the log group",
   "from": "vpc",
   "from_path": [
    "__resource__",
    "DependsOn",
    "*"
   ],
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
      "value": "AWS::Logs::LogGroup"
     }
    ]
   },
   "to_path": [
    "name"
   ]
  },
  {
   "id": "only_requested_resources",
   "kind": "all_of",
   "tier": "core",
   "quote": "consisting of just a CloudWatch log group and a virtual private cloud",
   "justify": "'just a log group and a VPC' limits the stack to one of each and nothing else",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": []
     },
     "quantifier": "all",
     "cond": {
      "path": [
       "type"
      ],
      "op": "in",
      "value": [
       "AWS::Logs::LogGroup",
       "AWS::EC2::VPC"
      ]
     }
    },
    {
     "kind": "exists",
     "select": "lg",
     "max": 1
    },
    {
     "kind": "exists",
     "select": "vpc",
     "max": 1
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
