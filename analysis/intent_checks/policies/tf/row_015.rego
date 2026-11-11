package intent.tf.row_015

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "ds": {
   "types": [
    "aws_route53_delegation_set"
   ],
   "where": []
  },
  "ssm": {
   "types": [
    "aws_ssm_parameter"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "delegation_set",
   "kind": "exists",
   "select": "ds",
   "tier": "core",
   "quote": "creates a reusable Amazon Route 53 delegation set"
  },
  {
   "id": "delegation_set_ref_name",
   "kind": "attr",
   "select": "ds",
   "cond": {
    "path": [
     "reference_name"
    ],
    "op": "eq",
    "value": "WebsiteDNS"
   },
   "tier": "core",
   "quote": "configured with the reference name \"WebsiteDNS\""
  },
  {
   "id": "ssm_parameter",
   "kind": "exists",
   "select": "ssm",
   "tier": "core",
   "quote": "provision an AWS Systems Manager (SSM) String parameter"
  },
  {
   "id": "ssm_type",
   "kind": "attr",
   "select": "ssm",
   "cond": {
    "path": [
     "type"
    ],
    "op": "eq",
    "value": "String"
   },
   "tier": "core",
   "quote": "SSM) String parameter"
  },
  {
   "id": "ssm_name",
   "kind": "attr",
   "select": "ssm",
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "/WebsiteCv/production/Route53/DelegationSetId"
   },
   "tier": "core",
   "quote": "named \"/WebsiteCv/production/Route53/DelegationSetId\""
  },
  {
   "id": "ssm_stores_delegation_id",
   "kind": "ref",
   "from": "ssm",
   "to": "ds",
   "tier": "core",
   "quote": "stores the newly generated ID of the delegation set"
  },
  {
   "id": "tag_project",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "ssm",
     "cond": {
      "path": [
       "tags_all",
       "Project"
      ],
      "op": "eq",
      "value": "Website CV"
     }
    },
    {
     "kind": "attr",
     "select": "ssm",
     "cond": {
      "path": [
       "tags",
       "Project"
      ],
      "op": "eq",
      "value": "Website CV"
     }
    }
   ],
   "tier": "detail",
   "quote": "default tags identifying the project as \"Website CV\""
  },
  {
   "id": "tag_environment",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "ssm",
     "cond": {
      "path": [
       "tags_all",
       "Environment"
      ],
      "op": "eq",
      "value": "production"
     }
    },
    {
     "kind": "attr",
     "select": "ssm",
     "cond": {
      "path": [
       "tags",
       "Environment"
      ],
      "op": "eq",
      "value": "production"
     }
    }
   ],
   "tier": "detail",
   "quote": "the environment as \"production\""
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
