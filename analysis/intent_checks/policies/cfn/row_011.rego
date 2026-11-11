package intent.cfn.row_011

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "ca": {
   "types": [
    "AWS::CodePipeline::CustomActionType"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "custom_action",
   "kind": "exists",
   "select": "ca",
   "tier": "core",
   "quote": "creates a CodePipeline custom action type"
  },
  {
   "id": "category_deploy",
   "kind": "attr",
   "select": "ca",
   "cond": {
    "path": [
     "Category"
    ],
    "op": "eq",
    "value": "Deploy"
   },
   "tier": "core",
   "quote": "for deploying to AWS OpsWorks"
  },
  {
   "id": "provider_stack_name",
   "kind": "attr",
   "select": "ca",
   "cond": {
    "path": [
     "Provider"
    ],
    "op": "eq",
    "value": "stack"
   },
   "tier": "core",
   "quote": "a provider name equal to the stack name",
   "justify": "stack name resolves to the pseudo-parameter value 'stack'"
  },
  {
   "id": "version_1",
   "kind": "attr",
   "select": "ca",
   "cond": {
    "path": [
     "Version"
    ],
    "op": "eq",
    "value": 1
   },
   "tier": "core",
   "quote": "a default version of 1"
  },
  {
   "id": "prop_bucket",
   "kind": "attr",
   "select": "ca",
   "cond": {
    "path": [
     "ConfigurationProperties",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "Name"
      ],
      "op": "eq",
      "value": "Deploy-Bucket"
     }
    ]
   },
   "tier": "detail",
   "quote": "configuration properties for Deploy-Bucket"
  },
  {
   "id": "prop_stack_id",
   "kind": "attr",
   "select": "ca",
   "cond": {
    "path": [
     "ConfigurationProperties",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "Name"
      ],
      "op": "eq",
      "value": "OpsWorks-Stack-ID"
     }
    ]
   },
   "tier": "detail",
   "quote": "OpsWorks-Stack-ID"
  },
  {
   "id": "prop_app_id",
   "kind": "attr",
   "select": "ca",
   "cond": {
    "path": [
     "ConfigurationProperties",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "Name"
      ],
      "op": "eq",
      "value": "OpsWorks-App-ID"
     },
     {
      "path": [
       "Key"
      ],
      "op": "truthy"
     }
    ]
   },
   "tier": "detail",
   "quote": "OpsWorks-App-ID (with the latter flagged as a key property)"
  },
  {
   "id": "input_one",
   "kind": "attr",
   "select": "ca",
   "cond": {
    "path": [
     "InputArtifactDetails",
     "MaximumCount"
    ],
    "op": "eq",
    "value": 1
   },
   "tier": "core",
   "quote": "accept one input artifact",
   "justify": "one artifact = maximum count 1"
  },
  {
   "id": "output_none",
   "kind": "attr",
   "select": "ca",
   "cond": {
    "path": [
     "OutputArtifactDetails",
     "MaximumCount"
    ],
    "op": "eq",
    "value": 0
   },
   "tier": "core",
   "quote": "produce no output artifacts",
   "justify": "no artifacts = maximum count 0"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
