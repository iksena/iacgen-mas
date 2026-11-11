package intent.cfn.row_010

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "rs": {
   "types": [
    "AWS::RAM::ResourceShare"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "resource_share",
   "kind": "exists",
   "select": "rs",
   "tier": "core",
   "quote": "creates an AWS Resource Access Manager resource share"
  },
  {
   "id": "share_name",
   "kind": "attr",
   "select": "rs",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "eq",
    "value": "MyResourceShare"
   },
   "tier": "core",
   "quote": "named \"MyResourceShare\""
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
