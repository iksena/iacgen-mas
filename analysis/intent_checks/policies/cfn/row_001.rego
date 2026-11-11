package intent.cfn.row_001

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "g": {
   "types": [
    "AWS::Detective::Graph"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "detective_graph",
   "kind": "exists",
   "select": "g",
   "tier": "core",
   "quote": "creates a simple Amazon Detective Graph"
  },
  {
   "id": "name_tag",
   "kind": "attr",
   "select": "g",
   "cond": {
    "path": [
     "Tags",
     "*"
    ],
    "op": "has_kv",
    "value": {
     "key": "Name",
     "value": "MyDetectiveGraph"
    }
   },
   "tier": "detail",
   "quote": "a tag named \"Name\" set to \"MyDetectiveGraph\""
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
