package intent.cfn.row_009

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "key": {
   "types": [
    "AWS::KMS::Key"
   ],
   "where": []
  },
  "alias": {
   "types": [
    "AWS::KMS::Alias"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "kms_key",
   "kind": "exists",
   "select": "key",
   "tier": "core",
   "quote": "a customer managed KMS key"
  },
  {
   "id": "rotation",
   "kind": "attr",
   "select": "key",
   "cond": {
    "path": [
     "EnableKeyRotation"
    ],
    "op": "truthy"
   },
   "tier": "core",
   "quote": "with key rotation enabled"
  },
  {
   "id": "alias",
   "kind": "exists",
   "select": "alias",
   "tier": "core",
   "quote": "an alias that uses the stack name"
  },
  {
   "id": "alias_stack_name",
   "kind": "attr",
   "select": "alias",
   "cond": {
    "path": [
     "AliasName"
    ],
    "op": "regex",
    "value": "(?i)^alias/.*stack"
   },
   "tier": "detail",
   "quote": "an alias that uses the stack name",
   "justify": "the stack name pseudo-parameter resolves to 'stack'; alias names carry the alias/ prefix"
  },
  {
   "id": "alias_targets_key",
   "kind": "ref",
   "tier": "detail",
   "quote": "a customer managed KMS key for encrypting DynamoDB items, with key rotation enabled and an alias",
   "from": "alias",
   "to": "key"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
