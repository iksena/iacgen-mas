package intent.cfn.row_003

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "inst": {
   "types": [
    "AWS::Lightsail::Instance"
   ],
   "where": []
  },
  "disk": {
   "types": [
    "AWS::Lightsail::Disk"
   ],
   "where": []
  },
  "both": {
   "types": [
    "AWS::Lightsail::Instance",
    "AWS::Lightsail::Disk"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "instance",
   "kind": "exists",
   "select": "inst",
   "tier": "core",
   "quote": "creates a Lightsail instance"
  },
  {
   "id": "blueprint",
   "kind": "attr",
   "select": "inst",
   "cond": {
    "path": [
     "BlueprintId"
    ],
    "op": "regex",
    "value": "(?i)^amazon_linux_2023"
   },
   "tier": "core",
   "quote": "the latest Amazon Linux 2023 blueprint",
   "justify": "Amazon Linux 2023 blueprint id is amazon_linux_2023"
  },
  {
   "id": "bundle_nano",
   "kind": "attr",
   "select": "inst",
   "cond": {
    "path": [
     "BundleId"
    ],
    "op": "regex",
    "value": "(?i)^nano"
   },
   "tier": "core",
   "quote": "a nano bundle",
   "justify": "nano bundle ids start with nano_"
  },
  {
   "id": "disk",
   "kind": "exists",
   "select": "disk",
   "tier": "core",
   "quote": "an attached 8GB disk"
  },
  {
   "id": "disk_size",
   "kind": "attr",
   "select": "disk",
   "cond": {
    "path": [
     "SizeInGb"
    ],
    "op": "eq",
    "value": 8
   },
   "tier": "core",
   "quote": "an attached 8GB disk",
   "justify": "8GB = SizeInGb 8"
  },
  {
   "id": "az_set",
   "kind": "attr",
   "select": "both",
   "cond": {
    "path": [
     "AvailabilityZone"
    ],
    "op": "regex",
    "value": "^[a-z0-9-]+a$"
   },
   "tier": "detail",
   "quote": "both deployed in the first available availability zone",
   "quantifier": "all",
   "justify": "'first available availability zone' is index 0 of Fn::GetAZs, which resolves to the region's 'a' zone; any region is accepted."
  },
  {
   "id": "instance_tag",
   "kind": "attr",
   "select": "inst",
   "cond": {
    "path": [
     "Tags",
     "*"
    ],
    "op": "has_kv",
    "value": {
     "key": "tutorial",
     "value": "stack"
    }
   },
   "tier": "detail",
   "quote": "tagged with a \"tutorial\" key whose value is the stack name",
   "justify": "stack name resolves to the pseudo-parameter value 'stack'"
  },
  {
   "id": "disk_tag",
   "kind": "attr",
   "select": "disk",
   "cond": {
    "path": [
     "Tags",
     "*"
    ],
    "op": "has_kv",
    "value": {
     "key": "tutorial",
     "value": "stack"
    }
   },
   "tier": "detail",
   "quote": "tagged with a \"tutorial\" key whose value is the stack name",
   "justify": "stack name resolves to the pseudo-parameter value 'stack'"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
