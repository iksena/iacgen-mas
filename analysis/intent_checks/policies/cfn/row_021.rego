package intent.cfn.row_021

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "ns": {
   "types": [
    "AWS::ServiceDiscovery::HttpNamespace"
   ],
   "where": []
  },
  "sv": {
   "types": [
    "AWS::ServiceDiscovery::Service"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "http_namespace",
   "kind": "exists",
   "select": "ns",
   "tier": "core",
   "quote": "creates an HTTP namespace for service discovery"
  },
  {
   "id": "namespace_name_stack",
   "kind": "attr",
   "select": "ns",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "regex",
    "value": "(?i)(^|[^a-z0-9])stack([^a-z0-9]|$)"
   },
   "tier": "core",
   "quote": "named after the stack name",
   "justify": "the prompt asks for the stack name; the adapter renders AWS::StackName as stack, and a prefix or suffix still counts as named after it"
  },
  {
   "id": "namespace_tag",
   "kind": "attr",
   "select": "ns",
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
      "value": "tutorial"
     },
     {
      "path": [
       "Value"
      ],
      "op": "eq",
      "value": "stack"
     }
    ]
   },
   "tier": "detail",
   "quote": "tagged with a \"tutorial\" key set to the stack name",
   "justify": "the prompt asks for the stack name; the adapter renders AWS::StackName as stack"
  },
  {
   "id": "service",
   "kind": "exists",
   "select": "sv",
   "tier": "core",
   "quote": "a service"
  },
  {
   "id": "service_name",
   "kind": "attr",
   "select": "sv",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "eq",
    "value": "web"
   },
   "tier": "core",
   "quote": "a service named \"web\""
  },
  {
   "id": "service_in_namespace",
   "kind": "ref",
   "from": "sv",
   "to": "ns",
   "tier": "core",
   "quote": "a service named \"web\" within that namespace"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
