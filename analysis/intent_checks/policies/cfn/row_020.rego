package intent.cfn.row_020

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "an": {
   "types": [
    "AWS::AccessAnalyzer::Analyzer"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "analyzer",
   "kind": "exists",
   "select": "an",
   "tier": "core",
   "quote": "creates an IAM Access Analyzer"
  },
  {
   "id": "analyzer_name",
   "kind": "attr",
   "select": "an",
   "cond": {
    "path": [
     "AnalyzerName"
    ],
    "op": "eq",
    "value": "MyAccountAnalyzer"
   },
   "tier": "core",
   "quote": "named \"MyAccountAnalyzer\""
  },
  {
   "id": "analyzer_type_account",
   "kind": "attr",
   "select": "an",
   "cond": {
    "path": [
     "Type"
    ],
    "op": "eq",
    "value": "ACCOUNT"
   },
   "tier": "core",
   "quote": "an IAM Access Analyzer for our account",
   "justify": "for our account implies ACCOUNT type"
  },
  {
   "id": "tag_kind_dev",
   "kind": "attr",
   "select": "an",
   "cond": {
    "path": [
     "Tags",
     "*"
    ],
    "op": "has_kv",
    "value": {
     "key": "Kind",
     "value": "Dev"
    }
   },
   "tier": "detail",
   "quote": "a tag \"Kind\" set to \"Dev\""
  },
  {
   "id": "archive_rules",
   "kind": "attr",
   "select": "an",
   "cond": {
    "path": [
     "ArchiveRules"
    ],
    "op": "len_gte",
    "value": 1
   },
   "tier": "core",
   "quote": "including archive rules to automatically archive findings",
   "justify": "at least one rule"
  },
  {
   "id": "archive_trusted_account",
   "kind": "attr",
   "select": "an",
   "cond": {
    "path": [
     "ArchiveRules",
     "*",
     "Filter",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "Property"
      ],
      "op": "regex",
      "value": "(?i)^principal"
     },
     {
      "path": [],
      "op": "contains",
      "value": "123456789012"
     }
    ]
   },
   "tier": "core",
   "quote": "a trusted principal account \"123456789012\"",
   "justify": "access by a principal is the principal filter property"
  },
  {
   "id": "archive_docs_bucket",
   "kind": "attr",
   "select": "an",
   "cond": {
    "path": [
     "ArchiveRules",
     "*",
     "Filter",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "Property"
      ],
      "op": "regex",
      "value": "(?i)^resource$"
     },
     {
      "path": [],
      "op": "contains",
      "value": "docs-bucket"
     }
    ]
   },
   "tier": "core",
   "quote": "the S3 buckets \"docs-bucket\"",
   "justify": "a bucket is matched by the resource filter property"
  },
  {
   "id": "archive_clients_bucket",
   "kind": "attr",
   "select": "an",
   "cond": {
    "path": [
     "ArchiveRules",
     "*",
     "Filter",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "Property"
      ],
      "op": "regex",
      "value": "(?i)^resource$"
     },
     {
      "path": [],
      "op": "contains",
      "value": "clients-bucket"
     }
    ]
   },
   "tier": "core",
   "quote": "\"clients-bucket\"",
   "justify": "a bucket is matched by the resource filter property"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
