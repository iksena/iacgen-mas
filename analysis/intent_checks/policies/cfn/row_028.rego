package intent.cfn.row_028

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "api": {
   "types": [
    "AWS::AppSync::GraphQLApi"
   ],
   "where": []
  },
  "acl": {
   "types": [
    "AWS::WAFv2::WebACL"
   ],
   "where": []
  },
  "assoc": {
   "types": [
    "AWS::WAFv2::WebACLAssociation"
   ],
   "where": []
  },
  "good_acl": {
   "types": [
    "AWS::WAFv2::WebACL"
   ],
   "where": [
    {
     "path": [
      "Scope"
     ],
     "op": "eq",
     "value": "REGIONAL"
    },
    {
     "path": [
      "DefaultAction"
     ],
     "op": "regex",
     "value": "(?i)block"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "two_apis",
   "kind": "exists",
   "select": "api",
   "tier": "core",
   "quote": "two AppSync GraphQL APIs",
   "min": 2,
   "max": 2
  },
  {
   "id": "api_key_auth",
   "kind": "attr",
   "select": "api",
   "cond": {
    "path": [
     "AuthenticationType"
    ],
    "op": "eq",
    "value": "API_KEY"
   },
   "tier": "core",
   "quote": "Both APIs should use API key authentication",
   "quantifier": "all"
  },
  {
   "id": "webacl",
   "kind": "exists",
   "select": "acl",
   "tier": "core",
   "quote": "a regional WAF WebACL"
  },
  {
   "id": "acl_regional",
   "kind": "attr",
   "select": "acl",
   "cond": {
    "path": [
     "Scope"
    ],
    "op": "eq",
    "value": "REGIONAL"
   },
   "tier": "core",
   "quote": "a regional WAF WebACL"
  },
  {
   "id": "acl_default_block",
   "kind": "attr",
   "select": "acl",
   "cond": {
    "path": [
     "DefaultAction"
    ],
    "op": "regex",
    "value": "(?i)block"
   },
   "tier": "core",
   "quote": "with a default block action"
  },
  {
   "id": "association",
   "kind": "exists",
   "select": "assoc",
   "tier": "core",
   "quote": "the WAF must be associated with the first API"
  },
  {
   "id": "assoc_to_acl",
   "kind": "ref",
   "from": "assoc",
   "to": "good_acl",
   "tier": "core",
   "quote": "the WAF must be associated with the first API",
   "justify": "regional and default block are the prompt's own terms for the WebACL"
  },
  {
   "id": "assoc_to_api",
   "kind": "ref",
   "from": "assoc",
   "to": "api",
   "tier": "core",
   "quote": "the WAF must be associated with the first API"
  },
  {
   "id": "other_api_no_waf",
   "kind": "exists",
   "select": "assoc",
   "min": 1,
   "max": 1,
   "tier": "core",
   "quote": "the other should have no WAF attached",
   "justify": "one association protects one API, so a second association would attach a WAF to the other API"
  },
  {
   "id": "x_acl_metrics",
   "kind": "attr",
   "select": "acl",
   "tier": "extra",
   "cond": {
    "path": [
     "VisibilityConfig",
     "CloudWatchMetricsEnabled"
    ],
    "op": "truthy"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
