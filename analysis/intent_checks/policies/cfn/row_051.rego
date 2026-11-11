package intent.cfn.row_051

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "sm": {
   "types": [
    "AWS::StepFunctions::StateMachine"
   ],
   "where": []
  },
  "role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "sm_exec_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "regex",
     "value": "states\\.amazonaws\\.com"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "state_machine",
   "kind": "exists",
   "tier": "core",
   "quote": "a basic Step Functions state machine",
   "select": "sm"
  },
  {
   "id": "sm_name",
   "kind": "attr",
   "tier": "core",
   "quote": "named \"MyBasicStateMachine\"",
   "select": "sm",
   "cond": {
    "path": [
     "StateMachineName"
    ],
    "op": "eq",
    "value": "MyBasicStateMachine"
   }
  },
  {
   "id": "sm_type",
   "kind": "attr",
   "tier": "core",
   "quote": "of type STANDARD",
   "select": "sm",
   "cond": {
    "path": [
     "StateMachineType"
    ],
    "op": "none_eq",
    "value": "EXPRESS"
   },
   "justify": "STANDARD is the only other type and the default, so an omitted type is STANDARD"
  },
  {
   "id": "two_pass_states",
   "kind": "attr",
   "tier": "core",
   "quote": "execute a simple two-step workflow using Pass states",
   "justify": "two Pass states means two entries with Type Pass",
   "select": "sm",
   "cond": {
    "path": [],
    "op": "regex",
    "value": "(?is)type\\W+pass\\b.*type\\W+pass\\b"
   }
  },
  {
   "id": "hello_world_outputs",
   "kind": "attr",
   "tier": "detail",
   "quote": "outputs \"Hello\" followed by \"World\"",
   "select": "sm",
   "cond": {
    "path": [],
    "op": "regex",
    "value": "(?is)(result|parameters|output)\\W{1,10}(\\w+\\W{1,10})?hello\\b.*(result|parameters|output)\\W{1,10}(\\w+\\W{1,10})?world\\b"
   }
  },
  {
   "id": "sm_role",
   "kind": "exists",
   "tier": "core",
   "quote": "include the necessary IAM role for Step Functions to execute",
   "select": "role"
  },
  {
   "id": "sm_role_trust",
   "kind": "ref",
   "tier": "detail",
   "quote": "IAM role for Step Functions to execute",
   "justify": "the state machine's role trusts states.amazonaws.com",
   "from": "sm",
   "to": "sm_exec_role"
  },
  {
   "id": "sm_uses_role",
   "kind": "ref",
   "tier": "core",
   "quote": "include the necessary IAM role for Step Functions to execute",
   "from": "sm",
   "to": "role"
  },
  {
   "id": "sm_tag",
   "kind": "attr",
   "tier": "detail",
   "quote": "tagging the resources with the key \"stateMachine:createdBy\" and value \"SAM\"",
   "select": "sm",
   "cond": {
    "path": [
     "Tags",
     "*"
    ],
    "op": "has_kv",
    "value": {
     "key": "stateMachine:createdBy",
     "value": "SAM"
    }
   }
  },
  {
   "id": "role_tag",
   "kind": "attr",
   "tier": "detail",
   "quote": "tagging the resources with the key \"stateMachine:createdBy\" and value \"SAM\"",
   "select": "role",
   "cond": {
    "path": [
     "Tags",
     "*"
    ],
    "op": "has_kv",
    "value": {
     "key": "stateMachine:createdBy",
     "value": "SAM"
    }
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
