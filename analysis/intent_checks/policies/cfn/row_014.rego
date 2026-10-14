# GENERATED from specs/cfn/row_014.json by intent_checks/build.py -- do not edit.
package intent.cfn.row_014

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "param": {
   "types": [
    "AWS::SSM::Parameter"
   ],
   "where": []
  },
  "out": {
   "types": [
    "__output__"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "wait_condition_handle",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::CloudFormation::WaitConditionHandle"
    ],
    "where": []
   },
   "tier": "core",
   "quote": "including a WaitConditionHandle"
  },
  {
   "id": "wait_handle_metadata",
   "kind": "all_of",
   "tier": "detail",
   "quote": "a WaitConditionHandle with metadata containing a greeting message and a timestamp",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::CloudFormation::WaitConditionHandle"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "__resource__",
       "Metadata"
      ],
      "op": "regex",
      "value": "(?i)(hello|greet|welcome|world)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::CloudFormation::WaitConditionHandle"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "__resource__",
       "Metadata"
      ],
      "op": "regex",
      "value": "(?i)(time|date)"
     }
    }
   ]
  },
  {
   "id": "ssm_parameter_path",
   "kind": "attr",
   "select": "param",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "regex",
    "value": "^/iidy/template-approval/test/"
   },
   "tier": "core",
   "quote": "an SSM parameter stored under the path \"/iidy/template-approval/test/\""
  },
  {
   "id": "name_parameter_default_world",
   "kind": "attr",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": "World"
   },
   "tier": "detail",
   "quote": "a name parameter that defaults to \"World\""
  },
  {
   "id": "value_stack_id",
   "kind": "attr",
   "select": "param",
   "cond": {
    "path": [
     "Value"
    ],
    "op": "contains",
    "value": "arn:aws:cloudformation:"
   },
   "tier": "detail",
   "quote": "a JSON string including the stack name, stack ID",
   "justify": "\"stack ID\" = AWS::StackId, which resolves to a CloudFormation stack ARN"
  },
  {
   "id": "value_stack_name",
   "kind": "attr",
   "select": "param",
   "cond": {
    "path": [
     "Value"
    ],
    "op": "regex",
    "value": ":\\s*\"stack\"\\s*[,}\\n]"
   },
   "tier": "detail",
   "quote": "a JSON string including the stack name"
  },
  {
   "id": "value_message",
   "kind": "attr",
   "select": "param",
   "cond": {
    "path": [
     "Value"
    ],
    "op": "contains",
    "value": "Hello from CloudFormation"
   },
   "tier": "core",
   "quote": "a custom message defaulting to \"Hello from CloudFormation\""
  },
  {
   "id": "value_approval_enabled",
   "kind": "attr",
   "select": "param",
   "cond": {
    "path": [
     "Value"
    ],
    "op": "regex",
    "value": "(?i)approval[^,}]*(enabled|true)"
   },
   "tier": "core",
   "quote": "an indication that the approval workflow is enabled"
  },
  {
   "id": "output_parameter_name",
   "kind": "ref",
   "from": "out",
   "to": "param",
   "tier": "detail",
   "quote": "output the parameter name"
  },
  {
   "id": "output_greeting",
   "kind": "attr",
   "select": "out",
   "cond": {
    "path": [
     "value"
    ],
    "op": "regex",
    "value": "(?i)(hello|greet|welcome|world)"
   },
   "tier": "detail",
   "quote": "a greeting message"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
