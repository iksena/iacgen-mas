# GENERATED from specs/cfn/row_047.json by intent_checks/build.py -- do not edit.
package intent.cfn.row_047

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "space": {
   "types": [
    "AWS::DevOpsAgent::AgentSpace"
   ],
   "where": []
  },
  "assoc": {
   "types": [
    "AWS::DevOpsAgent::Association"
   ],
   "where": []
  },
  "aidevops_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "contains",
     "value": "aidevops.amazonaws.com"
    }
   ]
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
   "id": "agent_space",
   "kind": "exists",
   "select": "space",
   "tier": "core",
   "quote": "creates a DevOps Agent Space"
  },
  {
   "id": "two_aidevops_roles",
   "kind": "exists",
   "select": "aidevops_role",
   "min": 2,
   "tier": "core",
   "quote": "IAM roles for the agent service and operator application, configures trust relationships allowing the aidevops.amazonaws.com service to assume these roles",
   "justify": "one role for the agent service and one for the operator application, both trusting aidevops.amazonaws.com"
  },
  {
   "id": "trust_source_account_condition",
   "kind": "attr",
   "select": "aidevops_role",
   "quantifier": "all",
   "tier": "core",
   "quote": "with source account and source ARN conditions",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument"
    ],
    "op": "regex",
    "value": "(?i)aws:sourceaccount"
   }
  },
  {
   "id": "trust_source_arn_condition",
   "kind": "attr",
   "select": "aidevops_role",
   "quantifier": "all",
   "tier": "core",
   "quote": "with source account and source ARN conditions",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument"
    ],
    "op": "regex",
    "value": "(?i)aws:sourcearn"
   }
  },
  {
   "id": "managed_policies_attached",
   "kind": "any_of",
   "tier": "detail",
   "quote": "attaches necessary managed policies to each role",
   "checks": [
    {
     "kind": "attr",
     "select": "aidevops_role",
     "quantifier": "all",
     "cond": {
      "path": [
       "ManagedPolicyArns"
      ],
      "op": "present"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::ManagedPolicy"
      ],
      "where": []
     },
     "to": "aidevops_role"
    }
   ]
  },
  {
   "id": "inline_create_slr",
   "kind": "any_of",
   "tier": "core",
   "quote": "an inline policy allowing the agent role to create service-linked roles",
   "checks": [
    {
     "kind": "attr",
     "select": "aidevops_role",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "iam:CreateServiceLinkedRole"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "iam:CreateServiceLinkedRole"
       }
      ]
     },
     "to": "aidevops_role"
    }
   ]
  },
  {
   "id": "operator_role_on_space",
   "kind": "ref",
   "from": "space",
   "to": "aidevops_role",
   "tier": "detail",
   "quote": "IAM roles for the agent service and operator application",
   "bidirectional": true
  },
  {
   "id": "account_association",
   "kind": "ref",
   "from": "assoc",
   "to": "space",
   "tier": "core",
   "quote": "associates the current AWS account as a primary monitoring account"
  },
  {
   "id": "association_monitor_type",
   "kind": "attr",
   "select": "assoc",
   "tier": "core",
   "quote": "as a primary monitoring account",
   "cond": {
    "path": [],
    "op": "regex",
    "value": "(?i)monitor"
   },
   "justify": "a monitoring account association is AccountType monitor"
  },
  {
   "id": "outputs_count",
   "kind": "exists",
   "select": "out",
   "min": 6,
   "tier": "detail",
   "quote": "outputs the agent space ID, ARN, name, operator URL, and both role ARNs",
   "justify": "the prompt lists six outputs (ID, ARN, name, operator URL, two role ARNs)"
  },
  {
   "id": "output_agent_space",
   "kind": "ref",
   "from": "out",
   "to": "space",
   "tier": "detail",
   "quote": "outputs the agent space ID, ARN"
  },
  {
   "id": "output_role_arn",
   "kind": "ref",
   "from": "out",
   "to": "aidevops_role",
   "tier": "detail",
   "quote": "both role ARNs"
  },
  {
   "id": "output_operator_url",
   "kind": "any_of",
   "tier": "detail",
   "quote": "operator URL",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "__output__"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)url"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__output__"
      ],
      "where": [
       {
        "path": [
         "value"
        ],
        "op": "regex",
        "value": "(?i)https?://"
       }
      ]
     }
    }
   ],
   "justify": "an operator URL output holds an http(s) address"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
