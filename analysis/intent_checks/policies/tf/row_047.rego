# GENERATED from specs/tf/row_047.json by intent_checks/build.py -- do not edit.
package intent.tf.row_047

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "user_tj": {
   "types": [
    "aws_iam_user"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "TJ"
    }
   ]
  },
  "named_policy": {
   "types": [
    "aws_iam_policy",
    "aws_iam_user_policy"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "GlacierEFSEC2"
    }
   ]
  },
  "policy_doc": {
   "types": [
    "aws_iam_policy",
    "aws_iam_user_policy",
    "data.aws_iam_policy_document"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "iam_user_tj",
   "kind": "exists",
   "select": "user_tj",
   "tier": "core",
   "quote": "an IAM user named \"TJ\""
  },
  {
   "id": "policy_named_glacierefsec2",
   "kind": "exists",
   "select": "named_policy",
   "tier": "core",
   "quote": "a custom IAM policy named \"GlacierEFSEC2\""
  },
  {
   "id": "policy_attached_to_user",
   "kind": "any_of",
   "tier": "core",
   "quote": "with a custom IAM policy named \"GlacierEFSEC2\" attached",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_user_policy_attachment",
       "aws_iam_policy_attachment"
      ],
      "where": []
     },
     "to": "user_tj"
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_user_policy_attachment"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "user"
      ],
      "op": "eq",
      "value": "TJ"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "users",
       "*"
      ],
      "op": "eq",
      "value": "TJ"
     }
    },
    {
     "kind": "ref",
     "from": "named_policy",
     "to": "user_tj"
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_user_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "user"
      ],
      "op": "eq",
      "value": "TJ"
     }
    }
   ]
  },
  {
   "id": "ec2_management_permissions",
   "kind": "attr",
   "select": "policy_doc",
   "tier": "core",
   "quote": "granting a broad set of EC2 management permissions",
   "cond": {
    "path": [],
    "op": "regex",
    "value": "(?i)ec2:(\\*|[a-z]*(Run|Create|Stop|Start|Terminate|Modify|Delete|Attach|Associate)[a-z]*)"
   }
  },
  {
   "id": "efs_client_mount",
   "kind": "attr",
   "select": "policy_doc",
   "tier": "core",
   "quote": "EFS client-mount access",
   "cond": {
    "path": [],
    "op": "regex",
    "value": "(?i)elasticfilesystem:(ClientMount|Client\\*|\\*)"
   }
  },
  {
   "id": "glacier_vault_permissions",
   "kind": "attr",
   "select": "policy_doc",
   "tier": "detail",
   "quote": "Glacier vault",
   "cond": {
    "path": [],
    "op": "regex",
    "value": "(?i)glacier:([a-z]*vault[a-z]*|\\*)"
   }
  },
  {
   "id": "glacier_multipart_permissions",
   "kind": "attr",
   "select": "policy_doc",
   "tier": "detail",
   "quote": "multipart-upload permissions",
   "cond": {
    "path": [],
    "op": "regex",
    "value": "(?i)glacier:([a-z]*multipart[a-z]*|\\*)"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
