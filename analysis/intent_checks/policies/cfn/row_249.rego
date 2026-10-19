package intent.cfn.row_249

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "doc": {
   "types": [
    "AWS::SSM::Document"
   ],
   "where": [
    {
     "path": [
      "DocumentType"
     ],
     "op": "eq",
     "value": "Automation"
    }
   ]
  },
  "ssm_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "contains",
     "value": "ssm.amazonaws.com"
    }
   ]
  },
  "events_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "contains",
     "value": "events.amazonaws.com"
    }
   ]
  },
  "rule": {
   "types": [
    "AWS::Events::Rule"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "ssm_automation_document",
   "kind": "exists",
   "select": "doc",
   "tier": "core",
   "quote": "provision an SSM Automation document"
  },
  {
   "id": "schema_version_03",
   "kind": "attr",
   "select": "doc",
   "cond": {
    "path": [
     "Content",
     "schemaVersion"
    ],
    "op": "eq",
    "value": "0.3"
   },
   "tier": "core",
   "quote": "running schema version 0.3"
  },
  {
   "id": "put_public_access_block_api",
   "kind": "attr",
   "select": "doc",
   "cond": {
    "path": [
     "Content"
    ],
    "op": "regex",
    "value": "(?i)s3control[\\s\\S]*PutPublicAccessBlock|PutPublicAccessBlock[\\s\\S]*s3control"
   },
   "tier": "core",
   "quote": "executes the S3 Control PutPublicAccessBlock API operation"
  },
  {
   "id": "block_flags_enabled",
   "kind": "all_of",
   "tier": "core",
   "quote": "enable BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, and RestrictPublicBuckets",
   "checks": [
    {
     "kind": "attr",
     "select": "doc",
     "cond": {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)BlockPublicAcls\\W*true"
     }
    },
    {
     "kind": "attr",
     "select": "doc",
     "cond": {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)BlockPublicPolicy\\W*true"
     }
    },
    {
     "kind": "attr",
     "select": "doc",
     "cond": {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)IgnorePublicAcls\\W*true"
     }
    },
    {
     "kind": "attr",
     "select": "doc",
     "cond": {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)RestrictPublicBuckets\\W*true"
     }
    }
   ]
  },
  {
   "id": "local_account",
   "kind": "attr",
   "select": "doc",
   "cond": {
    "path": [
     "Content"
    ],
    "op": "regex",
    "value": "(?i)AccountId\\W*(\\{\\{\\s*global:ACCOUNT_ID|123456789012)"
   },
   "tier": "detail",
   "quote": "for the local account"
  },
  {
   "id": "ssm_role_exists",
   "kind": "exists",
   "select": "ssm_role",
   "tier": "core",
   "quote": "an IAM role for Systems Manager trusting \"ssm.amazonaws.com\""
  },
  {
   "id": "ssm_role_put_permission",
   "kind": "any_of",
   "tier": "core",
   "quote": "permissions for s3:PutAccountPublicAccessBlock",
   "checks": [
    {
     "kind": "attr",
     "select": "ssm_role",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Action"
        ],
        "op": "regex",
        "value": "(?i)s3:(\\*|PutAccountPublicAccessBlock)"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "ssm_role",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "Action"
          ],
          "op": "regex",
          "value": "(?i)s3:(\\*|PutAccountPublicAccessBlock)"
         }
        ]
       }
      ]
     }
    }
   ]
  },
  {
   "id": "ssm_role_get_permission",
   "kind": "any_of",
   "tier": "detail",
   "quote": "s3:GetAccountPublicAccessBlock",
   "checks": [
    {
     "kind": "attr",
     "select": "ssm_role",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Action"
        ],
        "op": "regex",
        "value": "(?i)s3:(\\*|GetAccountPublicAccessBlock)"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "ssm_role",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "Action"
          ],
          "op": "regex",
          "value": "(?i)s3:(\\*|GetAccountPublicAccessBlock)"
         }
        ]
       }
      ]
     }
    }
   ]
  },
  {
   "id": "ssm_role_permissions_all_resources",
   "kind": "any_of",
   "tier": "detail",
   "quote": "on all resources",
   "checks": [
    {
     "kind": "attr",
     "select": "ssm_role",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Action"
        ],
        "op": "regex",
        "value": "(?i)s3:(\\*|PutAccountPublicAccessBlock)"
       },
       {
        "path": [
         "Resource"
        ],
        "op": "regex",
        "value": "^\\[?\"?\\*\"?\\]?$"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "ssm_role",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "Action"
          ],
          "op": "regex",
          "value": "(?i)s3:(\\*|PutAccountPublicAccessBlock)"
         },
         {
          "path": [
           "Resource"
          ],
          "op": "regex",
          "value": "^\\[?\"?\\*\"?\\]?$"
         }
        ]
       }
      ]
     }
    }
   ]
  },
  {
   "id": "events_role_exists",
   "kind": "exists",
   "select": "events_role",
   "tier": "core",
   "quote": "an IAM role for EventBridge trusting \"events.amazonaws.com\""
  },
  {
   "id": "events_role_start_automation",
   "kind": "any_of",
   "tier": "detail",
   "quote": "with permissions to start the SSM Automation document execution",
   "checks": [
    {
     "kind": "attr",
     "select": "events_role",
     "cond": {
      "path": [
       "Policies"
      ],
      "op": "regex",
      "value": "(?i)ssm:(\\*|StartAutomationExecution)"
     }
    },
    {
     "kind": "ref",
     "to": "events_role",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument"
        ],
        "op": "regex",
        "value": "(?i)ssm:(\\*|StartAutomationExecution)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "rule_daily_rate",
   "kind": "attr",
   "select": "rule",
   "cond": {
    "path": [
     "ScheduleExpression"
    ],
    "op": "regex",
    "value": "^rate\\(\\s*(1\\s+days?|24\\s+hours?)\\s*\\)$"
   },
   "tier": "core",
   "quote": "scheduled rule running on a daily rate expression"
  },
  {
   "id": "rule_enabled",
   "kind": "attr",
   "select": "rule",
   "cond": {
    "path": [
     "State"
    ],
    "op": "eq",
    "value": "ENABLED"
   },
   "tier": "detail",
   "quote": "an enabled EventBridge scheduled rule"
  },
  {
   "id": "rule_targets_document",
   "kind": "ref",
   "from": "rule",
   "to": "doc",
   "tier": "core",
   "quote": "targets the created SSM Automation document"
  },
  {
   "id": "rule_uses_events_role",
   "kind": "ref",
   "from": "rule",
   "to": "events_role",
   "tier": "detail",
   "quote": "using the EventBridge execution role"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
