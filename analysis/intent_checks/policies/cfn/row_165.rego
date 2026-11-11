package intent.cfn.row_165

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "rule": {
   "types": [
    "AWS::Events::Rule"
   ],
   "where": []
  },
  "doc": {
   "types": [
    "AWS::SSM::Document"
   ],
   "where": []
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
  "ev_role": {
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
  "role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "new_account_rule": {
   "types": [
    "AWS::Events::Rule"
   ],
   "where": [
    {
     "path": [
      "EventPattern"
     ],
     "op": "regex",
     "value": "(?i)createmanagedaccount"
    }
   ]
  },
  "landing_zone_rule": {
   "types": [
    "AWS::Events::Rule"
   ],
   "where": [
    {
     "path": [
      "EventPattern"
     ],
     "op": "regex",
     "value": "(?i)landing.?zone"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "event_rules",
   "kind": "exists",
   "select": "rule",
   "tier": "core",
   "quote": "EventBridge rules that react to the Control Tower lifecycle events",
   "min": 2,
   "justify": "one rule for new managed accounts and one for landing zone setup or update finished"
  },
  {
   "id": "rule_new_account",
   "kind": "attr",
   "select": "rule",
   "cond": {
    "path": [
     "EventPattern"
    ],
    "op": "regex",
    "value": "(?i)createmanagedaccount"
   },
   "tier": "core",
   "quote": "a new account was successfully provisioned",
   "justify": "Control Tower reports account provisioning as CreateManagedAccount"
  },
  {
   "id": "rule_succeeded",
   "kind": "attr",
   "select": "new_account_rule",
   "cond": {
    "path": [
     "EventPattern"
    ],
    "op": "regex",
    "value": "(?i)succe"
   },
   "tier": "core",
   "quote": "a new account was successfully provisioned",
   "justify": "successfully provisioned means state SUCCEEDED"
  },
  {
   "id": "rule_controltower_source",
   "kind": "attr",
   "select": "rule",
   "cond": {
    "path": [
     "EventPattern"
    ],
    "op": "regex",
    "value": "(?i)controltower"
   },
   "tier": "detail",
   "quote": "react to the Control Tower lifecycle events"
  },
  {
   "id": "rule_landing_zone",
   "kind": "attr",
   "select": "rule",
   "cond": {
    "path": [
     "EventPattern"
    ],
    "op": "regex",
    "value": "(?i)landing.?zone"
   },
   "tier": "core",
   "quote": "the landing zone setup or update has finished"
  },
  {
   "id": "rule_lz_setup_and_update",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": "landing_zone_rule",
     "cond": {
      "path": [
       "EventPattern"
      ],
      "op": "regex",
      "value": "(?i)setup"
     }
    },
    {
     "kind": "attr",
     "select": "landing_zone_rule",
     "cond": {
      "path": [
       "EventPattern"
      ],
      "op": "regex",
      "value": "(?i)update"
     }
    }
   ],
   "tier": "detail",
   "quote": "the landing zone setup or update has finished"
  },
  {
   "id": "rules_invoke_automation",
   "kind": "attr",
   "select": "rule",
   "cond": {
    "path": [
     "Targets",
     "*",
     "Arn"
    ],
    "op": "contains",
    "value": "automation-definition"
   },
   "quantifier": "all",
   "tier": "core",
   "quote": "invoking SSM automation documents"
  },
  {
   "id": "automation_docs",
   "kind": "exists",
   "select": "doc",
   "tier": "core",
   "quote": "SSM automation documents that handle the cross-account enablement, member invitation, and acceptance workflows",
   "min": 1,
   "justify": "the prompt says documents handle the workflows but does not guarantee a separate document for each"
  },
  {
   "id": "docs_are_automation",
   "kind": "attr",
   "select": "doc",
   "cond": {
    "path": [
     "DocumentType"
    ],
    "op": "eq",
    "value": "Automation"
   },
   "tier": "core",
   "quote": "SSM automation documents"
  },
  {
   "id": "doc_enable_security_hub",
   "kind": "attr",
   "select": "doc",
   "cond": {
    "path": [
     "Content"
    ],
    "op": "regex",
    "value": "(?i)(api\"?:\\s*\"?enable_?(securityhub|organizationadminaccount)|enable[-_]security[-_]hub|enable[-_]organization[-_]admin)"
   },
   "tier": "core",
   "quote": "automatically enable Security Hub",
   "justify": "the Security Hub enable API or the delegated-admin API, by its API, boto3 or CLI name"
  },
  {
   "id": "doc_invite_members",
   "kind": "attr",
   "select": "doc",
   "cond": {
    "path": [
     "Content"
    ],
    "op": "regex",
    "value": "(?i)invite[-_]?members"
   },
   "tier": "core",
   "quote": "member invitation",
   "justify": "the Security Hub InviteMembers API"
  },
  {
   "id": "doc_create_members",
   "kind": "attr",
   "select": "doc",
   "cond": {
    "path": [
     "Content"
    ],
    "op": "regex",
    "value": "(?i)create[-_]?members"
   },
   "tier": "core",
   "quote": "adding them as members",
   "justify": "the Security Hub CreateMembers API"
  },
  {
   "id": "doc_accept_invitation",
   "kind": "attr",
   "select": "doc",
   "cond": {
    "path": [
     "Content"
    ],
    "op": "regex",
    "value": "(?i)accept[-_]?(administrator[-_]?)?invitation"
   },
   "tier": "core",
   "quote": "acceptance workflows",
   "justify": "the Security Hub AcceptInvitation or AcceptAdministratorInvitation API"
  },
  {
   "id": "control_tower_execution_role",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "doc",
     "cond": {
      "path": [
       "Content"
      ],
      "op": "contains",
      "value": "AWSControlTowerExecution"
     }
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "Policies"
      ],
      "op": "contains",
      "value": "AWSControlTowerExecution"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::RolePolicy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "contains",
      "value": "AWSControlTowerExecution"
     }
    }
   ],
   "tier": "core",
   "quote": "named \"AWSControlTowerExecution\""
  },
  {
   "id": "superwerker_path",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "doc",
     "cond": {
      "path": [
       "Content"
      ],
      "op": "contains",
      "value": "/superwerker/"
     }
    },
    {
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
      "op": "contains",
      "value": "/superwerker/"
     }
    }
   ],
   "tier": "core",
   "quote": "stored under the \"/superwerker/\" path in Parameter Store"
  },
  {
   "id": "superwerker_audit_id",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "doc",
     "cond": {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)/superwerker/[^\"\\s]*audit"
     }
    },
    {
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
      "op": "regex",
      "value": "(?i)/superwerker/[^\"\\s]*audit"
     }
    }
   ],
   "tier": "detail",
   "quote": "read the audit and log archive account IDs from configuration values stored under the \"/superwerker/\" path in Parameter Store",
   "justify": "the audit account ID is a value under this path"
  },
  {
   "id": "superwerker_logarchive_id",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "doc",
     "cond": {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)/superwerker/[^\"\\s]*log.?archive"
     }
    },
    {
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
      "op": "regex",
      "value": "(?i)/superwerker/[^\"\\s]*log.?archive"
     }
    }
   ],
   "tier": "detail",
   "quote": "read the audit and log archive account IDs from configuration values stored under the \"/superwerker/\" path in Parameter Store",
   "justify": "the log archive account ID is a value under this path"
  },
  {
   "id": "iam_roles",
   "kind": "exists",
   "select": "role",
   "tier": "core",
   "quote": "define all required IAM roles",
   "min": 1
  },
  {
   "id": "automation_assume_role",
   "kind": "exists",
   "select": "ssm_role",
   "tier": "detail",
   "quote": "define all required IAM roles",
   "min": 1,
   "justify": "SSM automation documents assume an IAM role trusted by ssm.amazonaws.com"
  },
  {
   "id": "events_invoke_role",
   "kind": "ref",
   "from": "rule",
   "to": "ev_role",
   "tier": "detail",
   "quote": "invoking SSM automation documents",
   "justify": "EventBridge needs an events.amazonaws.com role to start automation"
  },
  {
   "id": "read_parameters_permission",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
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
         "Action",
         "*"
        ],
        "op": "regex",
        "value": "(?i)^(ssm:(\\*|get\\*|getparam.*)|\\*)$"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "(?i)(superwerker|^\\*$)"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::RolePolicy"
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
           "Action",
           "*"
          ],
          "op": "regex",
          "value": "(?i)^(ssm:(\\*|get\\*|getparam.*)|\\*)$"
         },
         {
          "path": [
           "Resource",
           "*"
          ],
          "op": "regex",
          "value": "(?i)(superwerker|^\\*$)"
         }
        ]
       }
      ]
     },
     "to": "role",
     "bidirectional": true
    }
   ],
   "tier": "detail",
   "quote": "read the audit and log archive account IDs from configuration values stored under the \"/superwerker/\" path in Parameter Store"
  },
  {
   "id": "x_rules_enabled",
   "kind": "attr",
   "select": "rule",
   "cond": {
    "path": [
     "State"
    ],
    "op": "eq",
    "value": "ENABLED"
   },
   "tier": "extra",
   "quantifier": "all"
  },
  {
   "id": "x_rule_transformer",
   "kind": "attr",
   "select": "rule",
   "cond": {
    "path": [
     "Targets",
     "*",
     "InputTransformer"
    ],
    "op": "present"
   },
   "tier": "extra"
  },
  {
   "id": "x_start_automation_permission",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
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
      "value": "ssm:StartAutomationExecution"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "ssm:StartAutomationExecution"
     }
    }
   ],
   "tier": "extra"
  },
  {
   "id": "x_assume_ct_role_permission",
   "kind": "attr",
   "select": "role",
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
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "sts:AssumeRole"
     },
     {
      "path": [
       "Resource",
       "*"
      ],
      "op": "contains",
      "value": "AWSControlTowerExecution"
     }
    ]
   },
   "tier": "extra"
  },
  {
   "id": "x_org_lookup",
   "kind": "attr",
   "select": "doc",
   "cond": {
    "path": [
     "Content"
    ],
    "op": "regex",
    "value": "(?i)organizations"
   },
   "tier": "extra"
  },
  {
   "id": "x_doc_schema",
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
   "tier": "extra",
   "quantifier": "all"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
