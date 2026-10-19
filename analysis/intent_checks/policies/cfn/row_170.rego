package intent.cfn.row_170

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "lg": {
   "types": [
    "AWS::Logs::LogGroup"
   ],
   "where": []
  },
  "key": {
   "types": [
    "AWS::KMS::Key"
   ],
   "where": []
  },
  "auto_role": {
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
  "ct_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "contains",
     "value": "cloudtrail.amazonaws.com"
    }
   ]
  },
  "autodoc": {
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
  }
 },
 "checks": [
  {
   "id": "log_group_retention_1827",
   "kind": "attr",
   "select": "lg",
   "cond": {
    "path": [
     "RetentionInDays"
    ],
    "op": "eq",
    "value": 1827
   },
   "tier": "core",
   "quote": "a CloudTrail CloudWatch Logs log group with a retention period of 1827 days"
  },
  {
   "id": "kms_key_rotation",
   "kind": "attr",
   "select": "key",
   "cond": {
    "path": [
     "EnableKeyRotation"
    ],
    "op": "truthy"
   },
   "tier": "core",
   "quote": "a KMS customer master key with key rotation enabled"
  },
  {
   "id": "kms_key_policy_root_full_access",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a key policy granting full KMS access to the account root",
   "checks": [
    {
     "kind": "attr",
     "select": "key",
     "cond": {
      "path": [
       "KeyPolicy",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Principal"
        ],
        "op": "contains",
        "value": ":root"
       },
       {
        "path": [
         "Action"
        ],
        "op": "eq",
        "value": "kms:*"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "key",
     "cond": {
      "path": [
       "KeyPolicy",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Principal"
        ],
        "op": "contains",
        "value": ":root"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "eq",
        "value": "kms:*"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "automation_role_managed_policies",
   "kind": "all_of",
   "tier": "core",
   "quote": "an IAM role for the SSM automations to assume that is attached the IAMFullAccess and AdministratorAccess managed policies",
   "checks": [
    {
     "kind": "attr",
     "select": "auto_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "policy/IAMFullAccess$"
     }
    },
    {
     "kind": "attr",
     "select": "auto_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "policy/AdministratorAccess$"
     }
    }
   ]
  },
  {
   "id": "cloudtrail_role",
   "kind": "exists",
   "select": "ct_role",
   "tier": "core",
   "quote": "CloudWatch Logs integration with permissions to write log events"
  },
  {
   "id": "cloudtrail_role_put_log_events",
   "kind": "any_of",
   "tier": "detail",
   "quote": "permissions to write log events",
   "checks": [
    {
     "kind": "attr",
     "select": "ct_role",
     "cond": {
      "path": [
       "Policies"
      ],
      "op": "regex",
      "value": "(?i)logs:(PutLogEvents|\\*)"
     }
    },
    {
     "kind": "ref",
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
        "value": "(?i)logs:(PutLogEvents|\\*)"
       }
      ]
     },
     "to": "ct_role"
    }
   ]
  },
  {
   "id": "cloudtrail_role_log_streams",
   "kind": "any_of",
   "tier": "detail",
   "quote": "manage log groups and streams",
   "checks": [
    {
     "kind": "attr",
     "select": "ct_role",
     "cond": {
      "path": [
       "Policies"
      ],
      "op": "regex",
      "value": "(?i)logs:(CreateLogStream|\\*)"
     }
    },
    {
     "kind": "ref",
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
        "value": "(?i)logs:(CreateLogStream|\\*)"
       }
      ]
     },
     "to": "ct_role"
    }
   ]
  },
  {
   "id": "nine_automation_documents",
   "kind": "exists",
   "select": "autodoc",
   "min": 9,
   "tier": "core",
   "quote": "nine distinct AWS Systems Manager Automation documents"
  },
  {
   "id": "doc_encrypt_trail",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "AWS::SSM::Document"
    ],
    "where": [
     {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)update_?trail"
     },
     {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)kms_?key_?id\\s*(=|\"\\s*:)"
     },
     {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)CloudWatchLogsLogGroupArn"
     }
    ]
   },
   "quote": "encrypts a given CloudTrail trail with a provided KMS key and also integrates it with CloudWatch Logs"
  },
  {
   "id": "doc_enable_key_rotation",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "AWS::SSM::Document"
    ],
    "where": [
     {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)enable_?key_?rotation"
     }
    ]
   },
   "quote": "enables key rotation for a specified KMS key"
  },
  {
   "id": "docs_cloudtrail_cloudwatch_integration",
   "kind": "exists",
   "tier": "detail",
   "min": 1,
   "select": {
    "types": [
     "AWS::SSM::Document"
    ],
    "where": [
     {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)update_?trail"
     },
     {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)CloudWatchLogsLogGroupArn"
     }
    ]
   },
   "quote": "integrates a CloudTrail trail with CloudWatch Logs"
  },
  {
   "id": "doc_password_policy",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "AWS::SSM::Document"
    ],
    "where": [
     {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)update_?account_?password_?policy"
     },
     {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)MinimumPasswordLength\\W{0,5}14\\b"
     },
     {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)MaxPasswordAge\\W{0,5}90\\b"
     },
     {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)PasswordReusePrevention\\W{0,5}24\\b"
     }
    ]
   },
   "quote": "minimum password length of 14"
  },
  {
   "id": "doc_password_policy_flags",
   "kind": "exists",
   "tier": "detail",
   "select": {
    "types": [
     "AWS::SSM::Document"
    ],
    "where": [
     {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)RequireUppercaseCharacters\\W{0,5}true"
     },
     {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)RequireLowercaseCharacters\\W{0,5}true"
     },
     {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)RequireNumbers\\W{0,5}true"
     },
     {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)RequireSymbols\\W{0,5}true"
     },
     {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)AllowUsersToChangePassword\\W{0,5}true"
     },
     {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)HardExpiry\\W{0,5}true"
     }
    ]
   },
   "quote": "require uppercase, lowercase, numbers, symbols, allow password change, set a hard expiry"
  },
  {
   "id": "doc_log_file_validation",
   "kind": "exists",
   "tier": "detail",
   "select": {
    "types": [
     "AWS::SSM::Document"
    ],
    "where": [
     {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)EnableLogFileValidation\\W{0,5}true"
     },
     {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)IsMultiRegionTrail\\W{0,5}true"
     },
     {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)CloudWatchLogsLogGroupArn"
     }
    ]
   },
   "quote": "enables log file validation for a CloudTrail trail while also ensuring multi-region and CloudWatch integration"
  },
  {
   "id": "doc_revoke_default_sg_rules",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "AWS::SSM::Document"
    ],
    "where": [
     {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)revoke_?(security_?group_?)?ingress"
     },
     {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)revoke_?(security_?group_?)?egress"
     }
    ]
   },
   "quote": "revokes all inbound and outbound rules on a given default security group"
  },
  {
   "id": "doc_delete_security_group",
   "kind": "exists",
   "tier": "detail",
   "select": {
    "types": [
     "AWS::SSM::Document"
    ],
    "where": [
     {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)delete_?security_?group"
     }
    ]
   },
   "quote": "deletes a specified security group"
  },
  {
   "id": "doc_release_eip",
   "kind": "exists",
   "tier": "detail",
   "select": {
    "types": [
     "AWS::SSM::Document"
    ],
    "where": [
     {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)release_?address"
     },
     {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)allocation_?id"
     }
    ]
   },
   "quote": "releases an unused Elastic IP address given its allocation ID"
  },
  {
   "id": "doc_codebuild_remove_credentials",
   "kind": "exists",
   "tier": "detail",
   "select": {
    "types": [
     "AWS::SSM::Document"
    ],
    "where": [
     {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)update_?project"
     },
     {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "AWS_ACCESS_KEY_ID"
     },
     {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "AWS_SECRET_ACCESS_KEY"
     }
    ]
   },
   "quote": "updates a CodeBuild project to remove any environment variables named AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY"
  },
  {
   "id": "all_outputs_exported",
   "kind": "attr",
   "select": {
    "types": [
     "__output__"
    ],
    "where": []
   },
   "quantifier": "all",
   "cond": {
    "path": [
     "export"
    ],
    "op": "present"
   },
   "tier": "detail",
   "quote": "with all outputs exported"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
