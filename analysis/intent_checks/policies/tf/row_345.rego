package intent.tf.row_345

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "pol": {
   "types": [
    "aws_iam_policy"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "policy_named",
   "kind": "attr",
   "tier": "core",
   "select": "pol",
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "managed-force-mfa-policy"
   },
   "quote": "customer-managed IAM policy named \"managed-force-mfa-policy\""
  },
  {
   "id": "policy_path",
   "kind": "attr",
   "tier": "core",
   "select": "pol",
   "cond": {
    "path": [
     "path"
    ],
    "op": "eq",
    "value": "/"
   },
   "quote": "at path \"/\""
  },
  {
   "id": "basic_info",
   "tier": "core",
   "quote": "lets IAM users view basic account information",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)\\{\"Action\":(?:\"(?:iam:(?:GetAccountSummary|ListAccountAliases|GetAccountPasswordPolicy|GetAccount\\*|Get\\*|List\\*|\\*)|\\*)\"|\\[(?:\"[^\"]*\",)*\"(?:iam:(?:GetAccountSummary|ListAccountAliases|GetAccountPasswordPolicy|GetAccount\\*|Get\\*|List\\*|\\*)|\\*)\"(?:,\"[^\"]*\")*\\]),(?:\"Condition\":\\{(?:[^{}]|\\{[^{}]*\\})*\\},)?\"Effect\":\"Allow\""
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "effect"
        ],
        "op": "none_eq",
        "value": "deny"
       },
       {
        "path": [
         "actions",
         "*"
        ],
        "op": "regex",
        "value": "(?i)^(iam:(GetAccountSummary|ListAccountAliases|GetAccountPasswordPolicy|GetAccount\\*|Get\\*|List\\*|\\*)|\\*)$"
       }
      ]
     }
    }
   ],
   "justify": "'lets ... view' means an Allow (effect not deny) granting the account-info actions"
  },
  {
   "id": "own_password",
   "tier": "core",
   "quote": "manage their own password",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)\\{\"Action\":(?:\"(?:iam:(?:ChangePassword|Change\\*|\\*)|\\*)\"|\\[(?:\"[^\"]*\",)*\"(?:iam:(?:ChangePassword|Change\\*|\\*)|\\*)\"(?:,\"[^\"]*\")*\\]),(?:\"Condition\":\\{(?:[^{}]|\\{[^{}]*\\})*\\},)?\"Effect\":\"Allow\""
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "effect"
        ],
        "op": "none_eq",
        "value": "deny"
       },
       {
        "path": [
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "iam:ChangePassword"
       }
      ]
     }
    }
   ],
   "justify": "'lets ... manage their own password' means an Allow (effect not deny) of iam:ChangePassword"
  },
  {
   "id": "virtual_mfa",
   "tier": "core",
   "quote": "manage their own password and virtual MFA device",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)\\{\"Action\":(?:\"(?:iam:(?:CreateVirtualMFADevice|CreateVirtual\\*|Create\\*|\\*)|\\*)\"|\\[(?:\"[^\"]*\",)*\"(?:iam:(?:CreateVirtualMFADevice|CreateVirtual\\*|Create\\*|\\*)|\\*)\"(?:,\"[^\"]*\")*\\]),(?:\"Condition\":\\{(?:[^{}]|\\{[^{}]*\\})*\\},)?\"Effect\":\"Allow\""
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "effect"
        ],
        "op": "none_eq",
        "value": "deny"
       },
       {
        "path": [
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "iam:CreateVirtualMFADevice"
       }
      ]
     }
    }
   ],
   "justify": "'lets ... manage their virtual MFA device' means an Allow (effect not deny) of iam:CreateVirtualMFADevice"
  },
  {
   "id": "own_mfa_device_scoped",
   "tier": "detail",
   "quote": "manage their own password and virtual MFA device",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)\\{\"Action\":(?:\"(?:iam:(?:CreateVirtualMFADevice|CreateVirtual\\*|Create\\*|\\*)|\\*)\"|\\[(?:\"[^\"]*\",)*\"(?:iam:(?:CreateVirtualMFADevice|CreateVirtual\\*|Create\\*|\\*)|\\*)\"(?:,\"[^\"]*\")*\\]),(?:\"Condition\":\\{(?:[^{}]|\\{[^{}]*\\})*\\},)?\"Effect\":\"Allow\",\"Resource\":(?:\"[^\"]*aws:username[^\"]*\"|\\[[^\\]]*aws:username[^\\]]*\\])"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "effect"
        ],
        "op": "none_eq",
        "value": "deny"
       },
       {
        "path": [
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "iam:CreateVirtualMFADevice"
       },
       {
        "path": [
         "resources",
         "*"
        ],
        "op": "contains",
        "value": "aws:username"
       }
      ]
     }
    }
   ],
   "justify": "'their own' virtual MFA device: an Allow whose Resource is scoped to the caller via the aws:username policy variable"
  },
  {
   "id": "deactivate_mfa_cond",
   "tier": "core",
   "quote": "allowing MFA deactivation and broader self-inspection only when signed in with MFA",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)\\{\"Action\":(?:\"(?:iam:(?:DeactivateMFADevice|Deactivate\\*|\\*MFADevice|\\*)|\\*)\"|\\[(?:\"[^\"]*\",)*\"(?:iam:(?:DeactivateMFADevice|Deactivate\\*|\\*MFADevice|\\*)|\\*)\"(?:,\"[^\"]*\")*\\]),\"Condition\":\\{(?:[^{}]|\\{[^{}]*\\})*\\{[^{}]*(?:MultiFactorAuthPresent\":\\[?\"?true|MultiFactorAuthAge\":\\[?\"?false)[^{}]*\\}(?:[^{}]|\\{[^{}]*\\})*\\},\"Effect\":\"Allow\"|\\{\"Action\":(?:\"(?:iam:(?:DeactivateMFADevice|Deactivate\\*|\\*MFADevice|\\*)|\\*)\"|\\[(?:\"[^\"]*\",)*\"(?:iam:(?:DeactivateMFADevice|Deactivate\\*|\\*MFADevice|\\*)|\\*)\"(?:,\"[^\"]*\")*\\]),\"Condition\":\\{(?:[^{}]|\\{[^{}]*\\})*\\{[^{}]*(?:MultiFactorAuthPresent\":\\[?\"?false|MultiFactorAuthAge\":\\[?\"?true)[^{}]*\\}(?:[^{}]|\\{[^{}]*\\})*\\},\"Effect\":\"Deny\"|\\{\"Condition\":\\{(?:[^{}]|\\{[^{}]*\\})*\\{[^{}]*(?:MultiFactorAuthPresent\":\\[?\"?false|MultiFactorAuthAge\":\\[?\"?true)[^{}]*\\}(?:[^{}]|\\{[^{}]*\\})*\\},\"Effect\":\"Deny\",\"NotAction\":(?:\"[^\"*D:](?:[^\"D:]|D[^\"e]|De[^\"a]|:(?:[^\"*D]|D[^\"e]|De[^\"a]))*(?:De?)?\"|\\[\"[^\"*D:](?:[^\"D:]|D[^\"e]|De[^\"a]|:(?:[^\"*D]|D[^\"e]|De[^\"a]))*(?:De?)?\"(?:,\"[^\"*D:](?:[^\"D:]|D[^\"e]|De[^\"a]|:(?:[^\"*D]|D[^\"e]|De[^\"a]))*(?:De?)?\")*\\])"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "effect"
        ],
        "op": "none_eq",
        "value": "deny"
       },
       {
        "path": [
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "iam:DeactivateMFADevice"
       },
       {
        "path": [
         "condition",
         "*",
         "variable"
        ],
        "op": "eq",
        "value": "aws:MultiFactorAuthPresent"
       },
       {
        "path": [
         "condition",
         "*",
         "values",
         "*"
        ],
        "op": "eq",
        "value": "true"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "effect"
        ],
        "op": "eq",
        "value": "deny"
       },
       {
        "path": [
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "iam:DeactivateMFADevice"
       },
       {
        "path": [
         "condition",
         "*",
         "variable"
        ],
        "op": "eq",
        "value": "aws:MultiFactorAuthPresent"
       },
       {
        "path": [
         "condition",
         "*",
         "values",
         "*"
        ],
        "op": "eq",
        "value": "false"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "effect"
        ],
        "op": "eq",
        "value": "deny"
       },
       {
        "path": [
         "not_actions",
         "*"
        ],
        "op": "present"
       },
       {
        "path": [
         "not_actions",
         "*"
        ],
        "op": "none_eq",
        "value": "iam:DeactivateMFADevice"
       },
       {
        "path": [
         "not_actions",
         "*"
        ],
        "op": "none_eq",
        "value": "iam:*"
       },
       {
        "path": [
         "not_actions",
         "*"
        ],
        "op": "none_eq",
        "value": "*"
       },
       {
        "path": [
         "not_actions",
         "*"
        ],
        "op": "none_eq",
        "value": "iam:Deactivate*"
       },
       {
        "path": [
         "not_actions",
         "*"
        ],
        "op": "none_eq",
        "value": "iam:*MFADevice"
       },
       {
        "path": [
         "condition",
         "*",
         "variable"
        ],
        "op": "eq",
        "value": "aws:MultiFactorAuthPresent"
       },
       {
        "path": [
         "condition",
         "*",
         "values",
         "*"
        ],
        "op": "eq",
        "value": "false"
       }
      ]
     }
    }
   ],
   "justify": "'only when signed in with MFA' is the aws:MultiFactorAuthPresent key: Allow when true, or Deny (Action, or NotAction not exempting DeactivateMFADevice/iam:Deactivate*) when false"
  },
  {
   "id": "deactivate_allowed",
   "tier": "core",
   "quote": "allowing MFA deactivation",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)\\{\"Action\":(?:\"(?:iam:(?:DeactivateMFADevice|Deactivate\\*|\\*MFADevice|\\*)|\\*)\"|\\[(?:\"[^\"]*\",)*\"(?:iam:(?:DeactivateMFADevice|Deactivate\\*|\\*MFADevice|\\*)|\\*)\"(?:,\"[^\"]*\")*\\]),(?:\"Condition\":\\{(?:[^{}]|\\{[^{}]*\\})*\\},)?\"Effect\":\"Allow\""
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "effect"
        ],
        "op": "none_eq",
        "value": "deny"
       },
       {
        "path": [
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "iam:DeactivateMFADevice"
       }
      ]
     }
    }
   ],
   "justify": "'allowing MFA deactivation' means an Allow (effect not deny) of iam:DeactivateMFADevice"
  },
  {
   "id": "inspect_mfa_cond",
   "tier": "detail",
   "quote": "broader self-inspection only when signed in with MFA",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)\\{\"Action\":(?:\"(?:iam:(?:(?:List|Get)[A-Za-z]*\\*?|\\*)|\\*)\"|\\[(?:\"[^\"]*\",)*\"(?:iam:(?:(?:List|Get)[A-Za-z]*\\*?|\\*)|\\*)\"(?:,\"[^\"]*\")*\\]),\"Condition\":\\{(?:[^{}]|\\{[^{}]*\\})*\\{[^{}]*(?:MultiFactorAuthPresent\":\\[?\"?true|MultiFactorAuthAge\":\\[?\"?false)[^{}]*\\}(?:[^{}]|\\{[^{}]*\\})*\\},\"Effect\":\"Allow\"|\\{\"Action\":(?:\"(?:iam:(?:(?:List|Get)[A-Za-z]*\\*?|\\*)|\\*)\"|\\[(?:\"[^\"]*\",)*\"(?:iam:(?:(?:List|Get)[A-Za-z]*\\*?|\\*)|\\*)\"(?:,\"[^\"]*\")*\\]),\"Condition\":\\{(?:[^{}]|\\{[^{}]*\\})*\\{[^{}]*(?:MultiFactorAuthPresent\":\\[?\"?false|MultiFactorAuthAge\":\\[?\"?true)[^{}]*\\}(?:[^{}]|\\{[^{}]*\\})*\\},\"Effect\":\"Deny\""
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "effect"
        ],
        "op": "none_eq",
        "value": "deny"
       },
       {
        "path": [
         "actions",
         "*"
        ],
        "op": "regex",
        "value": "(?i)^(iam:((List|Get)[A-Za-z]*\\*?|\\*)|\\*)$"
       },
       {
        "path": [
         "condition",
         "*",
         "variable"
        ],
        "op": "eq",
        "value": "aws:MultiFactorAuthPresent"
       },
       {
        "path": [
         "condition",
         "*",
         "values",
         "*"
        ],
        "op": "eq",
        "value": "true"
       }
      ]
     }
    }
   ],
   "justify": "'only when signed in with MFA' is the aws:MultiFactorAuthPresent key set to true on an Allow (effect not deny)"
  },
  {
   "id": "x_list_mfa",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "aws_iam_policy",
     "data.aws_iam_policy_document",
     "__declared__"
    ],
    "where": []
   },
   "cond": {
    "path": [],
    "op": "regex",
    "value": "(?i)iam:ListMFADevices"
   }
  },
  {
   "id": "extra_type_aws_iam_group_policy_attachment",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "__declared__"
    ],
    "where": [
     {
      "path": [
       "type"
      ],
      "op": "eq",
      "value": "aws_iam_group_policy_attachment"
     }
    ]
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
