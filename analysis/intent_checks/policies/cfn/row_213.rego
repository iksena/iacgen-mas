package intent.cfn.row_213

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "user": {
   "types": [
    "AWS::IAM::User"
   ],
   "where": []
  },
  "group": {
   "types": [
    "AWS::IAM::Group"
   ],
   "where": []
  },
  "key": {
   "types": [
    "AWS::IAM::AccessKey"
   ],
   "where": []
  },
  "fn": {
   "types": [
    "AWS::Lambda::Function"
   ],
   "where": []
  },
  "role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "lg": {
   "types": [
    "AWS::Logs::LogGroup"
   ],
   "where": []
  },
  "custom": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "regex",
     "value": "^(Custom::|AWS::CloudFormation::CustomResource)"
    },
    {
     "path": [
      "gated"
     ],
     "op": "falsy"
    }
   ]
  },
  "user_or_group": {
   "types": [
    "AWS::IAM::User",
    "AWS::IAM::Group"
   ],
   "where": []
  },
  "fn_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Principal",
      "Service",
      "*"
     ],
     "op": "eq",
     "value": "lambda.amazonaws.com"
    }
   ]
  },
  "limited_policy": {
   "types": [
    "AWS::IAM::Policy",
    "AWS::IAM::ManagedPolicy",
    "AWS::IAM::UserPolicy",
    "AWS::IAM::GroupPolicy",
    "AWS::IAM::RolePolicy"
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
     "op": "in",
     "value": [
      "ses:SendEmail",
      "ses:SendRawEmail"
     ],
     "every": true
    }
   ]
  }
 },
 "checks": [
  {
   "id": "iam_user",
   "kind": "exists",
   "tier": "core",
   "quote": "creates a dedicated IAM user and group for sending email through Amazon SES via SMTP",
   "select": "user"
  },
  {
   "id": "iam_group",
   "kind": "exists",
   "tier": "core",
   "quote": "creates a dedicated IAM user and group for sending email through Amazon SES via SMTP",
   "select": "group"
  },
  {
   "id": "user_in_group",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a dedicated IAM user and group for sending email",
   "justify": "a user and group for the same purpose implies membership",
   "checks": [
    {
     "kind": "ref",
     "from": "user",
     "to": "group"
    },
    {
     "kind": "join",
     "from": "user",
     "from_path": [
      "Groups",
      "*"
     ],
     "to": "group",
     "to_path": [
      "GroupName"
     ]
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::UserToGroupAddition"
      ],
      "where": []
     },
     "to": "group"
    }
   ]
  },
  {
   "id": "access_key",
   "kind": "exists",
   "tier": "core",
   "quote": "along with an access key for that user",
   "select": "key"
  },
  {
   "id": "access_key_for_user",
   "kind": "any_of",
   "tier": "detail",
   "quote": "an access key for that user",
   "checks": [
    {
     "kind": "ref",
     "from": "key",
     "to": "user"
    },
    {
     "kind": "join",
     "from": "key",
     "from_path": [
      "UserName"
     ],
     "to": "user",
     "to_path": [
      "UserName"
     ]
    }
   ]
  },
  {
   "id": "policy_send_email",
   "kind": "any_of",
   "tier": "core",
   "quote": "a policy limiting it to the ses:SendEmail and ses:SendRawEmail actions",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::UserPolicy",
       "AWS::IAM::GroupPolicy",
       "AWS::IAM::RolePolicy"
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
        "value": "ses:SendEmail"
       }
      ]
     },
     "to": "user_or_group",
     "bidirectional": true
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::UserPolicy",
       "AWS::IAM::GroupPolicy",
       "AWS::IAM::RolePolicy"
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
        "value": "ses:SendEmail"
       }
      ]
     },
     "from_path": [
      "Users",
      "*"
     ],
     "to": "user",
     "to_path": [
      "UserName"
     ]
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::UserPolicy",
       "AWS::IAM::GroupPolicy",
       "AWS::IAM::RolePolicy"
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
        "value": "ses:SendEmail"
       }
      ]
     },
     "from_path": [
      "Groups",
      "*"
     ],
     "to": "group",
     "to_path": [
      "GroupName"
     ]
    },
    {
     "kind": "attr",
     "select": "user",
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
      "value": "ses:SendEmail"
     }
    },
    {
     "kind": "attr",
     "select": "group",
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
      "value": "ses:SendEmail"
     }
    }
   ]
  },
  {
   "id": "policy_send_raw_email",
   "kind": "any_of",
   "tier": "core",
   "quote": "a policy limiting it to the ses:SendEmail and ses:SendRawEmail actions",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::UserPolicy",
       "AWS::IAM::GroupPolicy",
       "AWS::IAM::RolePolicy"
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
        "value": "ses:SendRawEmail"
       }
      ]
     },
     "to": "user_or_group",
     "bidirectional": true
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::UserPolicy",
       "AWS::IAM::GroupPolicy",
       "AWS::IAM::RolePolicy"
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
        "value": "ses:SendRawEmail"
       }
      ]
     },
     "from_path": [
      "Users",
      "*"
     ],
     "to": "user",
     "to_path": [
      "UserName"
     ]
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::UserPolicy",
       "AWS::IAM::GroupPolicy",
       "AWS::IAM::RolePolicy"
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
        "value": "ses:SendRawEmail"
       }
      ]
     },
     "from_path": [
      "Groups",
      "*"
     ],
     "to": "group",
     "to_path": [
      "GroupName"
     ]
    },
    {
     "kind": "attr",
     "select": "user",
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
      "value": "ses:SendRawEmail"
     }
    },
    {
     "kind": "attr",
     "select": "group",
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
      "value": "ses:SendRawEmail"
     }
    }
   ]
  },
  {
   "id": "policy_only_ses_send",
   "kind": "any_of",
   "tier": "core",
   "quote": "a policy limiting it to the ses:SendEmail and ses:SendRawEmail actions",
   "checks": [
    {
     "kind": "ref",
     "from": "limited_policy",
     "to": "user_or_group",
     "bidirectional": true
    },
    {
     "kind": "join",
     "from": "limited_policy",
     "from_path": [
      "Users",
      "*"
     ],
     "to": "user",
     "to_path": [
      "UserName"
     ]
    },
    {
     "kind": "join",
     "from": "limited_policy",
     "from_path": [
      "Groups",
      "*"
     ],
     "to": "group",
     "to_path": [
      "GroupName"
     ]
    },
    {
     "kind": "attr",
     "select": "user",
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
      "op": "in",
      "value": [
       "ses:SendEmail",
       "ses:SendRawEmail"
      ],
      "every": true
     }
    },
    {
     "kind": "attr",
     "select": "group",
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
      "op": "in",
      "value": [
       "ses:SendEmail",
       "ses:SendRawEmail"
      ],
      "every": true
     }
    }
   ]
  },
  {
   "id": "custom_resource",
   "kind": "exists",
   "tier": "core",
   "quote": "a Lambda-backed custom resource",
   "select": "custom"
  },
  {
   "id": "lambda_function",
   "kind": "exists",
   "tier": "core",
   "quote": "a Lambda-backed custom resource",
   "select": "fn"
  },
  {
   "id": "custom_uses_lambda",
   "kind": "ref",
   "tier": "core",
   "quote": "a Lambda-backed custom resource",
   "from": "custom",
   "to": "fn"
  },
  {
   "id": "custom_gets_secret_key",
   "kind": "attr",
   "tier": "core",
   "quote": "converts the user's secret access key into a valid SES SMTP password",
   "select": "custom",
   "cond": {
    "path": [
     "properties"
    ],
    "op": "regex",
    "value": "(?i)\"attr\": \"SecretAccessKey\"|\\.SecretAccessKey"
   }
  },
  {
   "id": "conversion_algorithm",
   "kind": "attr",
   "tier": "detail",
   "quote": "using AWS's published SMTP credential conversion algorithm",
   "justify": "the published algorithm is a chain of HMAC-SHA256 signatures",
   "select": "fn",
   "cond": {
    "path": [
     "Code",
     "ZipFile"
    ],
    "op": "regex",
    "value": "(?i)hmac"
   }
  },
  {
   "id": "secure_string_params",
   "kind": "any_of",
   "tier": "core",
   "quote": "stores both the resulting SMTP username and password as SecureString parameters in Systems Manager Parameter Store",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::SSM::Parameter"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Type"
      ],
      "op": "eq",
      "value": "SecureString"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Lambda::Function"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Code",
       "ZipFile"
      ],
      "op": "regex",
      "value": "SecureString"
     }
    }
   ]
  },
  {
   "id": "names_from_username",
   "kind": "any_of",
   "tier": "detail",
   "quote": "under names derived from the IAM username",
   "justify": "the parameter names are built from the username, so it must reach the SSM parameter or the custom resource or function that writes it",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::SSM::Parameter"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Name"
      ],
      "op": "contains",
      "value": "SMTPUser"
     }
    },
    {
     "kind": "attr",
     "select": "custom",
     "cond": {
      "path": [
       "properties"
      ],
      "op": "contains",
      "value": "SMTPUser"
     }
    },
    {
     "kind": "attr",
     "select": "fn",
     "cond": {
      "path": [
       "Environment"
      ],
      "op": "contains",
      "value": "SMTPUser"
     }
    }
   ]
  },
  {
   "id": "iam_username_default",
   "kind": "all_of",
   "tier": "core",
   "quote": "the desired IAM username (defaulting to SMTPUser)",
   "checks": [
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
      "op": "eq",
      "value": "SMTPUser"
     }
    },
    {
     "kind": "attr",
     "select": "user",
     "cond": {
      "path": [
       "UserName"
      ],
      "op": "eq",
      "value": "SMTPUser"
     }
    }
   ]
  },
  {
   "id": "rotation_version_param",
   "kind": "any_of",
   "tier": "detail",
   "quote": "an access key rotation version number",
   "checks": [
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
       "name"
      ],
      "op": "regex",
      "value": "(?i)(version|serial|rotat)"
     }
    },
    {
     "kind": "join",
     "from": "key",
     "from_path": [
      "Serial"
     ],
     "to": {
      "types": [
       "__parameter__"
      ],
      "where": []
     },
     "to_path": [
      "default"
     ]
    }
   ]
  },
  {
   "id": "log_retention_param",
   "kind": "any_of",
   "tier": "detail",
   "quote": "the Lambda function's log retention period",
   "checks": [
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
       "name"
      ],
      "op": "regex",
      "value": "(?i)retention"
     }
    },
    {
     "kind": "join",
     "from": "lg",
     "from_path": [
      "RetentionInDays"
     ],
     "to": {
      "types": [
       "__parameter__"
      ],
      "where": []
     },
     "to_path": [
      "default"
     ]
    }
   ]
  },
  {
   "id": "kms_arn_param",
   "kind": "attr",
   "tier": "detail",
   "quote": "an optional ARN of a customer-managed KMS key",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "name"
    ],
    "op": "regex",
    "value": "(?i)kms|cmk|customer.?managed|encryption.?key"
   }
  },
  {
   "id": "lambda_role",
   "kind": "exists",
   "tier": "core",
   "quote": "the Lambda function's execution role",
   "select": "fn_role",
   "justify": "a Lambda execution role is assumed by the Lambda service"
  },
  {
   "id": "fn_uses_role",
   "kind": "ref",
   "tier": "detail",
   "quote": "the Lambda function's execution role",
   "from": "fn",
   "to": "role"
  },
  {
   "id": "role_trusts_lambda",
   "kind": "attr",
   "tier": "detail",
   "quote": "the Lambda function's execution role",
   "justify": "a Lambda execution role is assumed by the Lambda service",
   "select": "role",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument"
    ],
    "op": "contains",
    "value": "lambda.amazonaws.com"
   }
  },
  {
   "id": "role_ssm_write",
   "kind": "any_of",
   "tier": "core",
   "quote": "permissions to write to Parameter Store",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::UserPolicy",
       "AWS::IAM::GroupPolicy",
       "AWS::IAM::RolePolicy"
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
        "value": "ssm:PutParameter"
       }
      ]
     },
     "to": "fn_role",
     "bidirectional": true
    },
    {
     "kind": "attr",
     "select": "fn_role",
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
      "value": "ssm:PutParameter"
     }
    },
    {
     "kind": "attr",
     "select": "fn_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "AmazonSSMFullAccess$"
     }
    }
   ],
   "justify": "AmazonSSMFullAccess is the AWS-managed policy that includes ssm:PutParameter"
  },
  {
   "id": "log_group",
   "kind": "exists",
   "tier": "core",
   "quote": "a CloudWatch Log Group for its execution logs",
   "select": "lg"
  },
  {
   "id": "log_group_for_fn",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a CloudWatch Log Group for its execution logs",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Logs::LogGroup"
      ],
      "where": []
     },
     "to": "fn"
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Logs::LogGroup"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "LogGroupName"
      ],
      "op": "contains",
      "value": "/aws/lambda/"
     }
    }
   ]
  },
  {
   "id": "x_key_active",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::IAM::AccessKey"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "Status"
    ],
    "op": "none_eq",
    "value": "Inactive"
   }
  },
  {
   "id": "x_basic_exec",
   "kind": "attr",
   "tier": "extra",
   "select": "role",
   "cond": {
    "path": [
     "ManagedPolicyArns",
     "*"
    ],
    "op": "contains",
    "value": "AWSLambdaBasicExecutionRole"
   }
  },
  {
   "id": "x_python",
   "kind": "attr",
   "tier": "extra",
   "select": "fn",
   "cond": {
    "path": [
     "Runtime"
    ],
    "op": "regex",
    "value": "^python"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
