package intent.cfn.row_209

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "secret": {
   "types": [
    "AWS::SecretsManager::Secret"
   ],
   "where": []
  },
  "group": {
   "types": [
    "AWS::IAM::Group"
   ],
   "where": []
  },
  "user": {
   "types": [
    "AWS::IAM::User"
   ],
   "where": []
  },
  "gen_secret": {
   "types": [
    "AWS::SecretsManager::Secret"
   ],
   "where": [
    {
     "path": [
      "GenerateSecretString"
     ],
     "op": "present"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "secret",
   "kind": "exists",
   "select": "gen_secret",
   "tier": "core",
   "quote": "an automatically generated Secrets Manager secret"
  },
  {
   "id": "secret_description",
   "kind": "attr",
   "select": "secret",
   "cond": {
    "path": [
     "Description"
    ],
    "op": "eq",
    "value": "Minesweeper user secret"
   },
   "tier": "detail",
   "quote": "\"Minesweeper user secret\""
  },
  {
   "id": "secret_username",
   "kind": "attr",
   "select": "secret",
   "cond": {
    "path": [
     "GenerateSecretString",
     "SecretStringTemplate"
    ],
    "op": "regex",
    "value": "(?i)username.{0,6}minesweeper-user"
   },
   "tier": "core",
   "quote": "a fixed username \"minesweeper-user\""
  },
  {
   "id": "secret_password_key",
   "kind": "attr",
   "select": "secret",
   "cond": {
    "path": [
     "GenerateSecretString",
     "GenerateStringKey"
    ],
    "op": "eq",
    "value": "password"
   },
   "tier": "detail",
   "quote": "username and password keys of the created Secrets Manager secret"
  },
  {
   "id": "password_length",
   "kind": "attr",
   "select": "secret",
   "cond": {
    "path": [
     "GenerateSecretString",
     "PasswordLength"
    ],
    "op": "eq",
    "value": 15
   },
   "tier": "core",
   "quote": "15-character generated password"
  },
  {
   "id": "password_charset",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::SecretsManager::Secret"
    ],
    "where": [
     {
      "path": [
       "GenerateSecretString"
      ],
      "op": "present"
     },
     {
      "path": [
       "GenerateSecretString",
       "ExcludeLowercase"
      ],
      "op": "none_eq",
      "value": true
     },
     {
      "path": [
       "GenerateSecretString",
       "ExcludeUppercase"
      ],
      "op": "none_eq",
      "value": true
     },
     {
      "path": [
       "GenerateSecretString",
       "ExcludeNumbers"
      ],
      "op": "none_eq",
      "value": true
     }
    ]
   },
   "tier": "core",
   "quote": "includes lowercase, uppercase, and numbers",
   "justify": "includes means those classes are not excluded"
  },
  {
   "id": "exclude_chars",
   "kind": "attr",
   "select": "secret",
   "cond": {
    "path": [
     "GenerateSecretString",
     "ExcludeCharacters"
    ],
    "op": "regex",
    "value": "^[|;,.\"<>%`]{9}$"
   },
   "tier": "core",
   "quote": "excluding specific special characters (\"|;,.\"<>%`\")",
   "justify": "the nine characters the prompt lists, in any order"
  },
  {
   "id": "param_id",
   "kind": "attr",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "ID"
     }
    ]
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": "999hadvhgchjesr"
   },
   "tier": "core",
   "quote": "a single parameter ID defaulting to \"999hadvhgchjesr\""
  },
  {
   "id": "single_parameter",
   "kind": "exists",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": []
   },
   "max": 1,
   "tier": "detail",
   "quote": "a single parameter ID",
   "justify": "a single parameter means at most one"
  },
  {
   "id": "group",
   "kind": "exists",
   "select": "group",
   "tier": "core",
   "quote": "create an IAM group"
  },
  {
   "id": "group_name",
   "kind": "attr",
   "select": "group",
   "cond": {
    "path": [
     "GroupName"
    ],
    "op": "eq",
    "value": "minesweeper-999hadvhgchjesr"
   },
   "tier": "core",
   "quote": "an IAM group named \"minesweeper-{ID}\"",
   "justify": "ID default resolved"
  },
  {
   "id": "group_ec2",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "group",
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
         "Effect"
        ],
        "op": "eq",
        "value": "Allow"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "ec2:*"
       }
      ]
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
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "Effect"
          ],
          "op": "eq",
          "value": "Allow"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "glob_covers",
          "value": "ec2:*"
         }
        ]
       }
      ]
     },
     "to": "group",
     "bidirectional": true
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "AWS::IAM::Policy"
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
           "Effect"
          ],
          "op": "eq",
          "value": "Allow"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "glob_covers",
          "value": "ec2:*"
         }
        ]
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
    }
   ],
   "tier": "core",
   "quote": "inline policy granting full permissions across ec2, cloudformation, and secretmanager actions"
  },
  {
   "id": "group_cfn",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "group",
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
         "Effect"
        ],
        "op": "eq",
        "value": "Allow"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "cloudformation:*"
       }
      ]
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
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "Effect"
          ],
          "op": "eq",
          "value": "Allow"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "glob_covers",
          "value": "cloudformation:*"
         }
        ]
       }
      ]
     },
     "to": "group",
     "bidirectional": true
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "AWS::IAM::Policy"
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
           "Effect"
          ],
          "op": "eq",
          "value": "Allow"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "glob_covers",
          "value": "cloudformation:*"
         }
        ]
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
    }
   ],
   "tier": "core",
   "quote": "inline policy granting full permissions across ec2, cloudformation, and secretmanager actions"
  },
  {
   "id": "group_secrets",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "group",
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
         "Effect"
        ],
        "op": "eq",
        "value": "Allow"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "regex",
        "value": "(?i)^(\\*|secrets?manager:\\*)$"
       }
      ]
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
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "Effect"
          ],
          "op": "eq",
          "value": "Allow"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "regex",
          "value": "(?i)^(\\*|secrets?manager:\\*)$"
         }
        ]
       }
      ]
     },
     "to": "group",
     "bidirectional": true
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "AWS::IAM::Policy"
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
           "Effect"
          ],
          "op": "eq",
          "value": "Allow"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "regex",
          "value": "(?i)^(\\*|secrets?manager:\\*)$"
         }
        ]
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
    }
   ],
   "tier": "core",
   "quote": "inline policy granting full permissions across ec2, cloudformation, and secretmanager actions",
   "justify": "full permissions means the whole service; the prompt writes 'secretmanager', and the real prefix secretsmanager is accepted too"
  },
  {
   "id": "user",
   "kind": "exists",
   "select": "user",
   "tier": "core",
   "quote": "create an IAM user"
  },
  {
   "id": "user_in_group",
   "kind": "any_of",
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
      "where": [
       {
        "path": [
         "Users",
         "*"
        ],
        "op": "present"
       }
      ]
     },
     "to": "group"
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "AWS::IAM::UserToGroupAddition"
      ],
      "where": [
       {
        "path": [
         "Users",
         "*"
        ],
        "op": "present"
       }
      ]
     },
     "from_path": [
      "GroupName"
     ],
     "to": "group",
     "to_path": [
      "GroupName"
     ]
    }
   ],
   "tier": "core",
   "quote": "create an IAM user assigned to this group"
  },
  {
   "id": "user_name_from_secret",
   "kind": "attr",
   "select": "user",
   "cond": {
    "path": [
     "UserName"
    ],
    "op": "regex",
    "value": "(?i)secretstring:username"
   },
   "tier": "core",
   "quote": "username and console login password dynamically resolve directly from the username and password keys"
  },
  {
   "id": "user_password_from_secret",
   "kind": "attr",
   "select": "user",
   "cond": {
    "path": [
     "LoginProfile",
     "Password"
    ],
    "op": "regex",
    "value": "(?i)secretstring:password"
   },
   "tier": "core",
   "quote": "console login password dynamically resolve directly from the username and password keys"
  },
  {
   "id": "user_refs_secret",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "user",
     "to": "secret"
    },
    {
     "kind": "attr",
     "select": "user",
     "cond": {
      "path": [
       "UserName"
      ],
      "op": "regex",
      "value": "(?i)secretsmanager:"
     }
    }
   ],
   "tier": "detail",
   "quote": "dynamically resolve directly from the username and password keys of the created Secrets Manager secret"
  },
  {
   "id": "output_user",
   "kind": "ref",
   "from": {
    "types": [
     "__output__"
    ],
    "where": []
   },
   "to": "user",
   "tier": "detail",
   "quote": "exporting the user ARN in the stack outputs"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
