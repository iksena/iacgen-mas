package intent.cfn.row_045

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "thing": {
   "types": [
    "AWS::IoT::Thing"
   ],
   "where": []
  },
  "up": {
   "types": [
    "AWS::Cognito::UserPool"
   ],
   "where": []
  },
  "upc": {
   "types": [
    "AWS::Cognito::UserPoolClient"
   ],
   "where": []
  },
  "ip": {
   "types": [
    "AWS::Cognito::IdentityPool"
   ],
   "where": []
  },
  "att": {
   "types": [
    "AWS::Cognito::IdentityPoolRoleAttachment"
   ],
   "where": []
  },
  "role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "role_a": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "regex",
     "value": "amr[^a-z]*authenticated"
    }
   ]
  },
  "role_u": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "regex",
     "value": "amr[^a-z]*unauthenticated"
    }
   ]
  },
  "role_cog": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "contains",
     "value": "cognito-identity.amazonaws.com"
    }
   ]
  },
  "att_a": {
   "types": [
    "AWS::Cognito::IdentityPoolRoleAttachment"
   ],
   "where": [
    {
     "path": [
      "Roles",
      "authenticated"
     ],
     "op": "present"
    }
   ]
  },
  "att_u": {
   "types": [
    "AWS::Cognito::IdentityPoolRoleAttachment"
   ],
   "where": [
    {
     "path": [
      "Roles",
      "unauthenticated"
     ],
     "op": "present"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "thing",
   "tier": "core",
   "quote": "an AWS IoT Thing named \"askaroundme-realtime\"",
   "kind": "attr",
   "select": "thing",
   "cond": {
    "path": [
     "ThingName"
    ],
    "op": "eq",
    "value": "askaroundme-realtime"
   }
  },
  {
   "id": "up_name",
   "tier": "core",
   "quote": "a Cognito User Pool named \"askAroundMeUserPool\"",
   "kind": "attr",
   "select": "up",
   "cond": {
    "path": [
     "UserPoolName"
    ],
    "op": "eq",
    "value": "askAroundMeUserPool"
   }
  },
  {
   "id": "email_attr",
   "tier": "core",
   "quote": "requires email as a mandatory immutable attribute",
   "kind": "attr",
   "select": "up",
   "cond": {
    "path": [
     "Schema",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "Name"
      ],
      "op": "eq",
      "value": "email"
     },
     {
      "path": [
       "Required"
      ],
      "op": "eq",
      "value": true
     },
     {
      "path": [
       "Mutable"
      ],
      "op": "eq",
      "value": false
     }
    ]
   }
  },
  {
   "id": "client",
   "tier": "core",
   "quote": "a corresponding User Pool Client without a secret",
   "kind": "exists",
   "select": "upc"
  },
  {
   "id": "client_nosecret",
   "tier": "core",
   "quote": "without a secret",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "upc",
     "cond": {
      "path": [
       "GenerateSecret"
      ],
      "op": "eq",
      "value": false
     }
    },
    {
     "kind": "attr",
     "select": "upc",
     "cond": {
      "path": [
       "GenerateSecret"
      ],
      "op": "absent"
     }
    }
   ]
  },
  {
   "id": "client_pool",
   "tier": "detail",
   "quote": "a corresponding User Pool Client",
   "kind": "ref",
   "from": "upc",
   "to": "up"
  },
  {
   "id": "ip_name",
   "tier": "core",
   "quote": "a federated Identity Pool named \"askAroundMeIdentityPool\"",
   "kind": "attr",
   "select": "ip",
   "cond": {
    "path": [
     "IdentityPoolName"
    ],
    "op": "eq",
    "value": "askAroundMeIdentityPool"
   }
  },
  {
   "id": "unauth",
   "tier": "core",
   "quote": "allows unauthenticated identities",
   "kind": "attr",
   "select": "ip",
   "cond": {
    "path": [
     "AllowUnauthenticatedIdentities"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "federated",
   "tier": "detail",
   "quote": "a federated Identity Pool",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "ip",
     "to": "up"
    },
    {
     "kind": "ref",
     "from": "ip",
     "to": "upc"
    }
   ]
  },
  {
   "id": "roles_two",
   "tier": "core",
   "quote": "IAM roles for both authenticated and unauthenticated users",
   "kind": "exists",
   "select": "role_cog",
   "min": 2
  },
  {
   "id": "att_auth",
   "tier": "core",
   "quote": "with these roles attached to the Identity Pool via a role mapping",
   "kind": "ref",
   "from": "att_a",
   "to": "role_cog"
  },
  {
   "id": "att_unauth",
   "tier": "core",
   "quote": "with these roles attached to the Identity Pool via a role mapping",
   "kind": "ref",
   "from": "att_u",
   "to": "role_cog"
  },
  {
   "id": "att_pool",
   "tier": "detail",
   "quote": "attached to the Identity Pool via a role mapping",
   "kind": "ref",
   "from": "att",
   "to": "ip"
  },
  {
   "id": "role_a_pol",
   "tier": "detail",
   "quote": "IAM roles for both authenticated and unauthenticated users that grant permissions",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "role_a",
     "cond": {
      "path": [
       "Policies"
      ],
      "op": "regex",
      "value": "(?s)cognito-sync.*iot:|iot:.*cognito-sync"
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
        "value": "(?s)cognito-sync.*iot:|iot:.*cognito-sync"
       }
      ]
     },
     "to": "role_a",
     "bidirectional": true
    }
   ],
   "justify": "both roles must carry the Cognito Sync and IoT grants; the role is told apart by its amr trust condition"
  },
  {
   "id": "role_u_pol",
   "tier": "detail",
   "quote": "IAM roles for both authenticated and unauthenticated users that grant permissions",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "role_u",
     "cond": {
      "path": [
       "Policies"
      ],
      "op": "regex",
      "value": "(?s)cognito-sync.*iot:|iot:.*cognito-sync"
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
        "value": "(?s)cognito-sync.*iot:|iot:.*cognito-sync"
       }
      ]
     },
     "to": "role_u",
     "bidirectional": true
    }
   ],
   "justify": "both roles must carry the Cognito Sync and IoT grants; the role is told apart by its amr trust condition"
  },
  {
   "id": "sync",
   "tier": "core",
   "quote": "permissions for Cognito Sync operations",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "role_cog",
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
        "value": "(?i)^(cognito-sync:|\\*$)"
       }
      ]
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
          "value": "(?i)^(cognito-sync:|\\*$)"
         }
        ]
       }
      ]
     },
     "to": "role_cog",
     "bidirectional": true
    }
   ]
  },
  {
   "id": "sync_resource",
   "tier": "detail",
   "quote": "Cognito Sync operations against the identity pool",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "role_cog",
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
        "value": "(?i)^(cognito-sync:|\\*$)"
       },
       {
        "path": [
         "Resource"
        ],
        "op": "regex",
        "value": "(?i)identitypool"
       }
      ]
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
          "value": "(?i)^(cognito-sync:|\\*$)"
         },
         {
          "path": [
           "Resource"
          ],
          "op": "regex",
          "value": "(?i)identitypool"
         }
        ]
       }
      ]
     },
     "to": "role_cog",
     "bidirectional": true
    }
   ]
  },
  {
   "id": "connect_prefix",
   "tier": "core",
   "quote": "IoT Connect restricted to clients with the \"askAroundMe-\" prefix",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "role_cog",
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
        "value": "iot:Connect"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "contains",
        "value": "client/askAroundMe-"
       }
      ]
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
          "value": "iot:Connect"
         },
         {
          "path": [
           "Resource",
           "*"
          ],
          "op": "contains",
          "value": "client/askAroundMe-"
         }
        ]
       }
      ]
     },
     "to": "role_cog",
     "bidirectional": true
    },
    {
     "kind": "attr",
     "select": "role_cog",
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
        "value": "iot:Connect"
       },
       {
        "path": [
         "Condition"
        ],
        "op": "contains",
        "value": "askAroundMe-"
       }
      ]
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
          "value": "iot:Connect"
         },
         {
          "path": [
           "Condition"
          ],
          "op": "contains",
          "value": "askAroundMe-"
         }
        ]
       }
      ]
     },
     "to": "role_cog",
     "bidirectional": true
    }
   ]
  },
  {
   "id": "subscribe_any",
   "tier": "core",
   "quote": "IoT Subscribe to any resource",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "role_cog",
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
        "value": "iot:Subscribe"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "^(\\*|arn:[^:]*:iot:[^:]*:[^:]*:topicfilter/\\*)$"
       }
      ]
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
          "value": "iot:Subscribe"
         },
         {
          "path": [
           "Resource",
           "*"
          ],
          "op": "regex",
          "value": "^(\\*|arn:[^:]*:iot:[^:]*:[^:]*:topicfilter/\\*)$"
         }
        ]
       }
      ]
     },
     "to": "role_cog",
     "bidirectional": true
    }
   ],
   "justify": "any resource means the wildcard resource, or every topic filter"
  },
  {
   "id": "receive_any",
   "tier": "core",
   "quote": "IoT Receive from any topic",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "role_cog",
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
        "value": "iot:Receive"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "^(\\*|arn:[^:]*:iot:[^:]*:[^:]*:topic/\\*)$"
       }
      ]
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
          "value": "iot:Receive"
         },
         {
          "path": [
           "Resource",
           "*"
          ],
          "op": "regex",
          "value": "^(\\*|arn:[^:]*:iot:[^:]*:[^:]*:topic/\\*)$"
         }
        ]
       }
      ]
     },
     "to": "role_cog",
     "bidirectional": true
    }
   ],
   "justify": "any topic means a wildcard topic resource"
  },
  {
   "id": "mfa_off",
   "tier": "extra",
   "kind": "attr",
   "select": "up",
   "cond": {
    "path": [
     "MfaConfiguration"
    ],
    "op": "eq",
    "value": "OFF"
   }
  },
  {
   "id": "trust_web_identity",
   "tier": "extra",
   "kind": "attr",
   "select": "role",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument",
     "Statement",
     "*",
     "Action",
     "*"
    ],
    "op": "eq",
    "value": "sts:AssumeRoleWithWebIdentity"
   }
  },
  {
   "id": "trust_federated",
   "tier": "extra",
   "kind": "attr",
   "select": "role",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument",
     "Statement",
     "*",
     "Principal",
     "Federated",
     "*"
    ],
    "op": "eq",
    "value": "cognito-identity.amazonaws.com"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
