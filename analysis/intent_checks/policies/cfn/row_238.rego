package intent.cfn.row_238

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "auth": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Condition"
     ],
     "op": "regex",
     "value": "amr\\W+authenticated"
    }
   ]
  },
  "unauth": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Condition"
     ],
     "op": "regex",
     "value": "amr\\W+unauthenticated"
    }
   ]
  },
  "both": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Condition"
     ],
     "op": "regex",
     "value": "amr\\W+(un)?authenticated"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "auth_role",
   "kind": "exists",
   "tier": "core",
   "select": "auth",
   "quote": "an IAM role for authenticated users",
   "justify": "authentication reference includes authenticated"
  },
  {
   "id": "unauth_role",
   "kind": "exists",
   "tier": "core",
   "select": "unauth",
   "quote": "an IAM role for unauthenticated users"
  },
  {
   "id": "fed",
   "kind": "attr",
   "tier": "core",
   "select": "both",
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
   },
   "quantifier": "all",
   "quote": "allowing federated assumption from \"cognito-identity.amazonaws.com\""
  },
  {
   "id": "aud",
   "tier": "core",
   "quote": "when the audience matches identity pool \"us-east-1:7792bdd9-773b-4af4-a7a8-035a45723fac\"",
   "kind": "attr",
   "select": "both",
   "quantifier": "all",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument",
     "Statement",
     "*",
     "Condition"
    ],
    "op": "regex",
    "value": "cognito-identity\\.amazonaws\\.com:aud\\W+us-east-1:7792bdd9-773b-4af4-a7a8-035a45723fac"
   }
  },
  {
   "id": "web_identity",
   "kind": "attr",
   "tier": "detail",
   "select": "both",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument",
     "Statement",
     "*",
     "Action",
     "*"
    ],
    "op": "glob_covers",
    "value": "sts:AssumeRoleWithWebIdentity"
   },
   "quantifier": "all",
   "quote": "web identity trust policy conditions",
   "justify": "a web identity trust policy uses AssumeRoleWithWebIdentity"
  },
  {
   "id": "del",
   "kind": "attr",
   "tier": "core",
   "select": "both",
   "cond": {
    "path": [
     "__resource__",
     "DeletionPolicy"
    ],
    "op": "eq",
    "value": "Delete"
   },
   "quantifier": "all",
   "quote": "Both roles must include deletion and update-replace policies set to delete"
  },
  {
   "id": "upd",
   "kind": "attr",
   "tier": "core",
   "select": "both",
   "cond": {
    "path": [
     "__resource__",
     "UpdateReplacePolicy"
    ],
    "op": "eq",
    "value": "Delete"
   },
   "quantifier": "all",
   "quote": "Both roles must include deletion and update-replace policies set to delete"
  },
  {
   "id": "tag_amplify_deployment_type",
   "kind": "attr",
   "tier": "detail",
   "select": "both",
   "quantifier": "all",
   "cond": {
    "path": [
     "Tags",
     "*"
    ],
    "op": "has_kv",
    "value": {
     "key": "amplify:deployment-type",
     "value": "sandbox"
    }
   },
   "quote": "standard Amplify sandbox tags (\"amplify:deployment-type\" as \"sandbox\", \"amplify:friendly-name\" as \"amplifyAuth\", and \"created-by\" as \"amplify\")"
  },
  {
   "id": "tag_amplify_friendly_name",
   "kind": "attr",
   "tier": "detail",
   "select": "both",
   "quantifier": "all",
   "cond": {
    "path": [
     "Tags",
     "*"
    ],
    "op": "has_kv",
    "value": {
     "key": "amplify:friendly-name",
     "value": "amplifyAuth"
    }
   },
   "quote": "standard Amplify sandbox tags (\"amplify:deployment-type\" as \"sandbox\", \"amplify:friendly-name\" as \"amplifyAuth\", and \"created-by\" as \"amplify\")"
  },
  {
   "id": "tag_created_by",
   "kind": "attr",
   "tier": "detail",
   "select": "both",
   "quantifier": "all",
   "cond": {
    "path": [
     "Tags",
     "*"
    ],
    "op": "has_kv",
    "value": {
     "key": "created-by",
     "value": "amplify"
    }
   },
   "quote": "standard Amplify sandbox tags (\"amplify:deployment-type\" as \"sandbox\", \"amplify:friendly-name\" as \"amplifyAuth\", and \"created-by\" as \"amplify\")"
  },
  {
   "id": "out_pool",
   "tier": "detail",
   "quote": "the associated Cognito User Pool ID (\"us-east-1_NjyzLtLGP\")",
   "kind": "attr",
   "select": {
    "types": [
     "__output__"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "value"
    ],
    "op": "eq",
    "value": "us-east-1_NjyzLtLGP"
   }
  },
  {
   "id": "out_client",
   "kind": "any_of",
   "tier": "detail",
   "quote": "App Client ID",
   "justify": "the prompt gives no client ID value, so the output is matched by the stated word or a reference",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "__output__"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)client"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "__output__"
      ],
      "where": []
     },
     "to": {
      "types": [
       "AWS::Cognito::UserPoolClient"
      ],
      "where": []
     }
    }
   ]
  },
  {
   "id": "out_idpool",
   "tier": "detail",
   "quote": "Identity Pool ID",
   "kind": "attr",
   "select": {
    "types": [
     "__output__"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "value"
    ],
    "op": "eq",
    "value": "us-east-1:7792bdd9-773b-4af4-a7a8-035a45723fac"
   }
  },
  {
   "id": "out_auth_role",
   "kind": "any_of",
   "tier": "detail",
   "quote": "both user role references",
   "justify": "the prompt gives no role name, so the output is matched by a reference or the stated word",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "__output__"
      ],
      "where": []
     },
     "to": "auth"
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__output__"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)((^|[^n])authenticated.*role|(^|[^n])auth.?role)"
     }
    }
   ]
  },
  {
   "id": "out_unauth_role",
   "kind": "any_of",
   "tier": "detail",
   "quote": "both user role references",
   "justify": "the prompt gives no role name, so the output is matched by a reference or the stated word",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "__output__"
      ],
      "where": []
     },
     "to": "unauth"
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__output__"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)unauth(enticated)?.*role"
     }
    }
   ]
  },
  {
   "id": "out_count",
   "kind": "exists",
   "tier": "detail",
   "select": {
    "types": [
     "__output__"
    ],
    "where": []
   },
   "min": 5,
   "quote": "App Client ID, Identity Pool ID, and both user role references",
   "justify": "User Pool ID, App Client ID, Identity Pool ID and two role references are five outputs"
  },
  {
   "id": "x_allow",
   "kind": "attr",
   "tier": "extra",
   "select": "both",
   "quantifier": "all",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument",
     "Statement",
     "*",
     "Effect"
    ],
    "op": "eq",
    "value": "Allow"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
