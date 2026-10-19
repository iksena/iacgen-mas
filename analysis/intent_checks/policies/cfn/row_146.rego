package intent.cfn.row_146

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "pool": {
   "types": [
    "AWS::Cognito::UserPool"
   ],
   "where": []
  },
  "client": {
   "types": [
    "AWS::Cognito::UserPoolClient"
   ],
   "where": []
  },
  "py_fn": {
   "types": [
    "AWS::Lambda::Function"
   ],
   "where": [
    {
     "path": [
      "Runtime"
     ],
     "op": "regex",
     "value": "^python3"
    }
   ]
  },
  "group": {
   "types": [
    "AWS::Cognito::UserPoolGroup"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "user_pool",
   "kind": "exists",
   "select": "pool",
   "tier": "core",
   "quote": "creates a Cognito user pool for the Hospitality Insights application"
  },
  {
   "id": "prod_environment",
   "kind": "any_of",
   "tier": "detail",
   "quote": "in the prod environment",
   "checks": [
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "UserPoolName"
      ],
      "op": "contains",
      "value": "prod"
     }
    },
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "UserPoolTags",
       "*"
      ],
      "op": "eq",
      "value": "prod"
     }
    }
   ]
  },
  {
   "id": "user_pool_client",
   "kind": "ref",
   "from": {
    "types": [
     "AWS::Cognito::UserPoolClient"
    ],
    "where": []
   },
   "to": "pool",
   "tier": "core",
   "quote": "including a user pool client"
  },
  {
   "id": "session_timeout_24h",
   "kind": "any_of",
   "tier": "core",
   "quote": "configured with a 24-hour session timeout",
   "checks": [
    {
     "kind": "attr",
     "select": "client",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "AccessTokenValidity"
        ],
        "op": "eq",
        "value": 24
       },
       {
        "path": [
         "TokenValidityUnits",
         "AccessToken"
        ],
        "op": "none_eq",
        "value": "minutes"
       },
       {
        "path": [
         "TokenValidityUnits",
         "AccessToken"
        ],
        "op": "none_eq",
        "value": "seconds"
       },
       {
        "path": [
         "TokenValidityUnits",
         "AccessToken"
        ],
        "op": "none_eq",
        "value": "days"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "client",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "AccessTokenValidity"
        ],
        "op": "eq",
        "value": 1440
       },
       {
        "path": [
         "TokenValidityUnits",
         "AccessToken"
        ],
        "op": "eq",
        "value": "minutes"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "client",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "AccessTokenValidity"
        ],
        "op": "eq",
        "value": 86400
       },
       {
        "path": [
         "TokenValidityUnits",
         "AccessToken"
        ],
        "op": "eq",
        "value": "seconds"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "client",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "IdTokenValidity"
        ],
        "op": "eq",
        "value": 24
       },
       {
        "path": [
         "TokenValidityUnits",
         "IdToken"
        ],
        "op": "none_eq",
        "value": "minutes"
       },
       {
        "path": [
         "TokenValidityUnits",
         "IdToken"
        ],
        "op": "none_eq",
        "value": "seconds"
       },
       {
        "path": [
         "TokenValidityUnits",
         "IdToken"
        ],
        "op": "none_eq",
        "value": "days"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "client",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "IdTokenValidity"
        ],
        "op": "eq",
        "value": 1440
       },
       {
        "path": [
         "TokenValidityUnits",
         "IdToken"
        ],
        "op": "eq",
        "value": "minutes"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "client",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "IdTokenValidity"
        ],
        "op": "eq",
        "value": 86400
       },
       {
        "path": [
         "TokenValidityUnits",
         "IdToken"
        ],
        "op": "eq",
        "value": "seconds"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "client",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "RefreshTokenValidity"
        ],
        "op": "eq",
        "value": 1
       },
       {
        "path": [
         "TokenValidityUnits",
         "RefreshToken"
        ],
        "op": "none_eq",
        "value": "hours"
       },
       {
        "path": [
         "TokenValidityUnits",
         "RefreshToken"
        ],
        "op": "none_eq",
        "value": "minutes"
       },
       {
        "path": [
         "TokenValidityUnits",
         "RefreshToken"
        ],
        "op": "none_eq",
        "value": "seconds"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "client",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "RefreshTokenValidity"
        ],
        "op": "eq",
        "value": 24
       },
       {
        "path": [
         "TokenValidityUnits",
         "RefreshToken"
        ],
        "op": "eq",
        "value": "hours"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "client",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "RefreshTokenValidity"
        ],
        "op": "eq",
        "value": 1440
       },
       {
        "path": [
         "TokenValidityUnits",
         "RefreshToken"
        ],
        "op": "eq",
        "value": "minutes"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "client",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "RefreshTokenValidity"
        ],
        "op": "eq",
        "value": 86400
       },
       {
        "path": [
         "TokenValidityUnits",
         "RefreshToken"
        ],
        "op": "eq",
        "value": "seconds"
       }
      ]
     }
    }
   ],
   "justify": "24-hour session = access/id token validity of 24 hours (1440 min, 86400 s) or a refresh token validity of 1 day (24 h, 1440 min, 86400 s)"
  },
  {
   "id": "post_auth_trigger",
   "kind": "ref",
   "tier": "core",
   "from": {
    "types": [
     "AWS::Cognito::UserPool"
    ],
    "where": [
     {
      "path": [
       "LambdaConfig",
       "PostAuthentication"
      ],
      "op": "present"
     }
    ]
   },
   "to": "py_fn",
   "quote": "a post-authentication Lambda trigger written in Python"
  },
  {
   "id": "trigger_updates_last_login",
   "kind": "attr",
   "select": "py_fn",
   "cond": {
    "path": [
     "Code",
     "ZipFile"
    ],
    "op": "contains",
    "value": "last_login"
   },
   "tier": "detail",
   "quote": "updates a custom last_login attribute"
  },
  {
   "id": "custom_last_login_attribute",
   "kind": "attr",
   "select": "pool",
   "cond": {
    "path": [
     "Schema",
     "*",
     "Name"
    ],
    "op": "regex",
    "value": "^(custom:)?last_login$"
   },
   "tier": "detail",
   "quote": "a custom last_login attribute"
  },
  {
   "id": "groups_with_precedence",
   "kind": "all_of",
   "tier": "core",
   "quote": "three user groups named Admin, RegularUser, and PowerUser with precedence values of 1, 2, and 3 respectively",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Cognito::UserPoolGroup"
      ],
      "where": [
       {
        "path": [
         "GroupName"
        ],
        "op": "eq",
        "value": "Admin"
       }
      ]
     },
     "cond": {
      "path": [
       "Precedence"
      ],
      "op": "eq",
      "value": 1
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Cognito::UserPoolGroup"
      ],
      "where": [
       {
        "path": [
         "GroupName"
        ],
        "op": "eq",
        "value": "RegularUser"
       }
      ]
     },
     "cond": {
      "path": [
       "Precedence"
      ],
      "op": "eq",
      "value": 2
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Cognito::UserPoolGroup"
      ],
      "where": [
       {
        "path": [
         "GroupName"
        ],
        "op": "eq",
        "value": "PowerUser"
       }
      ]
     },
     "cond": {
      "path": [
       "Precedence"
      ],
      "op": "eq",
      "value": 3
     }
    }
   ]
  },
  {
   "id": "groups_in_pool",
   "kind": "ref",
   "from": "group",
   "to": "pool",
   "tier": "detail",
   "quote": "three user groups"
  },
  {
   "id": "sso_params_empty_default",
   "kind": "exists",
   "min": 2,
   "tier": "detail",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": ""
     }
    ]
   },
   "quote": "the login URL and SSO provider name passed as parameters that are left empty by default to disable SSO",
   "justify": "prompt names two parameters (login URL and SSO provider name) left empty by default"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
