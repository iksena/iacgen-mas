package intent.tf.row_207

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "user": {
   "types": [
    "aws_iam_user"
   ],
   "where": []
  },
  "key": {
   "types": [
    "aws_iam_access_key"
   ],
   "where": []
  },
  "ssm": {
   "types": [
    "aws_ssm_parameter"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "user",
   "kind": "exists",
   "select": "user",
   "tier": "core",
   "quote": "create an IAM user defaulting in name to \"cert-manager\""
  },
  {
   "id": "user_name",
   "kind": "attr",
   "select": "user",
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "cert-manager"
   },
   "tier": "core",
   "quote": "defaulting in name to \"cert-manager\""
  },
  {
   "id": "key",
   "kind": "exists",
   "select": "key",
   "tier": "core",
   "quote": "generate a set of IAM access keys for the user"
  },
  {
   "id": "key_user",
   "kind": "ref",
   "from": "key",
   "to": "user",
   "tier": "core",
   "quote": "generate a set of IAM access keys for the user"
  },
  {
   "id": "ssm_access",
   "kind": "exists",
   "select": {
    "types": [
     "aws_ssm_parameter"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "/cert-manager/access-key"
     },
     {
      "path": [
       "type"
      ],
      "op": "eq",
      "value": "SecureString"
     }
    ]
   },
   "tier": "core",
   "quote": "SecureString parameters at \"/cert-manager/access-key\""
  },
  {
   "id": "ssm_secret",
   "kind": "exists",
   "select": {
    "types": [
     "aws_ssm_parameter"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "/cert-manager/secret-key"
     },
     {
      "path": [
       "type"
      ],
      "op": "eq",
      "value": "SecureString"
     }
    ]
   },
   "tier": "core",
   "quote": "\"/cert-manager/secret-key\" respectively"
  },
  {
   "id": "ssm_from_key",
   "kind": "ref",
   "from": "ssm",
   "to": "key",
   "tier": "detail",
   "quote": "securely store the resulting access key ID and secret access key in AWS Systems Manager Parameter Store"
  },
  {
   "id": "param_hosted_zone",
   "kind": "exists",
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
      "value": "hosted_zone_id"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "*"
     }
    ]
   },
   "tier": "detail",
   "quote": "a configurable hosted_zone_id variable defaulting to \"*\""
  },
  {
   "id": "policy_not_attached",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": []
     },
     "quantifier": "all",
     "cond": {
      "path": [
       "type"
      ],
      "op": "none_eq",
      "value": "aws_iam_user_policy_attachment"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": []
     },
     "quantifier": "all",
     "cond": {
      "path": [
       "type"
      ],
      "op": "none_eq",
      "value": "aws_iam_user_policy"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": []
     },
     "quantifier": "all",
     "cond": {
      "path": [
       "type"
      ],
      "op": "none_eq",
      "value": "aws_iam_policy_attachment"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": []
     },
     "quantifier": "all",
     "cond": {
      "path": [
       "type"
      ],
      "op": "none_eq",
      "value": "aws_iam_group_policy_attachment"
     }
    }
   ],
   "tier": "core",
   "quote": "define (but do not attach) an IAM policy document",
   "justify": "'do not attach' forbids any resource attaching a policy to the user (attachment, inline user policy, policy_attachment or group attachment)"
  },
  {
   "id": "pol_getchange",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "aws_iam_role_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)route53:(GetChange|\\*)([^A-Za-z0-9_]|$)"
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
        "op": "in",
        "value": [
         "data.aws_iam_policy_document",
         "aws_iam_policy",
         "aws_iam_user_policy",
         "aws_iam_role_policy"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)route53:(GetChange|\\*)([^A-Za-z0-9_]|$)"
     }
    }
   ],
   "tier": "core",
   "quote": "route53:GetChange on change resources"
  },
  {
   "id": "pol_changerrs",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "aws_iam_role_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)route53:(ChangeResourceRecordSets|\\*)([^A-Za-z0-9_]|$)"
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
        "op": "in",
        "value": [
         "data.aws_iam_policy_document",
         "aws_iam_policy",
         "aws_iam_user_policy",
         "aws_iam_role_policy"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)route53:(ChangeResourceRecordSets|\\*)([^A-Za-z0-9_]|$)"
     }
    }
   ],
   "tier": "core",
   "quote": "route53:ChangeResourceRecordSets and route53:ListResourceRecordSets on the specific hosted zone resource"
  },
  {
   "id": "pol_listrrs",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "aws_iam_role_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)route53:(ListResourceRecordSets|\\*)([^A-Za-z0-9_]|$)"
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
        "op": "in",
        "value": [
         "data.aws_iam_policy_document",
         "aws_iam_policy",
         "aws_iam_user_policy",
         "aws_iam_role_policy"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)route53:(ListResourceRecordSets|\\*)([^A-Za-z0-9_]|$)"
     }
    }
   ],
   "tier": "core",
   "quote": "route53:ChangeResourceRecordSets and route53:ListResourceRecordSets on the specific hosted zone resource"
  },
  {
   "id": "pol_listzones",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "aws_iam_role_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)route53:(ListHostedZonesByName|\\*)([^A-Za-z0-9_]|$)"
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
        "op": "in",
        "value": [
         "data.aws_iam_policy_document",
         "aws_iam_policy",
         "aws_iam_user_policy",
         "aws_iam_role_policy"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)route53:(ListHostedZonesByName|\\*)([^A-Za-z0-9_]|$)"
     }
    }
   ],
   "tier": "core",
   "quote": "route53:ListHostedZonesByName globally"
  },
  {
   "id": "pol_change_arn",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "aws_iam_role_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "route53:(GetChange|\\*)\"[^{}]*:::change/"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "route53:GetChange"
       },
       {
        "path": [
         "resources",
         "*"
        ],
        "op": "regex",
        "value": ":::change/"
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
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "route53:GetChange"
       },
       {
        "path": [
         "resources",
         "*"
        ],
        "op": "regex",
        "value": ":::change/"
       }
      ]
     }
    }
   ],
   "tier": "detail",
   "quote": "route53:GetChange on change resources"
  },
  {
   "id": "pol_zone_arn",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "aws_iam_role_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(route53:ChangeResourceRecordSets\"[^{}]*route53:ListResourceRecordSets\"|route53:ListResourceRecordSets\"[^{}]*route53:ChangeResourceRecordSets\"|route53:\\*\")[^{}]*:::hostedzone/"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "route53:ChangeResourceRecordSets"
       },
       {
        "path": [
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "route53:ListResourceRecordSets"
       },
       {
        "path": [
         "resources",
         "*"
        ],
        "op": "regex",
        "value": ":::hostedzone/"
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
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "route53:ChangeResourceRecordSets"
       },
       {
        "path": [
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "route53:ListResourceRecordSets"
       },
       {
        "path": [
         "resources",
         "*"
        ],
        "op": "regex",
        "value": ":::hostedzone/"
       }
      ]
     }
    }
   ],
   "tier": "detail",
   "quote": "route53:ChangeResourceRecordSets and route53:ListResourceRecordSets on the specific hosted zone resource"
  },
  {
   "id": "pol_listzones_global",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "aws_iam_role_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "route53:(ListHostedZonesByName|\\*)\"[^{}]*\"Resource\":\\[?\"\\*\""
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "route53:ListHostedZonesByName"
       },
       {
        "path": [
         "resources",
         "*"
        ],
        "op": "eq",
        "value": "*"
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
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "route53:ListHostedZonesByName"
       },
       {
        "path": [
         "resources",
         "*"
        ],
        "op": "eq",
        "value": "*"
       }
      ]
     }
    }
   ],
   "tier": "detail",
   "quote": "route53:ListHostedZonesByName globally",
   "justify": "globally means the resource is the wildcard *"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
