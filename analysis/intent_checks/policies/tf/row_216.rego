package intent.tf.row_216

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "g_admin": {
   "types": [
    "aws_iam_group"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "admin"
    },
    {
     "path": [
      "path"
     ],
     "op": "eq",
     "value": "/admin/"
    }
   ]
  },
  "g_atc": {
   "types": [
    "aws_iam_group"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "admin-terraform-cloud"
    },
    {
     "path": [
      "path"
     ],
     "op": "eq",
     "value": "/admin_terraform_cloud/"
    }
   ]
  },
  "g_github": {
   "types": [
    "aws_iam_group"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "github"
    },
    {
     "path": [
      "path"
     ],
     "op": "eq",
     "value": "/github/"
    }
   ]
  },
  "g_serverless": {
   "types": [
    "aws_iam_group"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "serverless"
    },
    {
     "path": [
      "path"
     ],
     "op": "eq",
     "value": "/serverless/"
    }
   ]
  },
  "gp_wildcard": {
   "types": [
    "aws_iam_group_policy"
   ],
   "where": [
    {
     "path": [
      "policy"
     ],
     "op": "regex",
     "value": "\"Action\"\\s*:\\s*(\\[\\s*)?\"\\*\""
    },
    {
     "path": [
      "policy"
     ],
     "op": "regex",
     "value": "\"Resource\"\\s*:\\s*(\\[\\s*)?\"\\*\""
    }
   ]
  },
  "gp_github": {
   "types": [
    "aws_iam_group_policy"
   ],
   "where": [
    {
     "path": [
      "policy"
     ],
     "op": "contains",
     "value": "acm:"
    },
    {
     "path": [
      "policy"
     ],
     "op": "contains",
     "value": "cloudfront:"
    },
    {
     "path": [
      "policy"
     ],
     "op": "contains",
     "value": "iam:"
    },
    {
     "path": [
      "policy"
     ],
     "op": "contains",
     "value": "lambda:"
    },
    {
     "path": [
      "policy"
     ],
     "op": "contains",
     "value": "route53:"
    },
    {
     "path": [
      "policy"
     ],
     "op": "contains",
     "value": "s3:"
    },
    {
     "path": [
      "policy"
     ],
     "op": "contains",
     "value": "sqs:"
    }
   ]
  },
  "sls_managed": {
   "types": [
    "aws_iam_policy"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "serverless"
    },
    {
     "path": [
      "path"
     ],
     "op": "eq",
     "value": "/serverless/"
    }
   ]
  },
  "sls_role": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "serverless"
    },
    {
     "path": [
      "path"
     ],
     "op": "eq",
     "value": "/serverless/"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "group_admin",
   "kind": "exists",
   "select": "g_admin",
   "tier": "core",
   "quote": "an \"admin\" group with path \"/admin/\""
  },
  {
   "id": "group_admin_tfc",
   "kind": "exists",
   "select": "g_atc",
   "tier": "core",
   "quote": "an \"admin-terraform-cloud\" group with path \"/admin_terraform_cloud/\""
  },
  {
   "id": "group_github",
   "kind": "exists",
   "select": "g_github",
   "tier": "core",
   "quote": "a \"github\" group with path \"/github/\""
  },
  {
   "id": "group_serverless",
   "kind": "exists",
   "select": "g_serverless",
   "tier": "core",
   "quote": "a \"serverless\" group with path \"/serverless/\""
  },
  {
   "id": "admin_inline_wildcard",
   "kind": "ref",
   "from": "gp_wildcard",
   "to": "g_admin",
   "tier": "core",
   "quote": "granting full wildcard administrative permissions",
   "justify": "\"full wildcard administrative permissions\" implies Action * on Resource *"
  },
  {
   "id": "admin_tfc_inline_wildcard",
   "kind": "ref",
   "from": "gp_wildcard",
   "to": "g_atc",
   "tier": "core",
   "quote": "also granted full wildcard administrative permissions",
   "justify": "\"full wildcard administrative permissions\" implies Action * on Resource *"
  },
  {
   "id": "github_inline_policy",
   "kind": "ref",
   "from": "gp_github",
   "to": "g_github",
   "tier": "core",
   "quote": "assigned an inline policy permitting targeted ACM, CloudFront, IAM, Lambda, Route53, S3, and SQS actions"
  },
  {
   "id": "serverless_group_policy",
   "kind": "any_of",
   "tier": "core",
   "quote": "assigned a dedicated policy covering ACM, CloudFront, IAM, Lambda, CloudWatch Logs, Route53, S3, and SQS actions",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "acm:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "cloudfront:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "iam:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "lambda:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "logs:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "route53:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "s3:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "sqs:"
       }
      ]
     },
     "to": "g_serverless"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_group_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "group"
        ],
        "op": "eq",
        "value": "serverless"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "acm:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "cloudfront:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "iam:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "lambda:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "logs:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "route53:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "s3:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "sqs:"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "users_exist",
   "kind": "all_of",
   "tier": "core",
   "quote": "provision corresponding IAM users and memberships",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_user"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "admin"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_user"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "admin-macbook-pro"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_user"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "admin-terraform-cloud"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_user"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "github"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_user"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "serverless"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "member_admin",
   "kind": "any_of",
   "tier": "detail",
   "quote": "\"admin\" in the admin group",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_user_group_membership"
      ],
      "where": [
       {
        "path": [
         "user"
        ],
        "op": "eq",
        "value": "admin"
       }
      ]
     },
     "to": "g_admin"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_group_membership"
      ],
      "where": [
       {
        "path": [
         "users",
         "*"
        ],
        "op": "eq",
        "value": "admin"
       }
      ]
     },
     "to": "g_admin"
    }
   ]
  },
  {
   "id": "member_admin_macbook",
   "kind": "any_of",
   "tier": "detail",
   "quote": "\"admin-macbook-pro\" in the admin group",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_user_group_membership"
      ],
      "where": [
       {
        "path": [
         "user"
        ],
        "op": "eq",
        "value": "admin-macbook-pro"
       }
      ]
     },
     "to": "g_admin"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_group_membership"
      ],
      "where": [
       {
        "path": [
         "users",
         "*"
        ],
        "op": "eq",
        "value": "admin-macbook-pro"
       }
      ]
     },
     "to": "g_admin"
    }
   ]
  },
  {
   "id": "member_admin_tfc",
   "kind": "any_of",
   "tier": "detail",
   "quote": "\"admin-terraform-cloud\" in the admin-terraform-cloud group",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_user_group_membership"
      ],
      "where": [
       {
        "path": [
         "user"
        ],
        "op": "eq",
        "value": "admin-terraform-cloud"
       }
      ]
     },
     "to": "g_atc"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_group_membership"
      ],
      "where": [
       {
        "path": [
         "users",
         "*"
        ],
        "op": "eq",
        "value": "admin-terraform-cloud"
       }
      ]
     },
     "to": "g_atc"
    }
   ]
  },
  {
   "id": "member_github",
   "kind": "any_of",
   "tier": "detail",
   "quote": "\"github\" in the github group",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_user_group_membership"
      ],
      "where": [
       {
        "path": [
         "user"
        ],
        "op": "eq",
        "value": "github"
       }
      ]
     },
     "to": "g_github"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_group_membership"
      ],
      "where": [
       {
        "path": [
         "users",
         "*"
        ],
        "op": "eq",
        "value": "github"
       }
      ]
     },
     "to": "g_github"
    }
   ]
  },
  {
   "id": "member_serverless",
   "kind": "any_of",
   "tier": "detail",
   "quote": "\"serverless\" in the serverless group",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_user_group_membership"
      ],
      "where": [
       {
        "path": [
         "user"
        ],
        "op": "eq",
        "value": "serverless"
       }
      ]
     },
     "to": "g_serverless"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_group_membership"
      ],
      "where": [
       {
        "path": [
         "users",
         "*"
        ],
        "op": "eq",
        "value": "serverless"
       }
      ]
     },
     "to": "g_serverless"
    }
   ]
  },
  {
   "id": "access_keys",
   "kind": "all_of",
   "tier": "detail",
   "quote": "with an access key",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_access_key"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_iam_user"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "admin-macbook-pro"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_access_key"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_iam_user"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "admin-terraform-cloud"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "serverless_role",
   "kind": "exists",
   "select": "sls_role",
   "tier": "core",
   "quote": "create an IAM role named \"serverless\" with path \"/serverless/\""
  },
  {
   "id": "serverless_role_trust",
   "kind": "attr",
   "select": "sls_role",
   "tier": "core",
   "quote": "allows trust assumptions for Lambda and Edge Lambda services",
   "cond": {
    "path": [],
    "op": "match",
    "value": [
     {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "\"lambda.amazonaws.com\""
     },
     {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "edgelambda.amazonaws.com"
     },
     {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "sts:AssumeRole"
     }
    ]
   },
   "justify": "a role trust for services implies sts:AssumeRole"
  },
  {
   "id": "serverless_managed_policy",
   "kind": "exists",
   "select": "sls_managed",
   "tier": "core",
   "quote": "a customer managed policy named \"serverless\" with path \"/serverless/\""
  },
  {
   "id": "serverless_managed_policy_content",
   "kind": "attr",
   "select": "sls_managed",
   "tier": "detail",
   "quote": "containing the identical serverless policy permissions",
   "cond": {
    "path": [],
    "op": "match",
    "value": [
     {
      "path": [
       "policy"
      ],
      "op": "contains",
      "value": "acm:"
     },
     {
      "path": [
       "policy"
      ],
      "op": "contains",
      "value": "cloudfront:"
     },
     {
      "path": [
       "policy"
      ],
      "op": "contains",
      "value": "iam:"
     },
     {
      "path": [
       "policy"
      ],
      "op": "contains",
      "value": "lambda:"
     },
     {
      "path": [
       "policy"
      ],
      "op": "contains",
      "value": "logs:"
     },
     {
      "path": [
       "policy"
      ],
      "op": "contains",
      "value": "route53:"
     },
     {
      "path": [
       "policy"
      ],
      "op": "contains",
      "value": "s3:"
     },
     {
      "path": [
       "policy"
      ],
      "op": "contains",
      "value": "sqs:"
     }
    ]
   }
  },
  {
   "id": "serverless_policy_attached_to_role",
   "kind": "any_of",
   "tier": "core",
   "quote": "attaching a customer managed policy named \"serverless\"",
   "checks": [
    {
     "kind": "ref",
     "from": "sls_role",
     "to": "sls_managed"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "role"
        ],
        "op": "eq",
        "value": "serverless"
       }
      ]
     },
     "to": "sls_managed"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "roles",
         "*"
        ],
        "op": "eq",
        "value": "serverless"
       }
      ]
     },
     "to": "sls_managed"
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
