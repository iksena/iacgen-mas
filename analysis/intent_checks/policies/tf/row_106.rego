package intent.tf.row_106

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "role",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_iam_role"
    ],
    "where": []
   },
   "quote": "creates a cross-account IAM role integration for Prisma Cloud"
  },
  {
   "id": "role_name",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "PrismaCloudReadWriteRole"
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
        "value": "aws_iam_role"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "name"
      ],
      "op": "contains",
      "value": "PrismaCloudReadWriteRole"
     }
    }
   ],
   "quote": "an IAM role name defaulting to \"PrismaCloudReadWriteRole\""
  },
  {
   "id": "var_region",
   "tier": "detail",
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
      "op": "regex",
      "value": "(?i)region"
     }
    ]
   },
   "quote": "variables for an AWS region",
   "justify": "a region variable is requested; name not pinned"
  },
  {
   "id": "var_role_name",
   "tier": "detail",
   "kind": "exists",
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
      "value": "PrismaCloudReadWriteRole"
     }
    ]
   },
   "quote": "an IAM role name defaulting to \"PrismaCloudReadWriteRole\""
  },
  {
   "id": "var_read_write",
   "tier": "detail",
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
      "value": "read_write"
     }
    ]
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": false
   },
   "quote": "a boolean flag named read_write defaulting to false"
  },
  {
   "id": "random_id",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "random_string",
     "random_password",
     "random_id"
    ],
    "where": []
   },
   "quote": "generate a random 32-character alphanumeric external ID"
  },
  {
   "id": "random_len",
   "tier": "core",
   "kind": "any_of",
   "quote": "random 32-character alphanumeric external ID",
   "justify": "16 random bytes hex-encode to exactly 32 alphanumeric characters",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "random_string",
       "random_password"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "length"
      ],
      "op": "eq",
      "value": 32
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "random_id"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "byte_length"
      ],
      "op": "eq",
      "value": 16
     }
    }
   ]
  },
  {
   "id": "random_nospecial",
   "tier": "detail",
   "kind": "any_of",
   "quote": "alphanumeric external ID without special characters",
   "justify": "a 16-byte random_id is only 32 characters as hex, which has no special characters",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "random_string",
       "random_password"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "special"
      ],
      "op": "eq",
      "value": false
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "random_id"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "byte_length"
      ],
      "op": "eq",
      "value": 16
     }
    }
   ]
  },
  {
   "id": "trust_principal",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "arn:aws:iam::188619942792:root"
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
        "value": "aws_iam_role"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "arn:aws:iam::188619942792:root"
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
       "statement"
      ],
      "op": "regex",
      "value": "arn:aws:iam::188619942792:root"
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
       "properties"
      ],
      "op": "regex",
      "value": "arn:aws:iam::188619942792:root"
     }
    }
   ],
   "quote": "allowing assumption by the principal \"arn:aws:iam::188619942792:root\""
  },
  {
   "id": "trust_extid",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "(?is)stringequals.{0,200}sts:externalid"
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
        "value": "aws_iam_role"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "(?is)stringequals.{0,200}sts:externalid"
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
       "statement"
      ],
      "op": "regex",
      "value": "(?is)stringequals.{0,200}sts:externalid"
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
       "properties"
      ],
      "op": "regex",
      "value": "(?is)stringequals.{0,200}sts:externalid"
     }
    }
   ],
   "quote": "conditioned on a StringEquals check against the generated external ID"
  },
  {
   "id": "trust_random",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     },
     "to": {
      "types": [
       "random_string",
       "random_password",
       "random_id"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": []
     },
     "to": {
      "types": [
       "random_string",
       "random_password",
       "random_id"
      ],
      "where": []
     }
    }
   ],
   "quote": "a StringEquals check against the generated external ID"
  },
  {
   "id": "attach_audit",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "eq",
        "value": "arn:aws:iam::aws:policy/SecurityAudit"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_iam_role_policy_attachment"
       },
       {
        "path": [
         "properties",
         "policy_arn"
        ],
        "op": "eq",
        "value": "arn:aws:iam::aws:policy/SecurityAudit"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "managed_policy_arns",
       "*"
      ],
      "op": "eq",
      "value": "arn:aws:iam::aws:policy/SecurityAudit"
     }
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
         "policy_arn"
        ],
        "op": "eq",
        "value": "arn:aws:iam::aws:policy/SecurityAudit"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     }
    }
   ],
   "quote": "Attach the managed SecurityAudit policy (\"arn:aws:iam::aws:policy/SecurityAudit\") to the role"
  },
  {
   "id": "ro_policy_name",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "PrismaCloud-IAM-ReadOnly-Policy"
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
        "value": "aws_iam_role_policy"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "name"
      ],
      "op": "eq",
      "value": "PrismaCloud-IAM-ReadOnly-Policy"
     }
    }
   ],
   "quote": "an inline policy named \"PrismaCloud-IAM-ReadOnly-Policy\""
  },
  {
   "id": "ro_policy_role",
   "tier": "detail",
   "kind": "ref",
   "from": {
    "types": [
     "aws_iam_role_policy"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_iam_role"
    ],
    "where": []
   },
   "quote": "an inline policy named \"PrismaCloud-IAM-ReadOnly-Policy\""
  },
  {
   "id": "ro_actions_1",
   "tier": "detail",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)apigateway:GET"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)cognito-identity:ListTagsForResource"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)cognito-idp:ListTagsForResource"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ecr:DescribeImages"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ecr:GetLifecyclePolicy"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)elasticbeanstalk:ListTagsForResource"
     }
    }
   ],
   "quote": "apigateway:GET, cognito-identity:ListTagsForResource, cognito-idp:ListTagsForResource, ecr:DescribeImages, ecr:GetLifecyclePolicy, elasticbeanstalk:ListTagsForResource"
  },
  {
   "id": "ro_actions_2",
   "tier": "detail",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)elasticfilesystem:DescribeTags"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)glacier:GetVaultLock"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)glacier:ListTagsForVault"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)glue:GetSecurityConfigurations"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)logs:GetLogEvents"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)mq:listBrokers"
     }
    }
   ],
   "quote": "elasticfilesystem:DescribeTags, glacier:GetVaultLock, glacier:ListTagsForVault, glue:GetSecurityConfigurations, logs:GetLogEvents, mq:listBrokers"
  },
  {
   "id": "ro_actions_3",
   "tier": "detail",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)mq:describeBroker"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ram:GetResourceShares"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)secretsmanager:DescribeSecret"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ssm:GetParameters"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ssm:ListTagsForResource"
     }
    }
   ],
   "quote": "mq:describeBroker, ram:GetResourceShares, secretsmanager:DescribeSecret, ssm:GetParameters, ssm:ListTagsForResource"
  },
  {
   "id": "ro_actions_4",
   "tier": "detail",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)sqs:SendMessage"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)elasticmapreduce:ListSecurityConfigurations"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)sns:listSubscriptions"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)wafv2:ListResourcesForWebACL"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)wafv2:ListWebACLs"
     }
    }
   ],
   "quote": "sqs:SendMessage, elasticmapreduce:ListSecurityConfigurations, sns:listSubscriptions, wafv2:ListResourcesForWebACL, and wafv2:ListWebACLs"
  },
  {
   "id": "ro_all_resources",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?is)[\"']Resource[\"']\\s*:\\s*\\[?\\s*[\"']\\*[\"']"
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
        "value": "aws_iam_role_policy"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?is)[\"']Resource[\"']\\s*:\\s*\\[?\\s*[\"']\\*[\"']"
     }
    },
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
      "value": "(?is)[\"']Resource[\"']\\s*:\\s*\\[?\\s*[\"']\\*[\"']"
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
        "value": "aws_iam_policy"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?is)[\"']Resource[\"']\\s*:\\s*\\[?\\s*[\"']\\*[\"']"
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
       "statement"
      ],
      "op": "regex",
      "value": "(?is)[\"']Resource[\"']\\s*:\\s*\\[?\\s*[\"']\\*[\"']"
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
       "properties"
      ],
      "op": "regex",
      "value": "(?is)[\"']Resource[\"']\\s*:\\s*\\[?\\s*[\"']\\*[\"']"
     }
    }
   ],
   "quote": "across all resources"
  },
  {
   "id": "rem_policy",
   "tier": "core",
   "kind": "exists",
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
      "value": "aws_iam_role_policy"
     },
     {
      "path": [
       "properties",
       "name"
      ],
      "op": "eq",
      "value": "PrismaCloud-IAM-Remediation-Policy"
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     }
    ]
   },
   "quote": "conditionally create an inline remediation policy named \"PrismaCloud-IAM-Remediation-Policy\""
  },
  {
   "id": "rem_gate",
   "tier": "core",
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
      "value": "aws_iam_role_policy"
     },
     {
      "path": [
       "properties",
       "name"
      ],
      "op": "eq",
      "value": "PrismaCloud-IAM-Remediation-Policy"
     }
    ]
   },
   "cond": {
    "path": [
     "gate"
    ],
    "op": "regex",
    "value": "read_write"
   },
   "quote": "attached to the role when read_write is true"
  },
  {
   "id": "rem_role",
   "tier": "detail",
   "kind": "ref",
   "from": {
    "types": [
     "__declared__"
    ],
    "where": [
     {
      "path": [
       "type"
      ],
      "op": "eq",
      "value": "aws_iam_role_policy"
     },
     {
      "path": [
       "properties",
       "name"
      ],
      "op": "eq",
      "value": "PrismaCloud-IAM-Remediation-Policy"
     }
    ]
   },
   "to": {
    "types": [
     "aws_iam_role"
    ],
    "where": []
   },
   "quote": "attached to the role when read_write is true"
  },
  {
   "id": "rem_actions",
   "tier": "detail",
   "kind": "all_of",
   "checks": [
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
        "value": "aws_iam_role_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "PrismaCloud-IAM-Remediation-Policy"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)iam:UpdateAccountPasswordPolicy"
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
        "value": "aws_iam_role_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "PrismaCloud-IAM-Remediation-Policy"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ec2:ModifyImageAttribute"
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
        "value": "aws_iam_role_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "PrismaCloud-IAM-Remediation-Policy"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)rds:ModifyDBSnapshotAttribute"
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
        "value": "aws_iam_role_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "PrismaCloud-IAM-Remediation-Policy"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)s3:PutBucketAcl"
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
        "value": "aws_iam_role_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "PrismaCloud-IAM-Remediation-Policy"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ec2:RevokeSecurityGroupIngress"
     }
    }
   ],
   "quote": "allowing iam:UpdateAccountPasswordPolicy, ec2:ModifyImageAttribute, rds:ModifyDBSnapshotAttribute, s3:PutBucketAcl, and ec2:RevokeSecurityGroupIngress across all resources"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
