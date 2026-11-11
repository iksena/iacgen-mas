package intent.tf.row_124

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "repo": {
   "types": [
    "aws_ecr_repository"
   ],
   "where": []
  },
  "pols": {
   "types": [
    "aws_iam_policy"
   ],
   "where": []
  },
  "rpol": {
   "types": [
    "aws_ecr_repository_policy"
   ],
   "where": []
  },
  "d_readpol": {
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
    },
    {
     "path": [
      "properties",
      "name"
     ],
     "op": "contains",
     "value": "-ecr-read"
    }
   ]
  },
  "d_writepol": {
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
    },
    {
     "path": [
      "properties",
      "name"
     ],
     "op": "contains",
     "value": "-ecr-write"
    }
   ]
  },
  "d_rpol_res": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "aws_ecr_repository_policy"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "repo_exists",
   "kind": "exists",
   "tier": "core",
   "select": "repo",
   "quote": "managed Amazon ECR container repository"
  },
  {
   "id": "namespace_var",
   "kind": "exists",
   "tier": "detail",
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
      "value": "namespace"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": ""
     }
    ]
   },
   "quote": "optional namespace variable (defaulting to empty)"
  },
  {
   "id": "petname",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "random_pet"
      ],
      "where": []
     }
    },
    {
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
        "value": "random_pet"
       }
      ]
     }
    }
   ],
   "quote": "petname generation when null or empty"
  },
  {
   "id": "mutability_immutable",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "repo",
     "cond": {
      "path": [
       "image_tag_mutability"
      ],
      "op": "eq",
      "value": "IMMUTABLE"
     }
    }
   ],
   "quote": "image tag mutability defaulting to \"IMMUTABLE\""
  },
  {
   "id": "scan_on_push",
   "kind": "attr",
   "tier": "core",
   "select": "repo",
   "cond": {
    "path": [
     "image_scanning_configuration",
     "*",
     "scan_on_push"
    ],
    "op": "eq",
    "value": true
   },
   "quote": "image scan on push defaulting to true"
  },
  {
   "id": "lifecycle_declared",
   "kind": "exists",
   "tier": "core",
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
      "value": "aws_ecr_lifecycle_policy"
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "gate"
      ],
      "op": "regex",
      "value": "lifecycle_policy"
     }
    ]
   },
   "quote": "a lifecycle policy that is only created when a lifecycle_policy JSON string is supplied"
  },
  {
   "id": "lifecycle_var",
   "kind": "exists",
   "tier": "detail",
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
      "value": "lifecycle_policy"
     }
    ]
   },
   "quote": "only created when a lifecycle_policy JSON string is supplied (defaulting to null, so no lifecycle policy is created by default)"
  },
  {
   "id": "read_policy_named",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
     "select": "d_readpol"
    },
    {
     "kind": "attr",
     "select": "pols",
     "cond": {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "-ecr-read$"
     }
    }
   ],
   "quote": "IAM policy named \"<local_name>-ecr-read\""
  },
  {
   "id": "read_policy_actions",
   "kind": "any_of",
   "tier": "core",
   "quote": "allowing ecr:BatchCheckLayerAvailability, ecr:BatchGetImage, ecr:DescribeImages, ecr:DescribeRepositories, ecr:GetAuthorizationToken, ecr:GetDownloadUrlForLayer, and ecr:ListImages",
   "checks": [
    {
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
        "value": "aws_iam_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "contains",
        "value": "-ecr-read"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "(?i)ecr:BatchCheckLayerAvailability([^A-Za-z]|$)"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "(?i)ecr:BatchGetImage([^A-Za-z]|$)"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "(?i)ecr:DescribeImages([^A-Za-z]|$)"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "(?i)ecr:DescribeRepositories([^A-Za-z]|$)"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "(?i)ecr:GetAuthorizationToken([^A-Za-z]|$)"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "(?i)ecr:GetDownloadUrlForLayer([^A-Za-z]|$)"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "(?i)ecr:ListImages([^A-Za-z]|$)"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "d_readpol",
     "to": {
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
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ecr:BatchCheckLayerAvailability([^A-Za-z]|$)"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ecr:BatchGetImage([^A-Za-z]|$)"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ecr:DescribeImages([^A-Za-z]|$)"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ecr:DescribeRepositories([^A-Za-z]|$)"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ecr:GetAuthorizationToken([^A-Za-z]|$)"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ecr:GetDownloadUrlForLayer([^A-Za-z]|$)"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ecr:ListImages([^A-Za-z]|$)"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "-ecr-read$"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)ecr:BatchCheckLayerAvailability([^A-Za-z]|$)"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)ecr:BatchGetImage([^A-Za-z]|$)"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)ecr:DescribeImages([^A-Za-z]|$)"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)ecr:DescribeRepositories([^A-Za-z]|$)"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)ecr:GetAuthorizationToken([^A-Za-z]|$)"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)ecr:GetDownloadUrlForLayer([^A-Za-z]|$)"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)ecr:ListImages([^A-Za-z]|$)"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "-ecr-read$"
       }
      ]
     },
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*",
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "ecr:BatchCheckLayerAvailability"
       },
       {
        "path": [
         "statement",
         "*",
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "ecr:BatchGetImage"
       },
       {
        "path": [
         "statement",
         "*",
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "ecr:DescribeImages"
       },
       {
        "path": [
         "statement",
         "*",
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "ecr:DescribeRepositories"
       },
       {
        "path": [
         "statement",
         "*",
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "ecr:GetAuthorizationToken"
       },
       {
        "path": [
         "statement",
         "*",
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "ecr:GetDownloadUrlForLayer"
       },
       {
        "path": [
         "statement",
         "*",
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "ecr:ListImages"
       }
      ]
     }
    },
    {
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
        "value": "aws_iam_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "contains",
        "value": "-ecr-read"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "(?i)local\\.[A-Za-z0-9_]*read[A-Za-z0-9_]*action"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "write_policy_named",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
     "select": "d_writepol"
    },
    {
     "kind": "attr",
     "select": "pols",
     "cond": {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "-ecr-write$"
     }
    }
   ],
   "quote": "IAM policy named \"<local_name>-ecr-write\""
  },
  {
   "id": "write_policy_actions",
   "kind": "any_of",
   "tier": "core",
   "quote": "allowing ecr:PutImage, ecr:UploadLayerPart, ecr:InitiateLayerUpload, and ecr:CompleteLayerUpload",
   "checks": [
    {
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
        "value": "aws_iam_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "contains",
        "value": "-ecr-write"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "(?i)ecr:PutImage([^A-Za-z]|$)"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "(?i)ecr:UploadLayerPart([^A-Za-z]|$)"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "(?i)ecr:InitiateLayerUpload([^A-Za-z]|$)"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "(?i)ecr:CompleteLayerUpload([^A-Za-z]|$)"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "d_writepol",
     "to": {
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
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ecr:PutImage([^A-Za-z]|$)"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ecr:UploadLayerPart([^A-Za-z]|$)"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ecr:InitiateLayerUpload([^A-Za-z]|$)"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ecr:CompleteLayerUpload([^A-Za-z]|$)"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "-ecr-write$"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)ecr:PutImage([^A-Za-z]|$)"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)ecr:UploadLayerPart([^A-Za-z]|$)"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)ecr:InitiateLayerUpload([^A-Za-z]|$)"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)ecr:CompleteLayerUpload([^A-Za-z]|$)"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "-ecr-write$"
       }
      ]
     },
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*",
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "ecr:PutImage"
       },
       {
        "path": [
         "statement",
         "*",
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "ecr:UploadLayerPart"
       },
       {
        "path": [
         "statement",
         "*",
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "ecr:InitiateLayerUpload"
       },
       {
        "path": [
         "statement",
         "*",
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "ecr:CompleteLayerUpload"
       }
      ]
     }
    },
    {
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
        "value": "aws_iam_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "contains",
        "value": "-ecr-write"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "(?i)local\\.[A-Za-z0-9_]*write[A-Za-z0-9_]*action"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "policies_on_repo_arn",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "ref",
     "from": "pols",
     "to": "repo"
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
        "value": "data.aws_iam_policy_document"
       }
      ]
     },
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_ecr_repository"
       }
      ]
     }
    }
   ],
   "quote": "on the repository ARN"
  },
  {
   "id": "repo_policy_exists",
   "kind": "exists",
   "tier": "core",
   "select": "rpol",
   "quote": "an ECR repository policy titled \"AllowCrossAccountAccess\""
  },
  {
   "id": "repo_policy_sid",
   "kind": "any_of",
   "tier": "core",
   "quote": "titled \"AllowCrossAccountAccess\"",
   "checks": [
    {
     "kind": "attr",
     "select": "rpol",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "AllowCrossAccountAccess"
     }
    },
    {
     "kind": "attr",
     "select": "d_rpol_res",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "AllowCrossAccountAccess"
     }
    },
    {
     "kind": "ref",
     "from": "d_rpol_res",
     "to": {
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
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "AllowCrossAccountAccess"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "rpol",
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*",
         "sid"
        ],
        "op": "eq",
        "value": "AllowCrossAccountAccess"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "repo_policy_read",
   "kind": "any_of",
   "tier": "detail",
   "quote": "granting read access to the current caller account",
   "checks": [
    {
     "kind": "attr",
     "select": "rpol",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ecr:(BatchGetImage|GetDownloadUrlForLayer)"
     }
    },
    {
     "kind": "attr",
     "select": "d_rpol_res",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ecr:(BatchGetImage|GetDownloadUrlForLayer)"
     }
    },
    {
     "kind": "ref",
     "from": "d_rpol_res",
     "to": {
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
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ecr:(BatchGetImage|GetDownloadUrlForLayer)"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "rpol",
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*",
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "ecr:BatchGetImage"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "repo_policy_caller",
   "kind": "any_of",
   "tier": "detail",
   "quote": "granting read access to the current caller account",
   "checks": [
    {
     "kind": "ref",
     "from": "d_rpol_res",
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_caller_identity"
       }
      ]
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "AllowCrossAccountAccess"
       }
      ]
     },
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_caller_identity"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rpol",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "000000000000"
     }
    }
   ],
   "justify": "000000000000 is the adapter's value for the current caller account, which the prompt names"
  },
  {
   "id": "trusted_accounts_var",
   "kind": "exists",
   "tier": "detail",
   "quote": "a trusted_accounts list variable",
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
      "value": "trusted_accounts"
     }
    ]
   }
  },
  {
   "id": "repo_policy_trusted_accounts",
   "kind": "any_of",
   "tier": "detail",
   "quote": "any additional AWS account IDs supplied in a trusted_accounts list variable",
   "checks": [
    {
     "kind": "attr",
     "select": "d_rpol_res",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "var\\.trusted_accounts|local\\.[A-Za-z0-9_]*account"
     }
    },
    {
     "kind": "ref",
     "from": "d_rpol_res",
     "to": {
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
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "var\\.trusted_accounts|local\\.[A-Za-z0-9_]*account"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "repo_policy_on_repo",
   "kind": "ref",
   "tier": "detail",
   "from": "rpol",
   "to": "repo",
   "quote": "an ECR repository policy"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
