package intent.tf.row_053

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "repo": {
   "types": [
    "aws_ecr_repository"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "ecr_repo",
   "tier": "core",
   "quote": "creates an Amazon ECR repository for container images",
   "kind": "exists",
   "select": "repo"
  },
  {
   "id": "aes256_default",
   "tier": "core",
   "quote": "falling back to AES256 by default",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "repo",
     "cond": {
      "path": [
       "encryption_configuration",
       "*",
       "encryption_type"
      ],
      "op": "eq",
      "value": "AES256"
     }
    },
    {
     "kind": "attr",
     "select": "repo",
     "cond": {
      "path": [
       "encryption_configuration",
       "*"
      ],
      "op": "absent"
     }
    }
   ]
  },
  {
   "id": "optional_kms",
   "tier": "core",
   "quote": "optional customer-managed KMS encryption",
   "kind": "any_of",
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
        "value": "aws_ecr_repository"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?s)encryption_type.{0,120}KMS"
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
        "value": "aws_ecr_repository"
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
        "value": "aws_kms_key"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "repo_policy",
   "tier": "core",
   "quote": "an optional repository access policy",
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
      "op": "in",
      "value": [
       "aws_ecr_repository_policy"
      ]
     }
    ]
   }
  },
  {
   "id": "repo_policy_on_repo",
   "tier": "detail",
   "quote": "an optional repository access policy",
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
      "op": "in",
      "value": [
       "aws_ecr_repository_policy"
      ]
     }
    ]
   },
   "to": "repo"
  },
  {
   "id": "repo_policy_pull",
   "tier": "detail",
   "quote": "restricting pull access to specified AWS principals",
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
      "op": "in",
      "value": [
       "data.aws_iam_policy_document",
       "aws_ecr_repository_policy"
      ]
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)(BatchGetImage|GetDownloadUrlForLayer)"
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)principal"
     }
    ]
   }
  },
  {
   "id": "lifecycle_policy",
   "tier": "core",
   "quote": "an optional lifecycle policy for image cleanup",
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
      "op": "in",
      "value": [
       "aws_ecr_lifecycle_policy"
      ]
     }
    ]
   }
  },
  {
   "id": "lifecycle_on_repo",
   "tier": "detail",
   "quote": "an optional lifecycle policy for image cleanup",
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
      "op": "in",
      "value": [
       "aws_ecr_lifecycle_policy"
      ]
     }
    ]
   },
   "to": "repo"
  },
  {
   "id": "scan_on_push",
   "tier": "extra",
   "kind": "attr",
   "select": "repo",
   "cond": {
    "path": [
     "image_scanning_configuration",
     "*",
     "scan_on_push"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "immutable_tags",
   "tier": "extra",
   "kind": "attr",
   "select": "repo",
   "cond": {
    "path": [
     "image_tag_mutability"
    ],
    "op": "eq",
    "value": "IMMUTABLE"
   }
  },
  {
   "id": "kms_rotation",
   "tier": "extra",
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
       "aws_kms_key"
      ]
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "enable_key_rotation"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "extra_type_aws_kms_alias",
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
      "value": "aws_kms_alias"
     }
    ]
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
