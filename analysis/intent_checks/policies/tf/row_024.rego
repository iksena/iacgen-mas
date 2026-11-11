package intent.tf.row_024

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "repo",
   "tier": "core",
   "quote": "creates an Amazon ECR repository",
   "kind": "exists",
   "select": {
    "types": [
     "aws_ecr_repository"
    ],
    "where": []
   }
  },
  {
   "id": "repo_name",
   "tier": "core",
   "quote": "The ECR repository name must use a configurable variable defaulting to \"illumidesk\"",
   "kind": "attr",
   "select": {
    "types": [
     "aws_ecr_repository"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "illumidesk"
   }
  },
  {
   "id": "repo_name_var",
   "tier": "detail",
   "quote": "a configurable variable defaulting to \"illumidesk\"",
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
      "value": "illumidesk"
     }
    ]
   }
  },
  {
   "id": "immutable",
   "tier": "core",
   "quote": "set image tag mutability to IMMUTABLE",
   "kind": "attr",
   "select": {
    "types": [
     "aws_ecr_repository"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "image_tag_mutability"
    ],
    "op": "eq",
    "value": "IMMUTABLE"
   }
  },
  {
   "id": "scan_on_push",
   "tier": "core",
   "quote": "enable image scanning on push",
   "kind": "attr",
   "select": {
    "types": [
     "aws_ecr_repository"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "image_scanning_configuration",
     "*",
     "scan_on_push"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "tag_name",
   "tier": "detail",
   "quote": "Name set to \"illumidesk-eks\"",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_ecr_repository"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "illumidesk-eks"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_ecr_repository"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "tags_all",
       "Name"
      ],
      "op": "eq",
      "value": "illumidesk-eks"
     }
    }
   ]
  },
  {
   "id": "tag_env",
   "tier": "detail",
   "quote": "Environment set to \"dev\"",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_ecr_repository"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "tags",
       "Environment"
      ],
      "op": "eq",
      "value": "dev"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_ecr_repository"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "tags_all",
       "Environment"
      ],
      "op": "eq",
      "value": "dev"
     }
    }
   ]
  },
  {
   "id": "tags_var",
   "tier": "detail",
   "quote": "accept a map of resource tags defaulting to Name set to \"illumidesk-eks\" and Environment set to \"dev\"",
   "kind": "exists",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "default",
       "Name"
      ],
      "op": "eq",
      "value": "illumidesk-eks"
     },
     {
      "path": [
       "default",
       "Environment"
      ],
      "op": "eq",
      "value": "dev"
     }
    ]
   }
  },
  {
   "id": "lifecycle_attached",
   "tier": "core",
   "quote": "attach an ECR lifecycle policy containing two rules",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_ecr_lifecycle_policy"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_ecr_repository"
      ],
      "where": []
     }
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "aws_ecr_lifecycle_policy"
      ],
      "where": []
     },
     "from_path": [
      "repository"
     ],
     "to": {
      "types": [
       "aws_ecr_repository"
      ],
      "where": []
     },
     "to_path": [
      "name"
     ]
    }
   ]
  },
  {
   "id": "rule1_untagged_14",
   "tier": "core",
   "quote": "rule priority 1 must expire untagged images older than 14 days since they were pushed",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_ecr_lifecycle_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?is)rulePriority[\"\\']?\\s*[:=]\\s*1\\b(?:[^}]*\\}?[^}]*tagStatus[\"\\']?\\s*[:=]\\s*[\"\\']?untagged[^}]*countNumber[\"\\']?\\s*[:=]\\s*14\\b|[^}]*tagStatus[\"\\']?\\s*[:=]\\s*[\"\\']?untagged[^}]*\\}?[^}]*countNumber[\"\\']?\\s*[:=]\\s*14\\b|[^}]*\\}?[^}]*countNumber[\"\\']?\\s*[:=]\\s*14\\b[^}]*tagStatus[\"\\']?\\s*[:=]\\s*[\"\\']?untagged|[^}]*countNumber[\"\\']?\\s*[:=]\\s*14\\b[^}]*\\}?[^}]*tagStatus[\"\\']?\\s*[:=]\\s*[\"\\']?untagged)"
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
        "value": "aws_ecr_lifecycle_policy"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?is)rulePriority[\"\\']?\\s*[:=]\\s*1\\b(?:[^}]*\\}?[^}]*tagStatus[\"\\']?\\s*[:=]\\s*[\"\\']?untagged[^}]*countNumber[\"\\']?\\s*[:=]\\s*14\\b|[^}]*tagStatus[\"\\']?\\s*[:=]\\s*[\"\\']?untagged[^}]*\\}?[^}]*countNumber[\"\\']?\\s*[:=]\\s*14\\b|[^}]*\\}?[^}]*countNumber[\"\\']?\\s*[:=]\\s*14\\b[^}]*tagStatus[\"\\']?\\s*[:=]\\s*[\"\\']?untagged|[^}]*countNumber[\"\\']?\\s*[:=]\\s*14\\b[^}]*\\}?[^}]*tagStatus[\"\\']?\\s*[:=]\\s*[\"\\']?untagged)"
     }
    }
   ]
  },
  {
   "id": "rule1_since_pushed",
   "tier": "core",
   "quote": "rule priority 1 must expire untagged images older than 14 days since they were pushed",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_ecr_lifecycle_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?is)rulePriority[\"\\']?\\s*[:=]\\s*1\\b[^}]*\\}?[^}]*countType[\"\\']?\\s*[:=]\\s*[\"\\']?sinceImagePushed"
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
        "value": "aws_ecr_lifecycle_policy"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?is)rulePriority[\"\\']?\\s*[:=]\\s*1\\b[^}]*\\}?[^}]*countType[\"\\']?\\s*[:=]\\s*[\"\\']?sinceImagePushed"
     }
    }
   ]
  },
  {
   "id": "rule2_count_30",
   "tier": "core",
   "quote": "rule priority 2 must expire images when the total image count exceeds 30",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_ecr_lifecycle_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?is)rulePriority[\"\\']?\\s*[:=]\\s*2\\b(?:[^}]*\\}?[^}]*countType[\"\\']?\\s*[:=]\\s*[\"\\']?imageCountMoreThan[^}]*countNumber[\"\\']?\\s*[:=]\\s*30\\b|[^}]*countType[\"\\']?\\s*[:=]\\s*[\"\\']?imageCountMoreThan[^}]*\\}?[^}]*countNumber[\"\\']?\\s*[:=]\\s*30\\b|[^}]*\\}?[^}]*countNumber[\"\\']?\\s*[:=]\\s*30\\b[^}]*countType[\"\\']?\\s*[:=]\\s*[\"\\']?imageCountMoreThan|[^}]*countNumber[\"\\']?\\s*[:=]\\s*30\\b[^}]*\\}?[^}]*countType[\"\\']?\\s*[:=]\\s*[\"\\']?imageCountMoreThan)"
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
        "value": "aws_ecr_lifecycle_policy"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?is)rulePriority[\"\\']?\\s*[:=]\\s*2\\b(?:[^}]*\\}?[^}]*countType[\"\\']?\\s*[:=]\\s*[\"\\']?imageCountMoreThan[^}]*countNumber[\"\\']?\\s*[:=]\\s*30\\b|[^}]*countType[\"\\']?\\s*[:=]\\s*[\"\\']?imageCountMoreThan[^}]*\\}?[^}]*countNumber[\"\\']?\\s*[:=]\\s*30\\b|[^}]*\\}?[^}]*countNumber[\"\\']?\\s*[:=]\\s*30\\b[^}]*countType[\"\\']?\\s*[:=]\\s*[\"\\']?imageCountMoreThan|[^}]*countNumber[\"\\']?\\s*[:=]\\s*30\\b[^}]*\\}?[^}]*countType[\"\\']?\\s*[:=]\\s*[\"\\']?imageCountMoreThan)"
     }
    }
   ]
  },
  {
   "id": "rule2_any_status",
   "tier": "detail",
   "quote": "rule priority 2 must expire images when the total image count exceeds 30 for any tag status",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_ecr_lifecycle_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?is)rulePriority[\"\\']?\\s*[:=]\\s*2\\b[^}]*\\}?[^}]*tagStatus[\"\\']?\\s*[:=]\\s*[\"\\']?any\\b"
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
        "value": "aws_ecr_lifecycle_policy"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?is)rulePriority[\"\\']?\\s*[:=]\\s*2\\b[^}]*\\}?[^}]*tagStatus[\"\\']?\\s*[:=]\\s*[\"\\']?any\\b"
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
