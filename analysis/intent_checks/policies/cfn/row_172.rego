# GENERATED from specs/cfn/row_172.json by intent_checks/build.py -- do not edit.
package intent.cfn.row_172

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "bucket": {
   "types": [
    "AWS::S3::Bucket"
   ],
   "where": []
  },
  "ecr": {
   "types": [
    "AWS::ECR::Repository"
   ],
   "where": []
  },
  "key": {
   "types": [
    "AWS::KMS::Key"
   ],
   "where": []
  },
  "cfn_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "contains",
     "value": "cloudformation.amazonaws.com"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "bucket_kms_encrypted",
   "kind": "attr",
   "select": "bucket",
   "cond": {
    "path": [
     "BucketEncryption",
     "ServerSideEncryptionConfiguration",
     "*",
     "ServerSideEncryptionByDefault",
     "SSEAlgorithm"
    ],
    "op": "in",
    "value": [
     "aws:kms",
     "aws:kms:dsse"
    ]
   },
   "tier": "core",
   "quote": "an encrypted S3 bucket for file assets"
  },
  {
   "id": "bucket_versioning",
   "kind": "attr",
   "select": "bucket",
   "cond": {
    "path": [
     "VersioningConfiguration",
     "Status"
    ],
    "op": "eq",
    "value": "Enabled"
   },
   "tier": "core",
   "quote": "with versioning"
  },
  {
   "id": "bucket_https_only",
   "kind": "ref",
   "from": {
    "types": [
     "AWS::S3::BucketPolicy"
    ],
    "where": [
     {
      "path": [
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "(?i)aws:SecureTransport"
     }
    ]
   },
   "to": "bucket",
   "tier": "core",
   "quote": "HTTPS-only access"
  },
  {
   "id": "ecr_immutable",
   "kind": "attr",
   "select": "ecr",
   "cond": {
    "path": [
     "ImageTagMutability"
    ],
    "op": "eq",
    "value": "IMMUTABLE"
   },
   "tier": "core",
   "quote": "an immutable ECR repository"
  },
  {
   "id": "ecr_scan_on_push",
   "kind": "attr",
   "select": "ecr",
   "cond": {
    "path": [
     "ImageScanningConfiguration",
     "ScanOnPush"
    ],
    "op": "truthy"
   },
   "tier": "core",
   "quote": "with image scanning for container assets"
  },
  {
   "id": "kms_key",
   "kind": "exists",
   "select": "key",
   "tier": "core",
   "quote": "a KMS key for bucket encryption"
  },
  {
   "id": "bucket_uses_key",
   "kind": "ref",
   "from": "bucket",
   "to": "key",
   "tier": "detail",
   "quote": "a KMS key for bucket encryption"
  },
  {
   "id": "kms_alias",
   "kind": "ref",
   "from": {
    "types": [
     "AWS::KMS::Alias"
    ],
    "where": []
   },
   "to": "key",
   "tier": "detail",
   "quote": "with a customizable alias"
  },
  {
   "id": "iam_roles",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::IAM::Role"
    ],
    "where": []
   },
   "min": 5,
   "tier": "core",
   "quote": "IAM roles for file publishing, image publishing, account lookup, deployment actions, and CloudFormation execution",
   "justify": "the prompt enumerates five roles (file publishing, image publishing, lookup, deployment, CFN execution)"
  },
  {
   "id": "cfn_execution_role",
   "kind": "any_of",
   "tier": "core",
   "quote": "CloudFormation execution",
   "checks": [
    {
     "kind": "exists",
     "select": "cfn_role"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Role",
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [],
        "op": "regex",
        "value": "(?i)iam:PassRole"
       }
      ]
     },
     "to": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": []
     }
    }
   ]
  },
  {
   "id": "cfn_execution_managed_policies",
   "kind": "any_of",
   "tier": "detail",
   "quote": "managed policy ARNs",
   "checks": [
    {
     "kind": "attr",
     "select": "cfn_role",
     "cond": {
      "path": [
       "ManagedPolicyArns"
      ],
      "op": "present"
     }
    },
    {
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
        "value": "(?i)(execution|cfn|cloudformation).*polic"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "file_publishing_permissions",
   "kind": "any_of",
   "tier": "detail",
   "quote": "file publishing",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*",
       "Action"
      ],
      "op": "glob_covers",
      "value": "s3:PutObject"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "s3:PutObject"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*",
       "Action"
      ],
      "op": "glob_covers",
      "value": "s3:PutObject"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "s3:PutObject"
     }
    }
   ],
   "justify": "publishing file assets to the S3 asset bucket implies s3:PutObject"
  },
  {
   "id": "image_publishing_permissions",
   "kind": "any_of",
   "tier": "detail",
   "quote": "image publishing",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*",
       "Action"
      ],
      "op": "glob_covers",
      "value": "ecr:PutImage"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "ecr:PutImage"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*",
       "Action"
      ],
      "op": "glob_covers",
      "value": "ecr:PutImage"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "ecr:PutImage"
     }
    }
   ]
  },
  {
   "id": "deployment_action_permissions",
   "kind": "any_of",
   "tier": "detail",
   "quote": "deployment actions",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Policies"
      ],
      "op": "regex",
      "value": "(?i)cloudformation:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "(?i)cloudformation:"
     }
    }
   ]
  },
  {
   "id": "trusted_accounts_parameter",
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
      "value": "(?i)trust"
     }
    ]
   },
   "tier": "detail",
   "quote": "configurable trusted accounts"
  },
  {
   "id": "execution_policies_parameter",
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
      "value": "(?i)polic"
     }
    ]
   },
   "tier": "detail",
   "quote": "managed policy ARNs"
  },
  {
   "id": "bootstrap_version_parameter",
   "kind": "attr",
   "select": {
    "types": [
     "AWS::SSM::Parameter"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "Name"
    ],
    "op": "regex",
    "value": "(?i)version"
   },
   "tier": "core",
   "quote": "an SSM parameter to track the bootstrap version"
  },
  {
   "id": "custom_bucket_name_parameter",
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
      "value": "(?i)bucket.*name"
     }
    ]
   },
   "tier": "detail",
   "quote": "support for custom asset bucket names"
  },
  {
   "id": "existing_kms_key_parameter",
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
      "value": "(?i)kms|key_?(id|arn)|existing"
     }
    ]
   },
   "tier": "detail",
   "quote": "using an existing KMS key"
  },
  {
   "id": "qualifier_parameter",
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
      "value": "(?i)qualifier|prefix"
     }
    ]
   },
   "tier": "detail",
   "quote": "a short qualifier string to uniquely identify the stack components"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
