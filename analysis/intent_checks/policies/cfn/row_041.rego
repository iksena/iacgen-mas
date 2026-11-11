package intent.cfn.row_041

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "pol": {
   "types": [
    "AWS::IAM::ManagedPolicy"
   ],
   "where": []
  },
  "pols": {
   "types": [
    "AWS::IAM::ManagedPolicy",
    "AWS::IAM::Policy"
   ],
   "where": []
  },
  "user": {
   "types": [
    "AWS::IAM::User"
   ],
   "where": []
  },
  "key": {
   "types": [
    "AWS::IAM::AccessKey"
   ],
   "where": []
  },
  "secret": {
   "types": [
    "AWS::SecretsManager::Secret"
   ],
   "where": []
  },
  "params": {
   "types": [
    "__parameter__"
   ],
   "where": []
  },
  "pols_ecr": {
   "types": [
    "AWS::IAM::Policy",
    "AWS::IAM::ManagedPolicy"
   ],
   "where": [
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "contains",
     "value": "ecr:"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "policy",
   "tier": "core",
   "quote": "an IAM managed policy",
   "kind": "exists",
   "select": "pol"
  },
  {
   "id": "repo_actions",
   "tier": "core",
   "quote": "allows repository-level ECR operations across all repositories in the account",
   "kind": "attr",
   "select": "pols",
   "cond": {
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
       "Resource",
       "*"
      ],
      "op": "regex",
      "value": ":repository/\\*$"
     },
     {
      "path": [
       "Action",
       "*"
      ],
      "op": "regex",
      "value": "(?i)^ecr:"
     }
    ]
   }
  },
  {
   "id": "registry_actions",
   "tier": "core",
   "quote": "alongside general registry-level ECR actions across all resources",
   "kind": "attr",
   "select": "pols",
   "cond": {
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
       "Resource",
       "*"
      ],
      "op": "eq",
      "value": "*"
     },
     {
      "path": [
       "Action",
       "*"
      ],
      "op": "regex",
      "value": "(?i)^ecr:"
     }
    ]
   }
  },
  {
   "id": "user",
   "tier": "core",
   "quote": "an IAM user",
   "kind": "exists",
   "select": "user"
  },
  {
   "id": "policy_attached",
   "tier": "core",
   "quote": "attach this policy to a new IAM service user",
   "kind": "ref",
   "from": "pols_ecr",
   "to": "user",
   "bidirectional": true
  },
  {
   "id": "access_key",
   "tier": "core",
   "quote": "access keys",
   "kind": "exists",
   "select": "key"
  },
  {
   "id": "key_inactive",
   "tier": "core",
   "quote": "generate an inactive IAM access key for the user",
   "kind": "attr",
   "select": "key",
   "cond": {
    "path": [
     "Status"
    ],
    "op": "eq",
    "value": "Inactive"
   }
  },
  {
   "id": "key_user",
   "tier": "detail",
   "quote": "generate an inactive IAM access key for the user",
   "kind": "ref",
   "from": "key",
   "to": "user"
  },
  {
   "id": "secret",
   "tier": "core",
   "quote": "a Secrets Manager secret named \"nextflow/ecr_service_acct\"",
   "kind": "attr",
   "select": "secret",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "eq",
    "value": "nextflow/ecr_service_acct"
   }
  },
  {
   "id": "secret_has_key",
   "tier": "core",
   "quote": "store the resulting access key ID and secret access key",
   "kind": "all_of",
   "checks": [
    {
     "kind": "ref",
     "from": "secret",
     "to": "key"
    },
    {
     "kind": "attr",
     "select": "secret",
     "cond": {
      "path": [
       "SecretString"
      ],
      "op": "contains",
      "value": "SecretAccessKey"
     }
    }
   ],
   "justify": "the secret access key is read from the access key's SecretAccessKey attribute"
  },
  {
   "id": "json_keys",
   "tier": "detail",
   "quote": "formatted as a JSON string with \"username\" and \"password\" keys",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": "secret",
     "cond": {
      "path": [
       "SecretString"
      ],
      "op": "contains",
      "value": "username"
     }
    },
    {
     "kind": "attr",
     "select": "secret",
     "cond": {
      "path": [
       "SecretString"
      ],
      "op": "contains",
      "value": "password"
     }
    }
   ]
  },
  {
   "id": "kms_param_default",
   "tier": "core",
   "quote": "an optional KMS key alias parameter defaulting to \"alias/aws/secretsmanager\"",
   "kind": "attr",
   "select": "params",
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": "alias/aws/secretsmanager"
   }
  },
  {
   "id": "secret_kms",
   "tier": "core",
   "quote": "encrypted with the specified KMS key alias",
   "kind": "attr",
   "select": "secret",
   "cond": {
    "path": [
     "KmsKeyId"
    ],
    "op": "regex",
    "value": "alias/aws/secretsmanager$"
   },
   "justify": "the parameter defaults to this alias, so the resolved key id is that alias"
  },
  {
   "id": "put_image",
   "tier": "extra",
   "kind": "attr",
   "select": "pols",
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
  },
  {
   "id": "auth_token",
   "tier": "extra",
   "kind": "attr",
   "select": "pols",
   "cond": {
    "path": [
     "PolicyDocument",
     "Statement",
     "*",
     "Action",
     "*"
    ],
    "op": "glob_covers",
    "value": "ecr:GetAuthorizationToken"
   }
  },
  {
   "id": "create_repo",
   "tier": "extra",
   "kind": "attr",
   "select": "pols",
   "cond": {
    "path": [
     "PolicyDocument",
     "Statement",
     "*",
     "Action",
     "*"
    ],
    "op": "glob_covers",
    "value": "ecr:CreateRepository"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
