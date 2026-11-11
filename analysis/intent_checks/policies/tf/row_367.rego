package intent.tf.row_367

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "user": {
   "types": [
    "aws_iam_user"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "gitops-bridge-gitops"
    }
   ]
  },
  "policy": {
   "types": [
    "aws_iam_policy"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "gitops-bridge-gitops"
    }
   ]
  },
  "tls": {
   "types": [
    "tls_private_key"
   ],
   "where": []
  },
  "sshkey": {
   "types": [
    "aws_iam_user_ssh_key"
   ],
   "where": []
  },
  "secret": {
   "types": [
    "aws_secretsmanager_secret"
   ],
   "where": []
  },
  "r1": {
   "types": [
    "aws_codecommit_repository"
   ],
   "where": [
    {
     "path": [
      "repository_name"
     ],
     "op": "eq",
     "value": "gitops-apps"
    }
   ]
  },
  "r2": {
   "types": [
    "aws_codecommit_repository"
   ],
   "where": [
    {
     "path": [
      "repository_name"
     ],
     "op": "eq",
     "value": "gitops-platform"
    }
   ]
  },
  "r3": {
   "types": [
    "aws_codecommit_repository"
   ],
   "where": [
    {
     "path": [
      "repository_name"
     ],
     "op": "eq",
     "value": "gitops-addons"
    }
   ]
  },
  "pol_any": {
   "types": [
    "data.aws_iam_policy_document",
    "aws_iam_policy",
    "aws_iam_user_policy"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "repo_apps",
   "kind": "exists",
   "tier": "core",
   "select": "r1",
   "quote": "three AWS CodeCommit repositories for an Argo CD GitOps bridge, named \"gitops-apps\", \"gitops-platform\", and \"gitops-addons\""
  },
  {
   "id": "repo_platform",
   "kind": "exists",
   "tier": "core",
   "select": "r2",
   "quote": "three AWS CodeCommit repositories for an Argo CD GitOps bridge, named \"gitops-apps\", \"gitops-platform\", and \"gitops-addons\""
  },
  {
   "id": "repo_addons",
   "kind": "exists",
   "tier": "core",
   "select": "r3",
   "quote": "three AWS CodeCommit repositories for an Argo CD GitOps bridge, named \"gitops-apps\", \"gitops-platform\", and \"gitops-addons\""
  },
  {
   "id": "iam_user",
   "kind": "exists",
   "tier": "core",
   "select": "user",
   "quote": "an IAM user named \"gitops-bridge-gitops\""
  },
  {
   "id": "rsa_key",
   "kind": "attr",
   "tier": "core",
   "select": "tls",
   "cond": {
    "path": [
     "algorithm"
    ],
    "op": "eq",
    "value": "RSA"
   },
   "quote": "newly generated 4096-bit RSA key pair"
  },
  {
   "id": "rsa_4096",
   "kind": "attr",
   "tier": "core",
   "select": "tls",
   "cond": {
    "path": [
     "rsa_bits"
    ],
    "op": "eq",
    "value": 4096
   },
   "quote": "newly generated 4096-bit RSA key pair",
   "justify": "stated 4096-bit"
  },
  {
   "id": "ssh_pubkey_uploaded",
   "kind": "exists",
   "tier": "core",
   "select": "sshkey",
   "quote": "uploaded as the user's SSH public key"
  },
  {
   "id": "ssh_key_from_tls",
   "kind": "ref",
   "tier": "core",
   "from": "sshkey",
   "to": "tls",
   "quote": "newly generated 4096-bit RSA key pair uploaded as the user's SSH public key"
  },
  {
   "id": "ssh_key_for_user",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "ref",
     "from": "sshkey",
     "to": "user"
    },
    {
     "kind": "attr",
     "select": "sshkey",
     "cond": {
      "path": [
       "username"
      ],
      "op": "eq",
      "value": "gitops-bridge-gitops"
     }
    }
   ],
   "quote": "uploaded as the user's SSH public key"
  },
  {
   "id": "policy_exists",
   "kind": "exists",
   "tier": "core",
   "select": "policy",
   "quote": "a customer-managed IAM policy named \"gitops-bridge-gitops\""
  },
  {
   "id": "policy_pull_push",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "pol_any",
     "cond": {
      "path": [
       "statement",
       "*",
       "actions",
       "*"
      ],
      "op": "glob_covers",
      "value": "codecommit:GitPull"
     }
    },
    {
     "kind": "attr",
     "select": "pol_any",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)codecommit:(GitPull|Git\\*|\\*)"
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
         "aws_iam_user_policy"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)codecommit:(GitPull|Git\\*|\\*)"
     }
    }
   ],
   "quote": "Grant that user Git pull and push access",
   "justify": "Git pull maps to codecommit:GitPull"
  },
  {
   "id": "policy_push",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "pol_any",
     "cond": {
      "path": [
       "statement",
       "*",
       "actions",
       "*"
      ],
      "op": "glob_covers",
      "value": "codecommit:GitPush"
     }
    },
    {
     "kind": "attr",
     "select": "pol_any",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)codecommit:(GitPush|Git\\*|\\*)"
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
         "aws_iam_user_policy"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)codecommit:(GitPush|Git\\*|\\*)"
     }
    }
   ],
   "quote": "Grant that user Git pull and push access",
   "justify": "Git push maps to codecommit:GitPush"
  },
  {
   "id": "policy_covers_apps",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "ref",
     "from": "pol_any",
     "to": "r1"
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
        "op": "in",
        "value": [
         "data.aws_iam_policy_document",
         "aws_iam_policy",
         "aws_iam_user_policy"
        ]
       }
      ]
     },
     "to": "r1"
    }
   ],
   "quote": "to only these three repositories"
  },
  {
   "id": "policy_covers_platform",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "ref",
     "from": "pol_any",
     "to": "r2"
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
        "op": "in",
        "value": [
         "data.aws_iam_policy_document",
         "aws_iam_policy",
         "aws_iam_user_policy"
        ]
       }
      ]
     },
     "to": "r2"
    }
   ],
   "quote": "to only these three repositories"
  },
  {
   "id": "policy_covers_addons",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "ref",
     "from": "pol_any",
     "to": "r3"
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
        "op": "in",
        "value": [
         "data.aws_iam_policy_document",
         "aws_iam_policy",
         "aws_iam_user_policy"
        ]
       }
      ]
     },
     "to": "r3"
    }
   ],
   "quote": "to only these three repositories"
  },
  {
   "id": "policy_attached_user",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_user_policy_attachment",
       "aws_iam_policy_attachment"
      ],
      "where": []
     },
     "to": "policy"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_user_policy"
      ],
      "where": []
     },
     "to": "user"
    },
    {
     "kind": "ref",
     "from": "user",
     "to": "policy",
     "bidirectional": true
    }
   ],
   "quote": "Grant that user Git pull and push access to only these three repositories through a customer-managed IAM policy"
  },
  {
   "id": "attachment_to_user",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_user_policy_attachment",
       "aws_iam_policy_attachment",
       "aws_iam_user_policy"
      ],
      "where": []
     },
     "to": "user"
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_user_policy_attachment",
       "aws_iam_policy_attachment",
       "aws_iam_user_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "user"
      ],
      "op": "eq",
      "value": "gitops-bridge-gitops"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "users",
       "*"
      ],
      "op": "eq",
      "value": "gitops-bridge-gitops"
     }
    }
   ],
   "quote": "Grant that user Git pull and push access"
  },
  {
   "id": "secret_exists",
   "kind": "exists",
   "tier": "core",
   "select": "secret",
   "quote": "store the generated private key in a Secrets Manager secret"
  },
  {
   "id": "secret_name_prefix",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "secret",
     "cond": {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "^codecommit-key-"
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
        "value": "aws_secretsmanager_secret"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "name"
      ],
      "op": "regex",
      "value": "^codecommit-key-"
     }
    }
   ],
   "quote": "a Secrets Manager secret whose name starts with \"codecommit-key-\""
  },
  {
   "id": "secret_holds_private_key",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_secretsmanager_secret_version"
      ],
      "where": []
     },
     "to": "tls"
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
        "value": "aws_secretsmanager_secret_version"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "secret_string"
      ],
      "op": "regex",
      "value": "private_key"
     }
    }
   ],
   "quote": "store the generated private key in a Secrets Manager secret"
  },
  {
   "id": "secret_version_to_secret",
   "kind": "ref",
   "tier": "detail",
   "from": {
    "types": [
     "aws_secretsmanager_secret_version"
    ],
    "where": []
   },
   "to": "secret",
   "quote": "store the generated private key in a Secrets Manager secret"
  },
  {
   "id": "random_suffix_5",
   "kind": "any_of",
   "tier": "core",
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
      "value": 5
     }
    }
   ],
   "quote": "followed by a random five-character suffix",
   "justify": "five-character suffix means length 5"
  },
  {
   "id": "secret_uses_random",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "ref",
     "from": "secret",
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
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_secretsmanager_secret"
       }
      ]
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
   "quote": "followed by a random five-character suffix"
  },
  {
   "id": "local_pem_file",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "local_file",
       "local_sensitive_file"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "filename"
      ],
      "op": "regex",
      "value": "gitops_ssh\\.pem$"
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
         "local_file",
         "local_sensitive_file"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "filename"
      ],
      "op": "contains",
      "value": "gitops_ssh"
     }
    }
   ],
   "quote": "write the private key locally as \"gitops_ssh.pem\""
  },
  {
   "id": "local_pem_content_tls",
   "kind": "ref",
   "tier": "detail",
   "from": {
    "types": [
     "local_file",
     "local_sensitive_file"
    ],
    "where": []
   },
   "to": "tls",
   "quote": "write the private key locally"
  },
  {
   "id": "pem_in_ssh_dir",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "local_file",
       "local_sensitive_file"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "filename"
      ],
      "op": "regex",
      "value": "(?i)\\.ssh/gitops_ssh\\.pem$"
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
         "local_file",
         "local_sensitive_file"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "filename"
      ],
      "op": "regex",
      "value": "(?i)\\.ssh/gitops_ssh\\.pem"
     }
    }
   ],
   "quote": "in the user's SSH directory",
   "justify": "the user's SSH directory is ~/.ssh, so the key file is ~/.ssh/gitops_ssh.pem"
  },
  {
   "id": "ssh_config_entry",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "local_file",
       "local_sensitive_file"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "filename"
      ],
      "op": "regex",
      "value": "(?i)\\.ssh/config$"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "null_resource",
       "terraform_data"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)\\.ssh/config"
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
         "local_file",
         "local_sensitive_file",
         "null_resource",
         "terraform_data"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)(\\.ssh/config|ssh_config|identityfile)"
     }
    }
   ],
   "quote": "add a matching SSH config entry for the CodeCommit Git endpoints",
   "justify": "an SSH config entry is written to ~/.ssh/config (Host/IdentityFile directives)"
  },
  {
   "id": "ssh_config_codecommit_host",
   "kind": "any_of",
   "tier": "detail",
   "quote": "SSH config entry for the CodeCommit Git endpoints",
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
        "op": "in",
        "value": [
         "local_file",
         "local_sensitive_file",
         "null_resource",
         "terraform_data"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)host\\s+git-codecommit"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__output__"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)(ssh|host)"
       }
      ]
     },
     "cond": {
      "path": [
       "value"
      ],
      "op": "regex",
      "value": "(?i)git-codecommit"
     }
    }
   ],
   "justify": "the CodeCommit Git SSH endpoints are git-codecommit.<region>.amazonaws.com"
  },
  {
   "id": "x_secret_policy_ssh_enc",
   "kind": "attr",
   "tier": "extra",
   "select": "sshkey",
   "cond": {
    "path": [
     "encoding"
    ],
    "op": "eq",
    "value": "SSH"
   }
  },
  {
   "id": "x_pem_perm",
   "kind": "any_of",
   "tier": "extra",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "local_file"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "file_permission"
      ],
      "op": "eq",
      "value": "0600"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "local_sensitive_file"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "file_permission"
      ],
      "op": "eq",
      "value": "0600"
     }
    }
   ]
  },
  {
   "id": "x_secret_version_exists",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_secretsmanager_secret_version"
    ],
    "where": []
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
