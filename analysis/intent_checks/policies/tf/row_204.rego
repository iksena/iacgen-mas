package intent.tf.row_204

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "p_cluster_tag",
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
      "value": "cluster_tag"
     }
    ]
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": "default"
   },
   "quote": "cluster_tag defaulting to \"default\""
  },
  {
   "id": "p_rotation",
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
      "value": "enable_key_rotation"
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
   "quote": "enable_key_rotation defaulting to false"
  },
  {
   "id": "p_roles",
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
      "value": "machine_roles"
     }
    ]
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "len_eq",
    "value": 0
   },
   "quote": "a machine_roles map (mapping role names to sets of policy identifier strings) defaulting to an empty map"
  },
  {
   "id": "kms",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_kms_key"
    ],
    "where": []
   },
   "quote": "Provision a KMS key for Vault unsealing"
  },
  {
   "id": "kms_desc",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_kms_key"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "description"
    ],
    "op": "eq",
    "value": "resinstack:vault:seal:default"
   },
   "quote": "description \"resinstack:vault:seal:{cluster_tag}\"",
   "justify": "cluster_tag defaults to \"default\""
  },
  {
   "id": "kms_rotation",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_kms_key"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "enable_key_rotation"
    ],
    "op": "falsy"
   },
   "quote": "annual key rotation set to enable_key_rotation"
  },
  {
   "id": "kms_tag",
   "tier": "detail",
   "kind": "attr",
   "select": {
    "types": [
     "aws_kms_key"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "tags",
     "resinstack:cluster"
    ],
    "op": "eq",
    "value": "default"
   },
   "quote": "a tag \"resinstack:cluster\" matching cluster_tag"
  },
  {
   "id": "secrets_count",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_secretsmanager_secret"
    ],
    "where": []
   },
   "min": 7,
   "quote": "Create seven Secrets Manager secrets"
  },
  {
   "id": "secret_names",
   "tier": "core",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_secretsmanager_secret"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "resinstack-consul-agent-token-default"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_secretsmanager_secret"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "resinstack-consul-gossip-key-default"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_secretsmanager_secret"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "resinstack-nomad-client-consul-token-default"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_secretsmanager_secret"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "resinstack-nomad-gossip-key-default"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_secretsmanager_secret"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "resinstack-nomad-server-consul-token-default"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_secretsmanager_secret"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "resinstack-nomad-vault-token-default"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_secretsmanager_secret"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "resinstack-vault-consul-token-default"
     }
    }
   ],
   "quote": "named \"resinstack-{name}-{cluster_tag}\" for consul-agent-token, consul-gossip-key, nomad-client-consul-token, nomad-gossip-key, nomad-server-consul-token, nomad-vault-token, and vault-consul-token",
   "justify": "cluster_tag defaults to \"default\""
  },
  {
   "id": "secret_tags",
   "tier": "detail",
   "kind": "attr",
   "select": {
    "types": [
     "aws_secretsmanager_secret"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "tags",
     "*"
    ],
    "op": "eq",
    "value": "default"
   },
   "quantifier": "all",
   "quote": "secrets tagged with cluster_tag"
  },
  {
   "id": "unseal_encrypt",
   "tier": "core",
   "kind": "any_of",
   "checks": [
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
       "*",
       "actions",
       "*"
      ],
      "op": "glob_covers",
      "value": "kms:Encrypt"
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
      "value": "(?i)kms:encrypt|kms:\\*"
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
      "value": "(?i)kms:encrypt|kms:\\*"
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
       "*",
       "actions",
       "*"
      ],
      "op": "glob_covers",
      "value": "kms:Encrypt"
     }
    }
   ],
   "quote": "IAM policies for unsealing Vault via KMS (permitting \"kms:Encrypt\", \"kms:Decrypt\", \"kms:DescribeKey\")"
  },
  {
   "id": "unseal_decrypt",
   "tier": "core",
   "kind": "any_of",
   "checks": [
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
       "*",
       "actions",
       "*"
      ],
      "op": "glob_covers",
      "value": "kms:Decrypt"
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
      "value": "(?i)kms:decrypt|kms:\\*"
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
      "value": "(?i)kms:decrypt|kms:\\*"
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
       "*",
       "actions",
       "*"
      ],
      "op": "glob_covers",
      "value": "kms:Decrypt"
     }
    }
   ],
   "quote": "IAM policies for unsealing Vault via KMS (permitting \"kms:Encrypt\", \"kms:Decrypt\", \"kms:DescribeKey\")"
  },
  {
   "id": "unseal_describekey",
   "tier": "core",
   "kind": "any_of",
   "checks": [
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
       "*",
       "actions",
       "*"
      ],
      "op": "glob_covers",
      "value": "kms:DescribeKey"
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
      "value": "(?i)kms:describekey|kms:\\*"
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
      "value": "(?i)kms:describekey|kms:\\*"
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
       "*",
       "actions",
       "*"
      ],
      "op": "glob_covers",
      "value": "kms:DescribeKey"
     }
    }
   ],
   "quote": "IAM policies for unsealing Vault via KMS (permitting \"kms:Encrypt\", \"kms:Decrypt\", \"kms:DescribeKey\")"
  },
  {
   "id": "unseal_on_key",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
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
        "value": "kms:Decrypt"
       }
      ]
     },
     "to": {
      "types": [
       "aws_kms_key"
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
        "value": "aws_iam_policy"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "(?i)kms:(decrypt|\\*)"
       }
      ]
     },
     "to": {
      "types": [
       "aws_kms_key"
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties",
         "statement",
         "*",
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "kms:Decrypt"
       }
      ]
     },
     "to": {
      "types": [
       "aws_kms_key"
      ],
      "where": []
     }
    }
   ],
   "quote": "unsealing Vault via KMS"
  },
  {
   "id": "readtags_policy",
   "tier": "core",
   "kind": "any_of",
   "checks": [
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
       "name"
      ],
      "op": "eq",
      "value": "ResinStackReadTags"
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
       "name"
      ],
      "op": "regex",
      "value": "^ResinStackReadTags$"
     }
    }
   ],
   "quote": "describing EC2 instances (\"ResinStackReadTags\", permitting \"ec2:DescribeInstances\")"
  },
  {
   "id": "readtags_action",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
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
        "value": "^ResinStackReadTags"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ec2:(describeinstances|describe\\*|\\*)"
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
        "value": "^ResinStackReadTags"
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
        "value": "ec2:DescribeInstances"
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
        "value": "aws_iam_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "regex",
        "value": "^ResinStackReadTags"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ec2:(describeinstances|describe\\*|\\*)"
     }
    }
   ],
   "quote": "permitting \"ec2:DescribeInstances\""
  },
  {
   "id": "keys_client",
   "tier": "core",
   "kind": "any_of",
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties",
         "statement",
         "*",
         "actions",
         "*"
        ],
        "op": "regex",
        "value": "(?i)secretsmanager:(getsecretvalue|\\*|get\\*)"
       },
       {
        "path": [
         "properties",
         "statement",
         "*",
         "resources",
         "*"
        ],
        "op": "contains",
        "value": "consul-agent-token"
       },
       {
        "path": [
         "properties",
         "statement",
         "*",
         "resources",
         "*"
        ],
        "op": "contains",
        "value": "consul-gossip-key"
       },
       {
        "path": [
         "properties",
         "statement",
         "*",
         "resources",
         "*"
        ],
        "op": "contains",
        "value": "nomad-client-consul-token"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "statement",
       "*",
       "resources",
       "*"
      ],
      "op": "regex",
      "value": "(consul\\-agent\\-token|consul\\-gossip\\-key|nomad\\-client\\-consul\\-token)",
      "every": true
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
      "op": "match",
      "value": [
       {
        "path": [],
        "op": "regex",
        "value": "(?i)secretsmanager:(getsecretvalue|\\*)"
       },
       {
        "path": [],
        "op": "contains",
        "value": "consul-agent-token"
       },
       {
        "path": [],
        "op": "contains",
        "value": "consul-gossip-key"
       },
       {
        "path": [],
        "op": "contains",
        "value": "nomad-client-consul-token"
       }
      ]
     }
    }
   ],
   "quote": "retrieving secret values from Secrets Manager tailored for clients (the consul-agent-token, consul-gossip-key, and nomad-client-consul-token secrets)",
   "justify": "the prompt lists the exact secrets each tailored policy covers"
  },
  {
   "id": "keys_nomad",
   "tier": "core",
   "kind": "any_of",
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties",
         "statement",
         "*",
         "actions",
         "*"
        ],
        "op": "regex",
        "value": "(?i)secretsmanager:(getsecretvalue|\\*|get\\*)"
       },
       {
        "path": [
         "properties",
         "statement",
         "*",
         "resources",
         "*"
        ],
        "op": "contains",
        "value": "consul-agent-token"
       },
       {
        "path": [
         "properties",
         "statement",
         "*",
         "resources",
         "*"
        ],
        "op": "contains",
        "value": "consul-gossip-key"
       },
       {
        "path": [
         "properties",
         "statement",
         "*",
         "resources",
         "*"
        ],
        "op": "contains",
        "value": "nomad-gossip-key"
       },
       {
        "path": [
         "properties",
         "statement",
         "*",
         "resources",
         "*"
        ],
        "op": "contains",
        "value": "nomad-server-consul-token"
       },
       {
        "path": [
         "properties",
         "statement",
         "*",
         "resources",
         "*"
        ],
        "op": "contains",
        "value": "nomad-vault-token"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "statement",
       "*",
       "resources",
       "*"
      ],
      "op": "regex",
      "value": "(consul\\-agent\\-token|consul\\-gossip\\-key|nomad\\-gossip\\-key|nomad\\-server\\-consul\\-token|nomad\\-vault\\-token)",
      "every": true
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
      "op": "match",
      "value": [
       {
        "path": [],
        "op": "regex",
        "value": "(?i)secretsmanager:(getsecretvalue|\\*)"
       },
       {
        "path": [],
        "op": "contains",
        "value": "consul-agent-token"
       },
       {
        "path": [],
        "op": "contains",
        "value": "consul-gossip-key"
       },
       {
        "path": [],
        "op": "contains",
        "value": "nomad-gossip-key"
       },
       {
        "path": [],
        "op": "contains",
        "value": "nomad-server-consul-token"
       },
       {
        "path": [],
        "op": "contains",
        "value": "nomad-vault-token"
       }
      ]
     }
    }
   ],
   "quote": "Nomad servers (consul-agent-token, consul-gossip-key, nomad-gossip-key, nomad-server-consul-token, and nomad-vault-token)",
   "justify": "the prompt lists the exact secrets each tailored policy covers"
  },
  {
   "id": "keys_consul",
   "tier": "core",
   "kind": "any_of",
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties",
         "statement",
         "*",
         "actions",
         "*"
        ],
        "op": "regex",
        "value": "(?i)secretsmanager:(getsecretvalue|\\*|get\\*)"
       },
       {
        "path": [
         "properties",
         "statement",
         "*",
         "resources",
         "*"
        ],
        "op": "contains",
        "value": "consul-gossip-key"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "statement",
       "*",
       "resources",
       "*"
      ],
      "op": "regex",
      "value": "(consul\\-gossip\\-key)",
      "every": true
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
      "value": "(?i)secretsmanager:(getsecretvalue|\\*)[\\s\\S]{0,400}resources?[\"']?\\s*[:=]\\s*(\\[\\s*[\"']?(\\$\\{[^}]*consul-gossip-key[^}]*\\}|arn:[^\"'\\],]*consul-gossip-key[^\"'\\],]*)[\"']?\\s*\\]|[\"'](\\$\\{[^}]*consul-gossip-key[^}]*\\}|arn:[^\"'\\],]*consul-gossip-key[^\"'\\],]*)[\"']\\s*[,}])|resources?[\"']?\\s*[:=]\\s*(\\[\\s*[\"']?(\\$\\{[^}]*consul-gossip-key[^}]*\\}|arn:[^\"'\\],]*consul-gossip-key[^\"'\\],]*)[\"']?\\s*\\]|[\"'](\\$\\{[^}]*consul-gossip-key[^}]*\\}|arn:[^\"'\\],]*consul-gossip-key[^\"'\\],]*)[\"']\\s*[,}])[\\s\\S]{0,400}secretsmanager:(getsecretvalue|\\*)"
     }
    }
   ],
   "quote": "Consul servers (consul-gossip-key)",
   "justify": "the prompt lists the exact secrets each tailored policy covers"
  },
  {
   "id": "keys_vault",
   "tier": "core",
   "kind": "any_of",
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties",
         "statement",
         "*",
         "actions",
         "*"
        ],
        "op": "regex",
        "value": "(?i)secretsmanager:(getsecretvalue|\\*|get\\*)"
       },
       {
        "path": [
         "properties",
         "statement",
         "*",
         "resources",
         "*"
        ],
        "op": "contains",
        "value": "consul-gossip-key"
       },
       {
        "path": [
         "properties",
         "statement",
         "*",
         "resources",
         "*"
        ],
        "op": "contains",
        "value": "vault-consul-token"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "statement",
       "*",
       "resources",
       "*"
      ],
      "op": "regex",
      "value": "(consul\\-gossip\\-key|vault\\-consul\\-token)",
      "every": true
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
      "op": "match",
      "value": [
       {
        "path": [],
        "op": "regex",
        "value": "(?i)secretsmanager:(getsecretvalue|\\*)"
       },
       {
        "path": [],
        "op": "contains",
        "value": "consul-gossip-key"
       },
       {
        "path": [],
        "op": "contains",
        "value": "vault-consul-token"
       }
      ]
     }
    }
   ],
   "quote": "Vault servers (consul-gossip-key and vault-consul-token)",
   "justify": "the prompt lists the exact secrets each tailored policy covers"
  },
  {
   "id": "policies_count",
   "tier": "detail",
   "kind": "exists",
   "select": {
    "types": [
     "aws_iam_policy"
    ],
    "where": []
   },
   "min": 6,
   "quote": "Define IAM policies for unsealing Vault via KMS",
   "justify": "unseal, read-tags and four secret-access policies"
  },
  {
   "id": "role",
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
      "value": "aws_iam_role"
     }
    ]
   },
   "quote": "Dynamically iterate over machine_roles to create EC2 assume roles"
  },
  {
   "id": "role_iterates",
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
      "value": "aws_iam_role"
     }
    ]
   },
   "cond": {
    "path": [
     "gate"
    ],
    "op": "regex",
    "value": "machine_roles"
   },
   "quote": "Dynamically iterate over machine_roles"
  },
  {
   "id": "role_ec2",
   "tier": "core",
   "kind": "any_of",
   "checks": [
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
        "value": "aws_iam_role"
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties",
         "statement",
         "*",
         "principals",
         "*",
         "identifiers",
         "*"
        ],
        "op": "eq",
        "value": "ec2.amazonaws.com"
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
        "value": "aws_iam_role"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "ec2.amazonaws.com"
     }
    }
   ],
   "quote": "EC2 assume roles"
  },
  {
   "id": "role_session",
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
      "value": "aws_iam_role"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "max_session_duration"
    ],
    "op": "regex",
    "value": "(?i)43200|3600 ?\\* ?12|12 ?\\* ?3600|12 ?\\* ?60 ?\\* ?60|60 ?\\* ?60 ?\\* ?12"
   },
   "quote": "a 12-hour maximum session duration",
   "justify": "12 hours is 43200 seconds"
  },
  {
   "id": "profile",
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
      "value": "aws_iam_instance_profile"
     },
     {
      "path": [
       "gate"
      ],
      "op": "regex",
      "value": "machine_roles"
     }
    ]
   },
   "quote": "corresponding instance profiles"
  },
  {
   "id": "profile_name",
   "tier": "detail",
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
      "value": "aws_iam_instance_profile"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "name"
    ],
    "op": "regex",
    "value": "^resinstack-\\$\\{[^}]+\\}-\\$\\{[^}]*cluster_tag[^}]*\\}$"
   },
   "quote": "instance profiles named \"resinstack-{role name}-{cluster_tag}\""
  },
  {
   "id": "profile_role",
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
      "value": "aws_iam_instance_profile"
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
      "value": "aws_iam_role"
     }
    ]
   },
   "quote": "corresponding instance profiles"
  },
  {
   "id": "attachments",
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
      "value": "aws_iam_role_policy_attachment"
     }
    ]
   },
   "quote": "attaching the appropriate IAM policies when their identifiers (\"read-tags\", \"vault-kms\", \"nomad-keys\", \"consul-keys\", \"vault-keys\", \"client-keys\") are present in the role's policy set"
  },
  {
   "id": "attachments_gated",
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
      "value": "aws_iam_role_policy_attachment"
     }
    ]
   },
   "cond": {
    "path": [
     "gated"
    ],
    "op": "truthy"
   },
   "quote": "when their identifiers (\"read-tags\", \"vault-kms\", \"nomad-keys\", \"consul-keys\", \"vault-keys\", \"client-keys\") are present in the role's policy set",
   "quantifier": "all"
  },
  {
   "id": "attach_role",
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
      "value": "aws_iam_role_policy_attachment"
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
      "value": "aws_iam_role"
     }
    ]
   },
   "quote": "attaching the appropriate IAM policies"
  },
  {
   "id": "out_kms",
   "tier": "detail",
   "kind": "ref",
   "from": {
    "types": [
     "__output__"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_kms_key"
    ],
    "where": []
   },
   "quote": "Output the Vault KMS key ID"
  },
  {
   "id": "out_secrets",
   "tier": "detail",
   "kind": "ref",
   "from": {
    "types": [
     "__output__"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_secretsmanager_secret"
    ],
    "where": []
   },
   "quote": "a map of secret names from Secrets Manager"
  },
  {
   "id": "out_roles",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "__output__"
      ],
      "where": []
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
        "value": "aws_iam_role"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "__output__"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     }
    }
   ],
   "quote": "maps of the generated machine role names"
  },
  {
   "id": "out_profiles",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "__output__"
      ],
      "where": []
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
        "value": "aws_iam_instance_profile"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "__output__"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_iam_instance_profile"
      ],
      "where": []
     }
    }
   ],
   "quote": "instance profile names"
  },
  {
   "id": "x_role_tags",
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
      "op": "eq",
      "value": "aws_iam_role"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "tags"
    ],
    "op": "present"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
