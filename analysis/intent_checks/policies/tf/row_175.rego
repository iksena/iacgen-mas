package intent.tf.row_175

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "efs": {
   "types": [
    "aws_efs_file_system"
   ],
   "where": []
  },
  "srv": {
   "types": [
    "aws_transfer_server"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "efs_exists",
   "kind": "exists",
   "tier": "core",
   "quote": "provision an EFS file system",
   "select": "efs"
  },
  {
   "id": "efs_encrypted",
   "kind": "attr",
   "tier": "core",
   "quote": "backed by an encrypted Amazon EFS file system",
   "select": "efs",
   "cond": {
    "path": [
     "encrypted"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "efs_perf_default",
   "kind": "attr",
   "tier": "core",
   "quote": "configurable performance mode (defaulting to \"generalPurpose\")",
   "select": "efs",
   "cond": {
    "path": [
     "performance_mode"
    ],
    "op": "eq",
    "value": "generalPurpose"
   }
  },
  {
   "id": "efs_bursting",
   "kind": "attr",
   "tier": "core",
   "quote": "bursting throughput mode",
   "select": "efs",
   "cond": {
    "path": [
     "throughput_mode"
    ],
    "op": "eq",
    "value": "bursting"
   }
  },
  {
   "id": "efs_kms_optional",
   "kind": "exists",
   "tier": "detail",
   "quote": "optional KMS customer-managed key encryption",
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
      "value": "aws_efs_file_system"
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "kms_key_id"
     }
    ]
   }
  },
  {
   "id": "efs_mount_targets",
   "kind": "exists",
   "tier": "core",
   "quote": "EFS mount targets deployed across an optional list of subnet IDs",
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
      "value": "aws_efs_mount_target"
     }
    ]
   }
  },
  {
   "id": "no_mount_targets_by_default",
   "kind": "exists",
   "tier": "detail",
   "quote": "both empty by default, in which case no mount targets are created",
   "justify": "exactly the one file system and zero planned mount targets under defaults",
   "select": {
    "types": [
     "aws_efs_file_system",
     "aws_efs_mount_target"
    ],
    "where": []
   },
   "min": 1,
   "max": 1
  },
  {
   "id": "user_access_points",
   "kind": "exists",
   "tier": "core",
   "quote": "optional user-specific access points mapped from an sftp_users object map",
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
      "value": "aws_efs_access_point"
     }
    ]
   }
  },
  {
   "id": "access_point_0755",
   "kind": "exists",
   "tier": "detail",
   "quote": "creating directories with POSIX ownership and \"0755\" permissions",
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
      "value": "aws_efs_access_point"
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "0755"
     }
    ]
   }
  },
  {
   "id": "access_point_posix",
   "kind": "exists",
   "tier": "detail",
   "quote": "POSIX ownership",
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
      "value": "aws_efs_access_point"
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)posix_user"
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)creation_info|owner_uid"
     }
    ]
   }
  },
  {
   "id": "srv_exists",
   "kind": "exists",
   "tier": "core",
   "quote": "The AWS Transfer Family SFTP server",
   "select": "srv"
  },
  {
   "id": "srv_sftp",
   "kind": "any_of",
   "tier": "core",
   "quote": "SFTP server",
   "justify": "protocols defaults to SFTP when unset",
   "checks": [
    {
     "kind": "attr",
     "select": "srv",
     "cond": {
      "path": [
       "protocols",
       "*"
      ],
      "op": "eq",
      "value": "SFTP"
     }
    },
    {
     "kind": "attr",
     "select": "srv",
     "cond": {
      "path": [
       "protocols"
      ],
      "op": "absent"
     }
    }
   ]
  },
  {
   "id": "srv_domain",
   "kind": "attr",
   "tier": "core",
   "quote": "\"EFS\" domain",
   "select": "srv",
   "cond": {
    "path": [
     "domain"
    ],
    "op": "eq",
    "value": "EFS"
   }
  },
  {
   "id": "srv_idp",
   "kind": "attr",
   "tier": "core",
   "quote": "\"SERVICE_MANAGED\" identity provider",
   "select": "srv",
   "cond": {
    "path": [
     "identity_provider_type"
    ],
    "op": "eq",
    "value": "SERVICE_MANAGED"
   }
  },
  {
   "id": "srv_policy",
   "kind": "attr",
   "tier": "core",
   "quote": "\"TransferSecurityPolicy-2023-05\" security policy",
   "select": "srv",
   "cond": {
    "path": [
     "security_policy_name"
    ],
    "op": "eq",
    "value": "TransferSecurityPolicy-2023-05"
   }
  },
  {
   "id": "srv_public_default",
   "kind": "attr",
   "tier": "core",
   "quote": "(or \"PUBLIC\" by default when omitted)",
   "select": "srv",
   "cond": {
    "path": [
     "endpoint_type"
    ],
    "op": "eq",
    "value": "PUBLIC"
   }
  },
  {
   "id": "srv_vpc_when_vpc_id",
   "kind": "any_of",
   "tier": "core",
   "quote": "\"VPC\" endpoint type when a VPC ID is supplied",
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
        "value": "aws_transfer_server"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "VPC"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "VPC"
     }
    },
    {
     "kind": "attr",
     "select": "srv",
     "cond": {
      "path": [
       "endpoint_details",
       "*",
       "vpc_id"
      ],
      "op": "present"
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
        "value": "aws_transfer_server"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)vpc_id"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "eip_when_public",
   "kind": "exists",
   "tier": "detail",
   "quote": "allocating Elastic IPs when is_public is enabled",
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
      "value": "aws_eip"
     },
     {
      "path": [],
      "op": "regex",
      "value": "is_public"
     }
    ]
   }
  },
  {
   "id": "is_public_var",
   "kind": "any_of",
   "tier": "detail",
   "quote": "when is_public is enabled",
   "checks": [
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
        "op": "eq",
        "value": "is_public"
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
        "value": "aws_eip"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "is_public"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "security_groups",
   "kind": "exists",
   "tier": "detail",
   "quote": "managing optional dedicated security groups and rules for both SFTP and EFS interfaces",
   "justify": "one group each for SFTP and EFS",
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
      "value": "aws_security_group"
     }
    ]
   },
   "min": 2
  },
  {
   "id": "security_group_rules",
   "kind": "any_of",
   "tier": "detail",
   "quote": "managing optional dedicated security groups and rules",
   "justify": "security group rules are ingress or egress rules",
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
        "value": "aws_security_group_rule"
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
        "value": "aws_vpc_security_group_ingress_rule"
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
        "value": "aws_security_group"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ingress"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "transfer_users",
   "kind": "exists",
   "tier": "core",
   "quote": "provision individual SFTP users",
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
      "value": "aws_transfer_user"
     }
    ]
   }
  },
  {
   "id": "user_posix",
   "kind": "exists",
   "tier": "detail",
   "quote": "linked to POSIX profiles (UID/GID)",
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
      "value": "aws_transfer_user"
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)posix_profile"
     }
    ]
   }
  },
  {
   "id": "ssh_keys",
   "kind": "exists",
   "tier": "core",
   "quote": "SSH public keys",
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
      "value": "aws_transfer_ssh_key"
     }
    ]
   }
  },
  {
   "id": "home_mappings",
   "kind": "exists",
   "tier": "detail",
   "quote": "home directory mappings",
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
      "value": "aws_transfer_user"
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)home_directory_mappings"
     }
    ]
   }
  },
  {
   "id": "restricted_flag",
   "kind": "exists",
   "tier": "detail",
   "quote": "restricting directory access when restricted is true",
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
      "value": "aws_transfer_user"
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "restricted"
     }
    ]
   }
  },
  {
   "id": "iam_role_suffix",
   "kind": "attr",
   "tier": "core",
   "quote": "an automatically generated IAM role named by suffixing the SFTP server name value with \"-role\"",
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
    "op": "regex",
    "value": "^\\$\\{(var|local)\\.[A-Za-z0-9_]+\\}-role$"
   }
  },
  {
   "id": "user_role_link",
   "kind": "ref",
   "tier": "detail",
   "quote": "attached to either an automatically generated IAM role",
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
      "value": "aws_transfer_user"
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
   }
  },
  {
   "id": "role_efs_perms",
   "kind": "all_of",
   "tier": "core",
   "quote": "granting EFS client mount/read/write permissions",
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
        "op": "in",
        "value": [
         "data.aws_iam_policy_document",
         "aws_iam_policy",
         "aws_iam_role_policy"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)elasticfilesystem:(ClientMount|\\*)"
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
        "op": "in",
        "value": [
         "data.aws_iam_policy_document",
         "aws_iam_policy",
         "aws_iam_role_policy"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)elasticfilesystem:(ClientWrite|\\*)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "user_role_provided_option",
   "kind": "any_of",
   "tier": "detail",
   "quote": "or a valid provided IAM role ARN",
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
        "value": "aws_transfer_user"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "role"
      ],
      "op": "regex",
      "value": "\\?|coalesce\\(|try\\("
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
        "value": "(?i)role_?arn"
       }
      ]
     }
    }
   ],
   "justify": "'either a generated role or a provided ARN' means the user's role is chosen conditionally"
  },
  {
   "id": "logging_role",
   "kind": "any_of",
   "tier": "core",
   "quote": "CloudWatch logging must be conditionally supported via an IAM logging role",
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
        "value": "aws_transfer_server"
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
        "value": "aws_transfer_server"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "logging_role"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "srv",
     "cond": {
      "path": [
       "logging_role"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "logging_policy",
   "kind": "exists",
   "tier": "detail",
   "quote": "and policy when logging_enabled is set to true",
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
       "aws_iam_role_policy"
      ]
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)logs:(PutLogEvents|CreateLogStream|\\*)"
     }
    ]
   }
  },
  {
   "id": "logging_enabled_var",
   "kind": "any_of",
   "tier": "detail",
   "quote": "when logging_enabled is set to true",
   "checks": [
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
        "op": "eq",
        "value": "logging_enabled"
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
        "value": "aws_iam_role"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "logging_enabled"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "sftp_users_var",
   "kind": "any_of",
   "tier": "detail",
   "quote": "sftp_users object map",
   "checks": [
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
        "op": "eq",
        "value": "sftp_users"
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
        "value": "aws_transfer_user"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "sftp_users"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "additional_ap_var",
   "kind": "any_of",
   "tier": "detail",
   "quote": "an additional_access_points map",
   "checks": [
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
        "op": "eq",
        "value": "additional_access_points"
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
        "value": "aws_efs_access_point"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "additional_access_points"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "x_srv_force",
   "kind": "attr",
   "tier": "extra",
   "select": "srv",
   "cond": {
    "path": [
     "force_destroy"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "x_user_to_server",
   "kind": "ref",
   "tier": "extra",
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
      "value": "aws_transfer_user"
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
      "value": "aws_transfer_server"
     }
    ]
   }
  },
  {
   "id": "x_key_to_user",
   "kind": "ref",
   "tier": "extra",
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
      "value": "aws_transfer_ssh_key"
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
      "value": "aws_transfer_user"
     }
    ]
   }
  },
  {
   "id": "x_mount_to_efs",
   "kind": "ref",
   "tier": "extra",
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
      "value": "aws_efs_mount_target"
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
      "value": "aws_efs_file_system"
     }
    ]
   }
  },
  {
   "id": "x_ap_to_efs",
   "kind": "ref",
   "tier": "extra",
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
      "value": "aws_efs_access_point"
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
      "value": "aws_efs_file_system"
     }
    ]
   }
  },
  {
   "id": "extra_type_aws_iam_role_policy_attachment",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_iam_role_policy_attachment"
    ],
    "where": []
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
