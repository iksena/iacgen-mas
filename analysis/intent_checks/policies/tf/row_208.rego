package intent.tf.row_208

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "detector",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_guardduty_detector"
    ],
    "where": []
   },
   "quote": "provision a primary GuardDuty detector"
  },
  {
   "id": "detector_enabled",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_guardduty_detector"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "enable"
      ],
      "op": "truthy"
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
        "value": "aws_guardduty_detector"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "enable"
      ],
      "op": "truthy"
     }
    }
   ],
   "quote": "enabled by default"
  },
  {
   "id": "ds_s3",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_guardduty_detector"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "datasources",
       "*",
       "s3_logs"
      ],
      "op": "present"
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_guardduty_detector_feature"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)S3"
       }
      ]
     }
    }
   ],
   "quote": "configurable data sources for S3 logs"
  },
  {
   "id": "ds_k8s",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_guardduty_detector"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "datasources",
       "*",
       "kubernetes"
      ],
      "op": "present"
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_guardduty_detector_feature"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)(EKS_AUDIT_LOGS|KUBERNETES)"
       }
      ]
     }
    }
   ],
   "quote": "Kubernetes audit logs"
  },
  {
   "id": "ds_malware",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_guardduty_detector"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "datasources",
       "*",
       "malware_protection"
      ],
      "op": "present"
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_guardduty_detector_feature"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)(EBS|MALWARE)"
       }
      ]
     }
    }
   ],
   "quote": "EC2 malware scanning"
  },
  {
   "id": "frequency",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_guardduty_detector"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "finding_publishing_frequency"
    ],
    "op": "eq",
    "value": "FIFTEEN_MINUTES"
   },
   "quote": "finding publishing frequencies defaulting to \"FIFTEEN_MINUTES\""
  },
  {
   "id": "local_exec",
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
        "value": "aws_guardduty_detector"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "provisioner"
      ],
      "op": "regex",
      "value": "(?is)local-exec.{0,800}snapshot.?preservation"
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
        "value": "null_resource"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "provisioner"
      ],
      "op": "regex",
      "value": "(?is)local-exec.{0,800}snapshot.?preservation"
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
        "value": "terraform_data"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "provisioner"
      ],
      "op": "regex",
      "value": "(?is)local-exec.{0,800}snapshot.?preservation"
     }
    }
   ],
   "quote": "a local-exec provisioner to set EBS snapshot preservation"
  },
  {
   "id": "snapshot_toggle",
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
      "op": "regex",
      "value": "(?i)snapshot"
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
   "quote": "a snapshot retention toggle (defaulting to false)"
  },
  {
   "id": "filters",
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
      "value": "aws_guardduty_filter"
     }
    ]
   },
   "quote": "custom finding filters"
  },
  {
   "id": "ipsets",
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
      "value": "aws_guardduty_ipset"
     }
    ]
   },
   "quote": "IP sets"
  },
  {
   "id": "threatintel",
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
      "value": "aws_guardduty_threatintelset"
     }
    ]
   },
   "quote": "threat intelligence sets"
  },
  {
   "id": "publishing",
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
      "value": "aws_guardduty_publishing_destination"
     }
    ]
   },
   "quote": "publishing destinations"
  },
  {
   "id": "kms_multi_region",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_kms_key"
      ],
      "where": [
       {
        "path": [
         "multi_region"
        ],
        "op": "truthy"
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
        "value": "aws_kms_key"
       },
       {
        "path": [
         "properties",
         "multi_region"
        ],
        "op": "truthy"
       }
      ]
     }
    }
   ],
   "quote": "a multi-region KMS key"
  },
  {
   "id": "kms_rotation",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_kms_key"
      ],
      "where": [
       {
        "path": [
         "multi_region"
        ],
        "op": "truthy"
       },
       {
        "path": [
         "enable_key_rotation"
        ],
        "op": "truthy"
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
        "value": "aws_kms_key"
       },
       {
        "path": [
         "properties",
         "multi_region"
        ],
        "op": "truthy"
       },
       {
        "path": [
         "properties",
         "enable_key_rotation"
        ],
        "op": "truthy"
       }
      ]
     }
    }
   ],
   "quote": "automated key rotation"
  },
  {
   "id": "kms_deletion_7",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_kms_key"
      ],
      "where": [
       {
        "path": [
         "multi_region"
        ],
        "op": "truthy"
       },
       {
        "path": [
         "deletion_window_in_days"
        ],
        "op": "eq",
        "value": 7
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
        "value": "aws_kms_key"
       },
       {
        "path": [
         "properties",
         "multi_region"
        ],
        "op": "truthy"
       },
       {
        "path": [
         "properties",
         "deletion_window_in_days"
        ],
        "op": "eq",
        "value": 7
       }
      ]
     }
    }
   ],
   "quote": "a 7-day deletion window"
  },
  {
   "id": "replication_role",
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
         "statement"
        ],
        "op": "regex",
        "value": "s3\\.amazonaws\\.com"
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
         "properties",
         "assume_role_policy"
        ],
        "op": "regex",
        "value": "s3\\.amazonaws\\.com"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "assume_role_policy"
        ],
        "op": "contains",
        "value": "s3.amazonaws.com"
       }
      ]
     }
    }
   ],
   "quote": "an IAM replication role",
   "justify": "an S3 replication role is assumed by the s3.amazonaws.com service"
  },
  {
   "id": "replication_policy_actions",
   "tier": "detail",
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties",
         "statement"
        ],
        "op": "regex",
        "value": "(?i)s3:(Replicate|\\*)"
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
         "policy"
        ],
        "op": "regex",
        "value": "(?i)s3:(Replicate|\\*)"
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
        "value": "aws_iam_role_policy"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "(?i)s3:(Replicate|\\*)"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
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
        "value": "s3:ReplicateObject"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)s3:(Replicate|\\*)"
       }
      ]
     }
    }
   ],
   "quote": "an IAM replication role and policy",
   "justify": "a replication policy grants S3 replication actions"
  },
  {
   "id": "replica_provider",
   "tier": "detail",
   "kind": "exists",
   "select": {
    "types": [
     "__declared__"
    ],
    "where": [
     {
      "path": [
       "properties",
       "provider"
      ],
      "op": "present"
     }
    ]
   },
   "quote": "in a replica region using cross-region provider settings"
  },
  {
   "id": "x_replica_key_rotation",
   "tier": "extra",
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
      "value": "aws_kms_key"
     },
     {
      "path": [
       "properties",
       "provider"
      ],
      "op": "present"
     },
     {
      "path": [
       "properties",
       "enable_key_rotation"
      ],
      "op": "truthy"
     }
    ]
   }
  },
  {
   "id": "x_bucket_policy_guardduty",
   "tier": "extra",
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
      "value": "data.aws_iam_policy_document"
     },
     {
      "path": [
       "properties",
       "statement"
      ],
      "op": "regex",
      "value": "guardduty\\.amazonaws\\.com"
     }
    ]
   }
  },
  {
   "id": "x_kms_guardduty",
   "tier": "extra",
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
      "value": "data.aws_iam_policy_document"
     },
     {
      "path": [
       "properties",
       "statement"
      ],
      "op": "regex",
      "value": "kms:GenerateDataKey"
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
   }
  },
  {
   "id": "extra_type_aws_s3_object",
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
      "value": "aws_s3_object"
     }
    ]
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
