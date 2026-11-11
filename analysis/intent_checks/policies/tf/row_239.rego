package intent.tf.row_239

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "ebs_default_encryption",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_ebs_encryption_by_default"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "enabled"
    ],
    "op": "truthy"
   },
   "quote": "default EBS encryption enabled at the account level"
  },
  {
   "id": "three_kms_keys",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_kms_key"
    ],
    "where": []
   },
   "min": 3,
   "quote": "three separate KMS customer-managed keys"
  },
  {
   "id": "alias_compute",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_kms_alias"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "^alias/.+-compute$"
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
        "value": "aws_kms_alias"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "regex",
        "value": "^alias/.+-compute$"
       }
      ]
     }
    }
   ],
   "quote": "\"-compute\"",
   "justify": "suffix and alias/ prefix are stated"
  },
  {
   "id": "alias_observability",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_kms_alias"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "^alias/.+-observability$"
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
        "value": "aws_kms_alias"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "regex",
        "value": "^alias/.+-observability$"
       }
      ]
     }
    }
   ],
   "quote": "\"-observability\"",
   "justify": "suffix and alias/ prefix are stated"
  },
  {
   "id": "alias_storage",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_kms_alias"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "^alias/.+-storage$"
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
        "value": "aws_kms_alias"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "regex",
        "value": "^alias/.+-storage$"
       }
      ]
     }
    }
   ],
   "quote": "\"-storage\"",
   "justify": "suffix and alias/ prefix are stated"
  },
  {
   "id": "rotation_enabled",
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
    "op": "truthy"
   },
   "quantifier": "all",
   "quote": "each with key rotation enabled"
  },
  {
   "id": "rotation_period_90",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_kms_key"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "rotation_period_in_days"
      ],
      "op": "eq",
      "value": 90
     },
     "quantifier": "all"
    },
    {
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
        "value": "(?i)rotation"
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": 90
     }
    }
   ],
   "quote": "configurable rotation period in days defaulting to 90",
   "justify": "default 90 days stated"
  },
  {
   "id": "deletion_window_30",
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
     "deletion_window_in_days"
    ],
    "op": "eq",
    "value": 30
   },
   "quantifier": "all",
   "quote": "a 30-day deletion window"
  },
  {
   "id": "prevent_destroy",
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
      "value": "aws_kms_key"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "lifecycle",
     "*",
     "prevent_destroy"
    ],
    "op": "truthy"
   },
   "quantifier": "all",
   "quote": "prevent_destroy lifecycle protection"
  },
  {
   "id": "keys_root_access",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_kms_key"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": ":root"
     },
     "quantifier": "all"
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
        "value": "aws_kms_key"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": ":root"
     },
     "quantifier": "all"
    }
   ],
   "quote": "permit IAM root access",
   "justify": "IAM root access is the account root principal"
  },
  {
   "id": "compute_ec2",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_kms_alias"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)-compute$"
       }
      ]
     },
     "to": {
      "types": [
       "aws_kms_key"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "ec2\\.amazonaws\\.com"
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
        "value": "aws_kms_alias"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "regex",
        "value": "(?i)-compute$"
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
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "ec2\\.amazonaws\\.com"
       }
      ]
     }
    }
   ],
   "quote": "EC2 service operations for the current account"
  },
  {
   "id": "compute_autoscaling_grant",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_kms_alias"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)-compute$"
       }
      ]
     },
     "to": {
      "types": [
       "aws_kms_key"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)autoscaling"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)CreateGrant"
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
        "value": "aws_kms_alias"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "regex",
        "value": "(?i)-compute$"
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
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "(?i)autoscaling"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "(?i)CreateGrant"
       }
      ]
     }
    }
   ],
   "quote": "Auto Scaling service role usage including grant creation"
  },
  {
   "id": "ebs_default_key_resource",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_ebs_default_kms_key"
    ],
    "where": []
   },
   "quote": "set the account-level default EBS KMS key"
  },
  {
   "id": "ebs_default_key_ref",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_ebs_default_kms_key"
      ],
      "where": []
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
        "value": "aws_ebs_default_kms_key"
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
   ],
   "quote": "the internal compute KMS key ARN when left blank"
  },
  {
   "id": "ebs_default_key_variable",
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
      "value": "aws_ebs_default_kms_key"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "key_arn"
    ],
    "op": "regex",
    "value": "(var\\.|local\\.[a-z_]*(ebs|kms|key))"
   },
   "quote": "an optional external key ARN variable"
  },
  {
   "id": "obs_logs_context",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_kms_alias"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)-observability$"
       }
      ]
     },
     "to": {
      "types": [
       "aws_kms_key"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)logs\\..{0,60}amazonaws\\.com"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)aws:logs:arn"
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
        "value": "aws_kms_alias"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "regex",
        "value": "(?i)-observability$"
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
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "(?i)logs\\..{0,60}amazonaws\\.com"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "(?i)aws:logs:arn"
       }
      ]
     }
    }
   ],
   "quote": "CloudWatch Logs conditioned on log group context"
  },
  {
   "id": "obs_services",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_kms_alias"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)-observability$"
       }
      ]
     },
     "to": {
      "types": [
       "aws_kms_key"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "cloudtrail\\.amazonaws\\.com"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "cloudwatch\\.amazonaws\\.com"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "sns\\.amazonaws\\.com"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "sqs\\.amazonaws\\.com"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "events\\.amazonaws\\.com"
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
        "value": "aws_kms_alias"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "regex",
        "value": "(?i)-observability$"
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
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "cloudtrail\\.amazonaws\\.com"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "cloudwatch\\.amazonaws\\.com"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "sns\\.amazonaws\\.com"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "sqs\\.amazonaws\\.com"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "events\\.amazonaws\\.com"
       }
      ]
     }
    }
   ],
   "quote": "CloudTrail, CloudWatch Alarms, SNS, SQS, and EventBridge"
  },
  {
   "id": "storage_services",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_kms_alias"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)-storage$"
       }
      ]
     },
     "to": {
      "types": [
       "aws_kms_key"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "s3\\.amazonaws\\.com"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "config\\.amazonaws\\.com"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "cloudtrail\\.amazonaws\\.com"
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
        "value": "aws_kms_alias"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "regex",
        "value": "(?i)-storage$"
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
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "s3\\.amazonaws\\.com"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "config\\.amazonaws\\.com"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "cloudtrail\\.amazonaws\\.com"
       }
      ]
     }
    }
   ],
   "quote": "S3 service usage, AWS Config encrypted snapshot delivery, and CloudTrail log encryption"
  },
  {
   "id": "image_block_public",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_ec2_image_block_public_access"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "state"
    ],
    "op": "eq",
    "value": "block-new-sharing"
   },
   "quote": "setting EC2 image block public access to \"block-new-sharing\""
  },
  {
   "id": "snapshot_block_public",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_ebs_snapshot_block_public_access"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "state"
    ],
    "op": "eq",
    "value": "block-all-sharing"
   },
   "quote": "EBS snapshot block public access to \"block-all-sharing\""
  },
  {
   "id": "imds_required",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_ec2_instance_metadata_defaults"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "http_tokens"
    ],
    "op": "eq",
    "value": "required"
   },
   "quote": "enforcing required HTTP tokens (IMDSv2)"
  },
  {
   "id": "imds_hop_limit",
   "tier": "detail",
   "kind": "attr",
   "select": {
    "types": [
     "aws_ec2_instance_metadata_defaults"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "http_put_response_hop_limit"
    ],
    "op": "eq",
    "value": 1
   },
   "quote": "a configurable hop limit defaulting to 1",
   "justify": "default hop limit 1 stated"
  },
  {
   "id": "imds_toggle",
   "tier": "detail",
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
      "value": "aws_ec2_instance_metadata_defaults"
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     }
    ]
   },
   "quote": "conditional account-level EC2 instance metadata defaults"
  },
  {
   "id": "serial_console_disabled",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_ec2_serial_console_access"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "enabled"
    ],
    "op": "eq",
    "value": false
   },
   "quote": "disabling of EC2 Serial Console access"
  },
  {
   "id": "serial_console_toggle",
   "tier": "detail",
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
      "value": "aws_ec2_serial_console_access"
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     }
    ]
   },
   "quote": "conditional disabling of EC2 Serial Console access when a default-true toggle is set"
  },
  {
   "id": "emr_block_public",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_emr_block_public_access_configuration"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "block_public_security_group_rules"
    ],
    "op": "truthy"
   },
   "quote": "EMR block public access configuration restricting public security groups"
  },
  {
   "id": "emr_toggle",
   "tier": "detail",
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
      "value": "aws_emr_block_public_access_configuration"
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     }
    ]
   },
   "quote": "conditional EMR block public access configuration"
  },
  {
   "id": "x_imds_endpoint",
   "tier": "extra",
   "kind": "attr",
   "select": {
    "types": [
     "aws_ec2_instance_metadata_defaults"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "http_endpoint"
    ],
    "op": "eq",
    "value": "enabled"
   }
  },
  {
   "id": "x_imds_tags_off",
   "tier": "extra",
   "kind": "attr",
   "select": {
    "types": [
     "aws_ec2_instance_metadata_defaults"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "instance_metadata_tags"
    ],
    "op": "eq",
    "value": "disabled"
   }
  },
  {
   "id": "x_ec2_source_account",
   "tier": "extra",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_kms_alias"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)-compute$"
       }
      ]
     },
     "to": {
      "types": [
       "aws_kms_key"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)SourceAccount"
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
        "value": "aws_kms_alias"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "regex",
        "value": "(?i)-compute$"
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
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "(?i)SourceAccount"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "x_cloudtrail_context",
   "tier": "extra",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_kms_alias"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)-storage$"
       }
      ]
     },
     "to": {
      "types": [
       "aws_kms_key"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)aws:cloudtrail:arn"
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
        "value": "aws_kms_alias"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "regex",
        "value": "(?i)-storage$"
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
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "(?i)aws:cloudtrail:arn"
       }
      ]
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
