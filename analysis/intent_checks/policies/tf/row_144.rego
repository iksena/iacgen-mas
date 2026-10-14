# GENERATED from specs/tf/row_144.json by intent_checks/build.py -- do not edit.
package intent.tf.row_144

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "role": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "assume_role_policy"
     ],
     "op": "contains",
     "value": "config.amazonaws.com"
    }
   ]
  },
  "recorder": {
   "types": [
    "aws_config_configuration_recorder"
   ],
   "where": []
  },
  "bucket": {
   "types": [
    "aws_s3_bucket"
   ],
   "where": [
    {
     "path": [
      "force_destroy"
     ],
     "op": "truthy"
    }
   ]
  },
  "topic": {
   "types": [
    "aws_sns_topic"
   ],
   "where": []
  },
  "channel": {
   "types": [
    "aws_config_delivery_channel"
   ],
   "where": []
  },
  "cmk": {
   "types": [
    "aws_kms_key"
   ],
   "where": [
    {
     "path": [
      "enable_key_rotation"
     ],
     "op": "truthy"
    }
   ]
  },
  "tags_rule": {
   "types": [
    "aws_config_config_rule"
   ],
   "where": [
    {
     "path": [
      "source",
      "*",
      "source_identifier"
     ],
     "op": "eq",
     "value": "REQUIRED_TAGS"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "config_role",
   "kind": "exists",
   "select": "role",
   "tier": "core",
   "quote": "The stack must deploy an IAM role"
  },
  {
   "id": "config_role_managed_policy",
   "kind": "any_of",
   "tier": "core",
   "quote": "paired with the AWS_ConfigRole managed policy",
   "checks": [
    {
     "kind": "ref",
     "to": "role",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "contains",
        "value": "AWS_ConfigRole"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "managed_policy_arns",
       "*"
      ],
      "op": "contains",
      "value": "AWS_ConfigRole"
     }
    },
    {
     "kind": "ref",
     "to": "role",
     "from": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "contains",
        "value": "AWS_ConfigRole"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "role_name_petname_fallback",
   "kind": "any_of",
   "tier": "detail",
   "quote": "with petname fallback when null or empty",
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
   "justify": "prompt explicitly asks for a petname fallback; accepted whether instantiated or only declared (gated)"
  },
  {
   "id": "snapshot_bucket_force_destroy",
   "kind": "exists",
   "select": "bucket",
   "tier": "core",
   "quote": "a force-destroy-enabled S3 snapshot storage bucket"
  },
  {
   "id": "role_bucket_write_permission",
   "kind": "any_of",
   "tier": "detail",
   "quote": "write permissions to a force-destroy-enabled S3 snapshot storage bucket",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_iam_policy"
      ],
      "where": []
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)s3:(put|\\*)"
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
         "aws_iam_policy",
         "aws_iam_role_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)s3:(put|\\*)"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "inline_policy",
       "*",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)s3:(put|\\*)"
     }
    }
   ],
   "justify": "'write permissions' to S3 implies s3:Put* (or s3:*)"
  },
  {
   "id": "role_sns_publish_inline",
   "kind": "any_of",
   "tier": "detail",
   "quote": "an inline policy permitting SNS publish operations",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": []
     },
     "to": "topic"
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "contains",
      "value": "sns:publish"
     }
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "inline_policy",
       "*",
       "policy"
      ],
      "op": "contains",
      "value": "sns:publish"
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
         "aws_iam_role_policy",
         "aws_iam_role",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)sns:publish"
       }
      ]
     }
    }
   ],
   "justify": "inline policy text may be in a policy document or jsonencode unknown at plan"
  },
  {
   "id": "recorder_all_supported",
   "kind": "attr",
   "select": "recorder",
   "tier": "core",
   "cond": {
    "path": [
     "recording_group",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "all_supported"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "include_global_resource_types"
      ],
      "op": "truthy"
     }
    ]
   },
   "quote": "capture all supported global and regional resource types"
  },
  {
   "id": "recorder_uses_role",
   "kind": "ref",
   "from": "recorder",
   "to": "role",
   "tier": "detail",
   "quote": "An AWS Config configuration recorder"
  },
  {
   "id": "delivery_prefix",
   "kind": "attr",
   "select": "channel",
   "tier": "core",
   "cond": {
    "path": [
     "s3_key_prefix"
    ],
    "op": "eq",
    "value": "awsconfig/records"
   },
   "quote": "deliver snapshot records with an S3 key prefix of \"awsconfig/records\""
  },
  {
   "id": "delivery_to_bucket",
   "kind": "any_of",
   "tier": "core",
   "quote": "deliver snapshot records with an S3 key prefix of \"awsconfig/records\" to the snapshot bucket",
   "checks": [
    {
     "kind": "ref",
     "from": "channel",
     "to": "bucket"
    },
    {
     "kind": "join",
     "from": "channel",
     "from_path": [
      "s3_bucket_name"
     ],
     "to": "bucket",
     "to_path": [
      "bucket"
     ]
    }
   ]
  },
  {
   "id": "delivery_to_topic",
   "kind": "ref",
   "from": "channel",
   "to": "topic",
   "tier": "core",
   "quote": "streaming notifications to an SNS topic"
  },
  {
   "id": "topic_cmk_rotation",
   "kind": "ref",
   "from": "topic",
   "to": "cmk",
   "tier": "core",
   "quote": "encrypted with a dedicated customer-managed KMS key with automatic rotation"
  },
  {
   "id": "eleven_rules",
   "kind": "exists",
   "tier": "core",
   "min": 11,
   "max": 11,
   "select": {
    "types": [
     "aws_config_config_rule"
    ],
    "where": []
   },
   "quote": "provision a set of eleven managed AWS Config rules"
  },
  {
   "id": "rules_aws_managed",
   "kind": "attr",
   "tier": "detail",
   "quantifier": "all",
   "select": {
    "types": [
     "aws_config_config_rule"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "source",
     "*",
     "owner"
    ],
    "op": "eq",
    "value": "AWS"
   },
   "quote": "eleven managed AWS Config rules"
  },
  {
   "id": "named_rules_with_identifiers",
   "kind": "all_of",
   "tier": "core",
   "quote": "\"cloudtrail-enabled\" (CLOUD_TRAIL_ENABLED), \"iam-pw-policy\" (IAM_PASSWORD_POLICY), \"ec2-vpc\" (INSTANCES_IN_VPC), \"root-mfa-enabled\" (ROOT_ACCOUNT_MFA_ENABLED), \"acm-expiration-check\" (ACM_CERTIFICATE_EXPIRATION_CHECK), \"ebs-inuse-check\" (EC2_VOLUME_INUSE_CHECK), \"ec2-imdsv2-check\" (EC2_IMDSV2_CHECK), \"rds-encrypted\" (RDS_STORAGE_ENCRYPTED), \"rds-private\" (RDS_INSTANCE_PUBLIC_ACCESS_CHECK), \"rds-private-snapshots\" (RDS_SNAPSHOTS_PUBLIC_PROHIBITED), and \"required-tags\" (REQUIRED_TAGS",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_config_config_rule"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "cloudtrail-enabled"
       },
       {
        "path": [
         "source",
         "*",
         "source_identifier"
        ],
        "op": "eq",
        "value": "CLOUD_TRAIL_ENABLED"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_config_config_rule"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "iam-pw-policy"
       },
       {
        "path": [
         "source",
         "*",
         "source_identifier"
        ],
        "op": "eq",
        "value": "IAM_PASSWORD_POLICY"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_config_config_rule"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "ec2-vpc"
       },
       {
        "path": [
         "source",
         "*",
         "source_identifier"
        ],
        "op": "eq",
        "value": "INSTANCES_IN_VPC"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_config_config_rule"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "root-mfa-enabled"
       },
       {
        "path": [
         "source",
         "*",
         "source_identifier"
        ],
        "op": "eq",
        "value": "ROOT_ACCOUNT_MFA_ENABLED"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_config_config_rule"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "acm-expiration-check"
       },
       {
        "path": [
         "source",
         "*",
         "source_identifier"
        ],
        "op": "eq",
        "value": "ACM_CERTIFICATE_EXPIRATION_CHECK"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_config_config_rule"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "ebs-inuse-check"
       },
       {
        "path": [
         "source",
         "*",
         "source_identifier"
        ],
        "op": "eq",
        "value": "EC2_VOLUME_INUSE_CHECK"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_config_config_rule"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "ec2-imdsv2-check"
       },
       {
        "path": [
         "source",
         "*",
         "source_identifier"
        ],
        "op": "eq",
        "value": "EC2_IMDSV2_CHECK"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_config_config_rule"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "rds-encrypted"
       },
       {
        "path": [
         "source",
         "*",
         "source_identifier"
        ],
        "op": "eq",
        "value": "RDS_STORAGE_ENCRYPTED"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_config_config_rule"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "rds-private"
       },
       {
        "path": [
         "source",
         "*",
         "source_identifier"
        ],
        "op": "eq",
        "value": "RDS_INSTANCE_PUBLIC_ACCESS_CHECK"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_config_config_rule"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "rds-private-snapshots"
       },
       {
        "path": [
         "source",
         "*",
         "source_identifier"
        ],
        "op": "eq",
        "value": "RDS_SNAPSHOTS_PUBLIC_PROHIBITED"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_config_config_rule"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "required-tags"
       },
       {
        "path": [
         "source",
         "*",
         "source_identifier"
        ],
        "op": "eq",
        "value": "REQUIRED_TAGS"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "rules_24h_frequency",
   "kind": "attr",
   "tier": "detail",
   "select": {
    "types": [
     "aws_config_config_rule"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "maximum_execution_frequency"
    ],
    "op": "eq",
    "value": "TwentyFour_Hours"
   },
   "quote": "evaluated every twenty-four hours or upon configuration changes"
  },
  {
   "id": "required_tags_keys",
   "kind": "all_of",
   "tier": "detail",
   "quote": "checking for \"terraform.io\" and \"environment\" tags",
   "checks": [
    {
     "kind": "attr",
     "select": "tags_rule",
     "cond": {
      "path": [
       "input_parameters"
      ],
      "op": "contains",
      "value": "\"terraform.io\""
     }
    },
    {
     "kind": "attr",
     "select": "tags_rule",
     "cond": {
      "path": [
       "input_parameters"
      ],
      "op": "contains",
      "value": "\"environment\""
     }
    }
   ]
  },
  {
   "id": "required_tags_scope_s3",
   "kind": "attr",
   "tier": "detail",
   "select": "tags_rule",
   "cond": {
    "path": [
     "scope",
     "*",
     "compliance_resource_types",
     "*"
    ],
    "op": "regex",
    "value": "S3::Bucket$"
   },
   "quote": "specifically scoped to \"S3::Bucket\" resources"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
