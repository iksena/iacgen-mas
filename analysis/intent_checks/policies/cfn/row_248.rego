package intent.cfn.row_248

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "dlm_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Principal",
      "Service",
      "*"
     ],
     "op": "eq",
     "value": "dlm.amazonaws.com"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "dlm_policy",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "AWS::DLM::LifecyclePolicy"
    ],
    "where": []
   },
   "quote": "deploy an enabled DLM EBS volume lifecycle policy"
  },
  {
   "id": "iam_role",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "AWS::IAM::Role"
    ],
    "where": []
   },
   "quote": "its supporting IAM role"
  },
  {
   "id": "dlm_enabled",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "AWS::DLM::LifecyclePolicy"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "State"
    ],
    "op": "eq",
    "value": "ENABLED"
   },
   "quote": "an enabled DLM EBS volume lifecycle policy"
  },
  {
   "id": "dlm_volume",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "AWS::DLM::LifecyclePolicy"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "PolicyDetails",
     "ResourceTypes",
     "*"
    ],
    "op": "eq",
    "value": "VOLUME"
   },
   "quote": "EBS volume lifecycle policy"
  },
  {
   "id": "dlm_uses_role",
   "kind": "ref",
   "tier": "core",
   "from": {
    "types": [
     "AWS::DLM::LifecyclePolicy"
    ],
    "where": []
   },
   "to": "dlm_role",
   "quote": "supporting IAM role"
  },
  {
   "id": "trust_dlm",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "AWS::IAM::Role"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "AssumeRolePolicyDocument",
     "Statement",
     "*",
     "Principal",
     "Service",
     "*"
    ],
    "op": "eq",
    "value": "dlm.amazonaws.com"
   },
   "quote": "trusts \"dlm.amazonaws.com\""
  },
  {
   "id": "role_name",
   "tier": "detail",
   "quote": "named \"{LogicalName}-DataLifecycleManager-{Region}\"",
   "justify": "LogicalName defaults to WebServers and us-east-1 stands in for this stack's region, which the prompt asks for",
   "kind": "attr",
   "select": "dlm_role",
   "cond": {
    "path": [
     "RoleName"
    ],
    "op": "eq",
    "value": "WebServers-DataLifecycleManager-us-east-1"
   }
  },
  {
   "id": "perm_create_snapshot",
   "tier": "detail",
   "quote": "policies permitting snapshot creation",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "dlm_role",
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
      "value": "ec2:CreateSnapshot"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "ec2:CreateSnapshot"
       }
      ]
     },
     "to": "dlm_role",
     "bidirectional": true
    },
    {
     "kind": "attr",
     "select": "dlm_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "AWSDataLifecycleManagerServiceRole$"
     }
    }
   ]
  },
  {
   "id": "perm_delete_snapshot",
   "tier": "detail",
   "quote": "deletion",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "dlm_role",
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
      "value": "ec2:DeleteSnapshot"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "ec2:DeleteSnapshot"
       }
      ]
     },
     "to": "dlm_role",
     "bidirectional": true
    },
    {
     "kind": "attr",
     "select": "dlm_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "AWSDataLifecycleManagerServiceRole$"
     }
    }
   ]
  },
  {
   "id": "perm_tags",
   "tier": "detail",
   "quote": "tag management",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "dlm_role",
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
      "value": "ec2:CreateTags"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "ec2:CreateTags"
       }
      ]
     },
     "to": "dlm_role",
     "bidirectional": true
    },
    {
     "kind": "attr",
     "select": "dlm_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "AWSDataLifecycleManagerServiceRole$"
     }
    }
   ]
  },
  {
   "id": "perm_describe_volumes",
   "tier": "detail",
   "quote": "volume description",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "dlm_role",
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
      "value": "ec2:DescribeVolumes"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "ec2:DescribeVolumes"
       }
      ]
     },
     "to": "dlm_role",
     "bidirectional": true
    },
    {
     "kind": "attr",
     "select": "dlm_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "AWSDataLifecycleManagerServiceRole$"
     }
    }
   ]
  },
  {
   "id": "schedule_name",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "AWS::DLM::LifecyclePolicy"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "PolicyDetails",
     "Schedules",
     "*",
     "Name"
    ],
    "op": "eq",
    "value": "Daily Snapshots"
   },
   "quote": "scheduled to take \"Daily Snapshots\""
  },
  {
   "id": "schedule_time",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "AWS::DLM::LifecyclePolicy"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "PolicyDetails",
     "Schedules",
     "*",
     "CreateRule",
     "Times",
     "*"
    ],
    "op": "eq",
    "value": "17:00"
   },
   "quote": "at the configured daily time",
   "justify": "DailySnapshotScheduledAt defaults to 17:00"
  },
  {
   "id": "schedule_interval",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "AWS::DLM::LifecyclePolicy"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "PolicyDetails",
     "Schedules",
     "*",
     "CreateRule"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "Interval"
      ],
      "op": "eq",
      "value": 24
     },
     {
      "path": [
       "IntervalUnit"
      ],
      "op": "eq",
      "value": "HOURS"
     }
    ]
   },
   "quote": "hour interval",
   "justify": "SnapshotInterval defaults to 24 hours"
  },
  {
   "id": "retain_count",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "AWS::DLM::LifecyclePolicy"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "PolicyDetails",
     "Schedules",
     "*",
     "RetainRule",
     "Count"
    ],
    "op": "eq",
    "value": 7
   },
   "quote": "retain the defined count of snapshots",
   "justify": "SnapshotRetainRule defaults to 7"
  },
  {
   "id": "copy_tags",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "AWS::DLM::LifecyclePolicy"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "PolicyDetails",
     "Schedules",
     "*",
     "CopyTags"
    ],
    "op": "eq",
    "value": true
   },
   "quote": "copy volume tags to generated snapshots"
  },
  {
   "id": "target_env",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "AWS::DLM::LifecyclePolicy"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "PolicyDetails",
     "TargetTags",
     "*",
     "Value"
    ],
    "op": "eq",
    "value": "production"
   },
   "quote": "targeting volumes matching the specified environment",
   "justify": "Environment defaults to production"
  },
  {
   "id": "target_custom_tag",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "AWS::DLM::LifecyclePolicy"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "PolicyDetails",
     "TargetTags",
     "*"
    ],
    "op": "has_kv",
    "value": {
     "key": "createdby",
     "value": "aws-cloudformation-templates"
    }
   },
   "quote": "and custom tags",
   "justify": "TagKey/TagValue defaults"
  },
  {
   "id": "policy_name_tag",
   "kind": "attr",
   "tier": "detail",
   "select": {
    "types": [
     "AWS::DLM::LifecyclePolicy"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "Tags",
     "*"
    ],
    "op": "has_kv",
    "value": {
     "key": "Name",
     "value": "policy-WebServers-us-east-1"
    }
   },
   "quote": "a Name tag formatted as \"policy-{LogicalName}-{Region}\"",
   "justify": "LogicalName default WebServers, region resolves to us-east-1"
  },
  {
   "id": "p_time",
   "kind": "attr",
   "tier": "detail",
   "quote": "DailySnapshotScheduledAt defaulting to \"17:00\"",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": []
   },
   "cond": {
    "path": [],
    "op": "match",
    "value": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "DailySnapshotScheduledAt"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "17:00"
     }
    ]
   }
  },
  {
   "id": "p_interval",
   "kind": "attr",
   "tier": "detail",
   "quote": "SnapshotInterval defaulting to 24",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": []
   },
   "cond": {
    "path": [],
    "op": "match",
    "value": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "SnapshotInterval"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": 24
     }
    ]
   }
  },
  {
   "id": "p_retain",
   "kind": "attr",
   "tier": "detail",
   "quote": "SnapshotRetainRule defaulting to 7",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": []
   },
   "cond": {
    "path": [],
    "op": "match",
    "value": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "SnapshotRetainRule"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": 7
     }
    ]
   }
  },
  {
   "id": "p_logical",
   "kind": "attr",
   "tier": "detail",
   "quote": "LogicalName defaulting to \"WebServers\"",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": []
   },
   "cond": {
    "path": [],
    "op": "match",
    "value": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "LogicalName"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "WebServers"
     }
    ]
   }
  },
  {
   "id": "p_env",
   "kind": "attr",
   "tier": "detail",
   "quote": "Environment defaulting to \"production\"",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": []
   },
   "cond": {
    "path": [],
    "op": "match",
    "value": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "Environment"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "production"
     }
    ]
   }
  },
  {
   "id": "p_tagkey",
   "kind": "attr",
   "tier": "detail",
   "quote": "TagKey defaulting to \"createdby\"",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": []
   },
   "cond": {
    "path": [],
    "op": "match",
    "value": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "TagKey"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "createdby"
     }
    ]
   }
  },
  {
   "id": "p_tagvalue",
   "kind": "attr",
   "tier": "detail",
   "quote": "TagValue defaulting to \"aws-cloudformation-templates\"",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": []
   },
   "cond": {
    "path": [],
    "op": "match",
    "value": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "TagValue"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "aws-cloudformation-templates"
     }
    ]
   }
  },
  {
   "id": "p_interval_allowed",
   "kind": "all_of",
   "tier": "detail",
   "quote": "allowed values 2, 3, 4, 6, 8, 12, or 24 hours",
   "justify": "the seven allowed values are listed in the prompt",
   "checks": [
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
        "op": "eq",
        "value": "SnapshotInterval"
       }
      ]
     },
     "cond": {
      "path": [
       "allowed_values",
       "*"
      ],
      "op": "in",
      "value": [
       2,
       3,
       4,
       6,
       8,
       12,
       24
      ],
      "every": true
     }
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
        "op": "eq",
        "value": "SnapshotInterval"
       }
      ]
     },
     "cond": {
      "path": [
       "allowed_values"
      ],
      "op": "len_eq",
      "value": 7
     }
    }
   ]
  },
  {
   "id": "p_env_allowed",
   "kind": "all_of",
   "tier": "detail",
   "quote": "allowed values \"production\", \"test\", or \"development\"",
   "checks": [
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
        "op": "eq",
        "value": "Environment"
       }
      ]
     },
     "cond": {
      "path": [
       "allowed_values",
       "*"
      ],
      "op": "in",
      "value": [
       "production",
       "test",
       "development"
      ],
      "every": true
     }
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
        "op": "eq",
        "value": "Environment"
       }
      ]
     },
     "cond": {
      "path": [
       "allowed_values"
      ],
      "op": "len_eq",
      "value": 3
     }
    }
   ]
  },
  {
   "id": "x_trust_assume",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::IAM::Role"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "AssumeRolePolicyDocument",
     "Statement",
     "*",
     "Action",
     "*"
    ],
    "op": "glob_covers",
    "value": "sts:AssumeRole"
   }
  },
  {
   "id": "x_perm_describe_snap",
   "kind": "any_of",
   "tier": "extra",
   "checks": [
    {
     "kind": "attr",
     "select": "dlm_role",
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
      "value": "ec2:DescribeSnapshots"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "ec2:DescribeSnapshots"
       }
      ]
     },
     "to": "dlm_role",
     "bidirectional": true
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
