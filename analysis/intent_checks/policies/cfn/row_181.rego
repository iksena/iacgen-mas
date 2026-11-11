package intent.cfn.row_181

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "roles": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "outs": {
   "types": [
    "__output__"
   ],
   "where": []
  },
  "dms": {
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
     "op": "regex",
     "value": "(?i)^dms(\\.[a-z0-9-]+)?\\.amazonaws\\.com$"
    }
   ]
  },
  "pipes": {
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
     "op": "regex",
     "value": "(?i)^pipes(\\.[a-z0-9-]+)?\\.amazonaws\\.com$"
    }
   ]
  },
  "lam": {
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
     "op": "regex",
     "value": "(?i)^lambda(\\.[a-z0-9-]+)?\\.amazonaws\\.com$"
    }
   ]
  },
  "glue": {
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
     "op": "regex",
     "value": "(?i)^glue(\\.[a-z0-9-]+)?\\.amazonaws\\.com$"
    }
   ]
  },
  "lf": {
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
     "op": "regex",
     "value": "(?i)^lakeformation(\\.[a-z0-9-]+)?\\.amazonaws\\.com$"
    }
   ]
  },
  "sfn": {
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
     "op": "regex",
     "value": "(?i)^states(\\.[a-z0-9-]+)?\\.amazonaws\\.com$"
    }
   ]
  },
  "ecs": {
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
     "op": "regex",
     "value": "(?i)^ecs-tasks(\\.[a-z0-9-]+)?\\.amazonaws\\.com$"
    }
   ]
  },
  "emr": {
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
     "op": "regex",
     "value": "(?i)^emr-serverless(\\.[a-z0-9-]+)?\\.amazonaws\\.com$"
    }
   ]
  },
  "grafana": {
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
     "op": "regex",
     "value": "(?i)^grafana(\\.[a-z0-9-]+)?\\.amazonaws\\.com$"
    }
   ]
  },
  "tagged": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "Tags",
      "*"
     ],
     "op": "has_kv",
     "value": {
      "key": "Project",
      "value": "DataMaster"
     }
    },
    {
     "path": [
      "Tags",
      "*"
     ],
     "op": "has_kv",
     "value": {
      "key": "Component",
      "value": "Roles"
     }
    }
   ]
  },
  "exports": {
   "types": [
    "__output__"
   ],
   "where": [
    {
     "path": [
      "export"
     ],
     "op": "regex",
     "value": "(?i)^dm-.+-role-arn$"
    }
   ]
  },
  "assume_pol": {
   "types": [
    "AWS::IAM::Policy",
    "AWS::IAM::ManagedPolicy"
   ],
   "where": [
    {
     "path": [
      "PolicyDocument",
      "Statement",
      "*"
     ],
     "op": "match",
     "value": [
      {
       "path": [
        "Action",
        "*"
       ],
       "op": "glob_covers",
       "value": "sts:AssumeRole"
      },
      {
       "path": [
        "Resource",
        "*"
       ],
       "op": "regex",
       "value": "arn:aws:iam::[^*]"
      }
     ]
    }
   ]
  },
  "kin_pol": {
   "types": [
    "AWS::IAM::Policy",
    "AWS::IAM::ManagedPolicy"
   ],
   "where": [
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "(?i)kinesis:(put|\\*)"
    }
   ]
  },
  "fh_pol": {
   "types": [
    "AWS::IAM::Policy",
    "AWS::IAM::ManagedPolicy"
   ],
   "where": [
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "(?i)firehose:(put|\\*)"
    }
   ]
  },
  "kms_pol": {
   "types": [
    "AWS::IAM::Policy",
    "AWS::IAM::ManagedPolicy"
   ],
   "where": [
    {
     "path": [
      "PolicyDocument",
      "Statement",
      "*"
     ],
     "op": "match",
     "value": [
      {
       "path": [
        "Action",
        "*"
       ],
       "op": "regex",
       "value": "(?i)^kms:"
      },
      {
       "path": [
        "Resource",
        "*"
       ],
       "op": "none_eq",
       "value": "*"
      }
     ]
    }
   ]
  },
  "dmsvpc": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [],
     "op": "regex",
     "value": "(?is)(dms.{0,12}vpc|vpc.{0,12}dms|dms\\.amazonaws\\.com.{0,900}ec2:[a-z]*NetworkInterface)"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "iam_roles",
   "kind": "exists",
   "select": "roles",
   "tier": "core",
   "quote": "creates a comprehensive, self-contained set of IAM roles for the Data Master project",
   "justify": "nine service categories are listed, each needing a role",
   "min": 9
  },
  {
   "id": "account_id_parameter",
   "kind": "any_of",
   "tier": "core",
   "quote": "the Target AWS Account ID (used to scope STS AssumeRole policies)",
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
        "op": "regex",
        "value": "(?i)account"
       }
      ]
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
         "default"
        ],
        "op": "regex",
        "value": "^[0-9]{12}$"
       }
      ]
     }
    }
   ],
   "justify": "an AWS account ID is 12 digits"
  },
  {
   "id": "dms_role",
   "kind": "exists",
   "select": "dms",
   "tier": "core",
   "quote": "Provision roles for DMS to write to Kinesis"
  },
  {
   "id": "dms_kinesis_permissions",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "dms",
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
      "value": "kinesis:PutRecord"
     }
    },
    {
     "kind": "attr",
     "select": "dms",
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
      "value": "kinesis:PutRecords"
     }
    },
    {
     "kind": "attr",
     "select": "dms",
     "cond": {
      "path": [
       "ManagedPolicyArns"
      ],
      "op": "regex",
      "value": "(?i)kinesis.*fullaccess"
     }
    },
    {
     "kind": "ref",
     "from": "kin_pol",
     "to": "dms",
     "bidirectional": true
    }
   ],
   "tier": "core",
   "quote": "Provision roles for DMS to write to Kinesis",
   "justify": "writing to Kinesis means granting a Kinesis put action"
  },
  {
   "id": "pipes_role",
   "kind": "exists",
   "select": "pipes",
   "tier": "core",
   "quote": "EventBridge Pipes to forward data to Firehose"
  },
  {
   "id": "pipes_firehose_permissions",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "pipes",
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
      "value": "firehose:PutRecord"
     }
    },
    {
     "kind": "attr",
     "select": "pipes",
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
      "value": "firehose:PutRecordBatch"
     }
    },
    {
     "kind": "attr",
     "select": "pipes",
     "cond": {
      "path": [
       "ManagedPolicyArns"
      ],
      "op": "regex",
      "value": "(?i)firehose.*fullaccess"
     }
    },
    {
     "kind": "ref",
     "from": "fh_pol",
     "to": "pipes",
     "bidirectional": true
    }
   ],
   "tier": "core",
   "quote": "EventBridge Pipes to forward data to Firehose",
   "justify": "forwarding to Firehose means granting a Firehose put action"
  },
  {
   "id": "lambda_role",
   "kind": "exists",
   "select": "lam",
   "tier": "core",
   "quote": "Lambda functions for processing and routing"
  },
  {
   "id": "glue_role",
   "kind": "exists",
   "select": "glue",
   "tier": "core",
   "quote": "Glue crawlers and ETL jobs"
  },
  {
   "id": "lakeformation_role",
   "kind": "exists",
   "select": "lf",
   "tier": "core",
   "quote": "Lake Formation data lake access"
  },
  {
   "id": "stepfunctions_role",
   "kind": "exists",
   "select": "sfn",
   "tier": "core",
   "quote": "Step Functions for orchestration"
  },
  {
   "id": "ecs_role",
   "kind": "exists",
   "select": "ecs",
   "tier": "core",
   "quote": "ECS Fargate tasks"
  },
  {
   "id": "emr_role",
   "kind": "exists",
   "select": "emr",
   "tier": "core",
   "quote": "EMR Serverless jobs"
  },
  {
   "id": "grafana_role",
   "kind": "exists",
   "select": "grafana",
   "tier": "core",
   "quote": "AWS Managed Grafana for monitoring"
  },
  {
   "id": "dms_assume_role_scoped",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "dmsvpc",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "sts:AssumeRole"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "arn:aws:iam::[^*]"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "dmsvpc",
     "cond": {
      "path": [
       "AssumeRolePolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Condition"
        ],
        "op": "regex",
        "value": "(?i)aws:(sourceaccount|principalaccount|resourceaccount|sourceowner|sourcearn|principalarn)"
       },
       {
        "path": [
         "Condition"
        ],
        "op": "regex",
        "value": "([0-9]{12}|<param:)"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "dmsvpc",
     "cond": {
      "path": [
       "AssumeRolePolicyDocument",
       "Statement",
       "*",
       "Principal",
       "AWS",
       "*"
      ],
      "op": "regex",
      "value": "^(arn:aws:iam::[^*]|[0-9]{12}$|<param:)"
     }
    },
    {
     "kind": "ref",
     "from": "assume_pol",
     "to": "dmsvpc",
     "bidirectional": true
    }
   ],
   "tier": "core",
   "quote": "The DMS VPC role must restrict its 'AssumeRole' policy statement using the provided Target Account ID parameter",
   "justify": "the AssumeRole statement can be the role policy or the trust policy, and either way it names an account rather than any account"
  },
  {
   "id": "kms_permissions",
   "kind": "any_of",
   "tier": "core",
   "quote": "any roles requiring KMS encryption or decryption permissions (such as the Firehose access role, the processing controller function role, and the worker role) must grant access",
   "justify": "the prompt names three roles that need the key; a statement limited to the key is not on Resource *",
   "checks": [
    {
     "kind": "exists",
     "min": 3,
     "select": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": [
       {
        "path": [
         "Policies",
         "*",
         "PolicyDocument",
         "Statement",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "regex",
          "value": "(?i)^kms:"
         },
         {
          "path": [
           "Resource",
           "*"
          ],
          "op": "none_eq",
          "value": "*"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "kms_pol",
     "to": "roles",
     "bidirectional": true
    }
   ]
  },
  {
   "id": "tagged_roles",
   "kind": "exists",
   "select": "tagged",
   "tier": "detail",
   "quote": "ensure all roles are tagged with Project: DataMaster and Component: Roles",
   "justify": "nine service roles are listed and all must be tagged",
   "min": 9
  },
  {
   "id": "exported_arns",
   "kind": "exists",
   "select": "exports",
   "tier": "core",
   "quote": "export their ARNs utilizing a naming convention consisting of a 'dm-' prefix and a '-role-arn' suffix",
   "justify": "one export per role, nine service roles",
   "min": 9
  },
  {
   "id": "exports_are_arns",
   "kind": "attr",
   "select": "exports",
   "cond": {
    "path": [
     "value"
    ],
    "op": "regex",
    "value": "(?i)(\"attr\": \"arn\"|^arn:)"
   },
   "tier": "detail",
   "quote": "export their ARNs",
   "quantifier": "all"
  },
  {
   "id": "x_dms_vpc_managed",
   "kind": "attr",
   "select": "dms",
   "cond": {
    "path": [
     "ManagedPolicyArns"
    ],
    "op": "regex",
    "value": "AmazonDMSVPCManagementRole"
   },
   "tier": "extra"
  },
  {
   "id": "x_glue_managed",
   "kind": "attr",
   "select": "glue",
   "cond": {
    "path": [
     "ManagedPolicyArns"
    ],
    "op": "regex",
    "value": "AWSGlueServiceRole"
   },
   "tier": "extra"
  },
  {
   "id": "x_ecs_managed",
   "kind": "attr",
   "select": "ecs",
   "cond": {
    "path": [
     "ManagedPolicyArns"
    ],
    "op": "regex",
    "value": "AmazonECSTaskExecutionRolePolicy"
   },
   "tier": "extra"
  },
  {
   "id": "x_sfn_runtask",
   "kind": "attr",
   "select": "sfn",
   "cond": {
    "path": [
     "Policies"
    ],
    "op": "regex",
    "value": "ecs:RunTask"
   },
   "tier": "extra"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
