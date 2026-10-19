package intent.cfn.row_150

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "exp": {
   "types": [
    "AWS::FIS::ExperimentTemplate"
   ],
   "where": []
  },
  "fis_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "contains",
     "value": "fis.amazonaws.com"
    }
   ]
  },
  "lg": {
   "types": [
    "AWS::Logs::LogGroup"
   ],
   "where": []
  },
  "key": {
   "types": [
    "AWS::KMS::Key"
   ],
   "where": []
  },
  "param": {
   "types": [
    "__parameter__"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "experiment_template",
   "kind": "exists",
   "select": "exp",
   "tier": "core",
   "quote": "an AWS Fault Injection Simulator (FIS) experiment template"
  },
  {
   "id": "action_tgw_disrupt",
   "kind": "attr",
   "select": "exp",
   "tier": "core",
   "quote": "disrupting transit gateway and route table connectivity",
   "cond": {
    "path": [
     "Actions",
     "*",
     "ActionId"
    ],
    "op": "eq",
    "value": "aws:network:transit-gateway-disrupt-cross-region-connectivity"
   },
   "justify": "the FIS action that disrupts transit gateway cross-region connectivity"
  },
  {
   "id": "action_route_table_disrupt",
   "kind": "attr",
   "select": "exp",
   "tier": "core",
   "quote": "disrupting transit gateway and route table connectivity",
   "cond": {
    "path": [
     "Actions",
     "*",
     "ActionId"
    ],
    "op": "eq",
    "value": "aws:network:route-table-disrupt-cross-region-connectivity"
   },
   "justify": "the FIS action that disrupts route-table (subnet) cross-region connectivity"
  },
  {
   "id": "action_s3_pause_replication",
   "kind": "attr",
   "select": "exp",
   "tier": "core",
   "quote": "pausing S3 and DynamoDB replication",
   "cond": {
    "path": [
     "Actions",
     "*",
     "ActionId"
    ],
    "op": "eq",
    "value": "aws:s3:bucket-pause-replication"
   },
   "justify": "the FIS action that pauses S3 replication"
  },
  {
   "id": "action_ddb_pause_replication",
   "kind": "attr",
   "select": "exp",
   "tier": "core",
   "quote": "pausing S3 and DynamoDB replication",
   "cond": {
    "path": [
     "Actions",
     "*",
     "ActionId"
    ],
    "op": "eq",
    "value": "aws:dynamodb:global-table-pause-replication"
   },
   "justify": "the FIS action that pauses DynamoDB global-table replication"
  },
  {
   "id": "target_region_parameter",
   "kind": "any_of",
   "tier": "core",
   "quote": "to a target region (provided via a parameter)",
   "checks": [
    {
     "kind": "join",
     "from": "exp",
     "from_path": [
      "Actions",
      "*",
      "Parameters",
      "region"
     ],
     "to": "param",
     "to_path": [
      "default"
     ]
    },
    {
     "kind": "join",
     "from": "exp",
     "from_path": [
      "Actions",
      "*",
      "Parameters",
      "targetRegion"
     ],
     "to": "param",
     "to_path": [
      "default"
     ]
    },
    {
     "kind": "join",
     "from": "exp",
     "from_path": [
      "Actions",
      "*",
      "Parameters",
      "destinationRegion"
     ],
     "to": "param",
     "to_path": [
      "default"
     ]
    }
   ],
   "justify": "FIS names the cross-region target parameter region; models also write targetRegion/destinationRegion"
  },
  {
   "id": "duration_20_minutes",
   "kind": "attr",
   "select": "exp",
   "tier": "core",
   "quote": "a configurable duration that defaults to 20 minutes",
   "cond": {
    "path": [
     "Actions",
     "*",
     "Parameters",
     "duration"
    ],
    "op": "eq",
    "value": "PT20M"
   },
   "justify": "20 minutes in FIS ISO-8601 duration format is PT20M"
  },
  {
   "id": "duration_configurable",
   "kind": "attr",
   "tier": "detail",
   "quote": "a configurable duration",
   "justify": "a duration parameter defaulting to 20 minutes, either as PT20M or as a number of minutes",
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
      "value": "(?i)duration"
     }
    ]
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "in",
    "value": [
     "20",
     "PT20M"
    ]
   }
  },
  {
   "id": "targets_resource_types",
   "kind": "all_of",
   "tier": "core",
   "quote": "target transit gateways, subnets, S3 buckets, and DynamoDB global tables",
   "checks": [
    {
     "kind": "attr",
     "select": "exp",
     "cond": {
      "path": [
       "Targets",
       "*",
       "ResourceType"
      ],
      "op": "eq",
      "value": "aws:ec2:transit-gateway"
     }
    },
    {
     "kind": "attr",
     "select": "exp",
     "cond": {
      "path": [
       "Targets",
       "*",
       "ResourceType"
      ],
      "op": "eq",
      "value": "aws:ec2:subnet"
     }
    },
    {
     "kind": "attr",
     "select": "exp",
     "cond": {
      "path": [
       "Targets",
       "*",
       "ResourceType"
      ],
      "op": "eq",
      "value": "aws:s3:bucket"
     }
    },
    {
     "kind": "attr",
     "select": "exp",
     "cond": {
      "path": [
       "Targets",
       "*",
       "ResourceType"
      ],
      "op": "eq",
      "value": "aws:dynamodb:global-table"
     }
    }
   ],
   "justify": "FIS resource types for transit gateways, subnets, S3 buckets and DynamoDB global tables"
  },
  {
   "id": "targets_chaos_allowed_tag",
   "kind": "attr",
   "select": "exp",
   "tier": "core",
   "quote": "possess a 'ChaosAllowed' tag set to true",
   "cond": {
    "path": [
     "Targets",
     "*",
     "ResourceTags",
     "ChaosAllowed"
    ],
    "op": "eq",
    "value": "true",
    "every": true
   }
  },
  {
   "id": "experiment_uses_fis_role",
   "kind": "ref",
   "from": "exp",
   "to": "fis_role",
   "tier": "core",
   "quote": "provision all necessary IAM roles and policies to allow FIS to perform these specific actions"
  },
  {
   "id": "perm_tgw",
   "kind": "any_of",
   "tier": "detail",
   "quote": "disrupting transit gateway and route table connectivity",
   "checks": [
    {
     "kind": "attr",
     "select": "fis_role",
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
      "op": "regex",
      "value": "(?i)^(\\*|ec2:\\*|ec2:(Create|Delete|Replace|Associate|Disassociate|Enable|Disable)TransitGateway\\w*)$"
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
        "op": "regex",
        "value": "(?i)^(\\*|ec2:\\*|ec2:(Create|Delete|Replace|Associate|Disassociate|Enable|Disable)TransitGateway\\w*)$"
       }
      ]
     },
     "to": "fis_role"
    },
    {
     "kind": "ref",
     "from": "fis_role",
     "to": {
      "types": [
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
        "op": "regex",
        "value": "(?i)^(\\*|ec2:\\*|ec2:(Create|Delete|Replace|Associate|Disassociate|Enable|Disable)TransitGateway\\w*)$"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "fis_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "(?i)AWSFaultInjectionSimulatorNetworkAccess"
     }
    }
   ],
   "justify": "disrupting transit-gateway connectivity needs a mutating ec2 TransitGateway* permission (any of the route/association/propagation actions)"
  },
  {
   "id": "perm_route_table",
   "kind": "any_of",
   "tier": "detail",
   "quote": "disrupting transit gateway and route table connectivity",
   "checks": [
    {
     "kind": "attr",
     "select": "fis_role",
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
      "op": "regex",
      "value": "(?i)^(\\*|ec2:\\*|ec2:(Create|Delete|Replace)Route(Table)?(Association)?)$"
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
        "op": "regex",
        "value": "(?i)^(\\*|ec2:\\*|ec2:(Create|Delete|Replace)Route(Table)?(Association)?)$"
       }
      ]
     },
     "to": "fis_role"
    },
    {
     "kind": "ref",
     "from": "fis_role",
     "to": {
      "types": [
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
        "op": "regex",
        "value": "(?i)^(\\*|ec2:\\*|ec2:(Create|Delete|Replace)Route(Table)?(Association)?)$"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "fis_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "(?i)AWSFaultInjectionSimulatorNetworkAccess"
     }
    }
   ],
   "justify": "disrupting route-table connectivity needs ec2 route/route-table modification permissions"
  },
  {
   "id": "perm_s3_pause",
   "kind": "any_of",
   "tier": "detail",
   "quote": "pausing S3 and DynamoDB replication",
   "checks": [
    {
     "kind": "attr",
     "select": "fis_role",
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
      "op": "regex",
      "value": "(?i)^(\\*|s3:\\*|s3:PauseReplication|s3:PutReplicationConfiguration)$"
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
        "op": "regex",
        "value": "(?i)^(\\*|s3:\\*|s3:PauseReplication|s3:PutReplicationConfiguration)$"
       }
      ]
     },
     "to": "fis_role"
    },
    {
     "kind": "ref",
     "from": "fis_role",
     "to": {
      "types": [
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
        "op": "regex",
        "value": "(?i)^(\\*|s3:\\*|s3:PauseReplication|s3:PutReplicationConfiguration)$"
       }
      ]
     }
    }
   ],
   "justify": "pausing S3 replication needs s3:PauseReplication or s3:PutReplicationConfiguration"
  },
  {
   "id": "perm_ddb_pause",
   "kind": "any_of",
   "tier": "detail",
   "quote": "pausing S3 and DynamoDB replication",
   "checks": [
    {
     "kind": "attr",
     "select": "fis_role",
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
      "op": "regex",
      "value": "(?i)^(\\*|dynamodb:\\*|dynamodb:PutResourcePolicy|dynamodb:Update(Global)?Table\\w*)$"
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
        "op": "regex",
        "value": "(?i)^(\\*|dynamodb:\\*|dynamodb:PutResourcePolicy|dynamodb:Update(Global)?Table\\w*)$"
       }
      ]
     },
     "to": "fis_role"
    },
    {
     "kind": "ref",
     "from": "fis_role",
     "to": {
      "types": [
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
        "op": "regex",
        "value": "(?i)^(\\*|dynamodb:\\*|dynamodb:PutResourcePolicy|dynamodb:Update(Global)?Table\\w*)$"
       }
      ]
     }
    }
   ],
   "justify": "pausing DynamoDB global-table replication needs a mutating dynamodb permission (resource policy or table/global-table update)"
  },
  {
   "id": "log_group_kms_key",
   "kind": "ref",
   "from": "lg",
   "to": "key",
   "tier": "core",
   "quote": "a CloudWatch log group encrypted with a dedicated KMS key"
  },
  {
   "id": "experiment_logs_to_log_group",
   "kind": "ref",
   "from": "exp",
   "to": "lg",
   "tier": "detail",
   "quote": "for experiment logging"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
