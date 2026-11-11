package intent.cfn.row_063

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "fn": {
   "types": [
    "AWS::Lambda::Function"
   ],
   "where": []
  },
  "lg": {
   "types": [
    "AWS::Logs::LogGroup"
   ],
   "where": []
  },
  "rule": {
   "types": [
    "AWS::Events::Rule",
    "AWS::Scheduler::Schedule"
   ],
   "where": []
  },
  "role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "pol": {
   "types": [
    "AWS::IAM::Policy",
    "AWS::IAM::ManagedPolicy",
    "AWS::IAM::RolePolicy"
   ],
   "where": []
  },
  "decl_sched": {
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
      "AWS::Events::Rule",
      "AWS::Scheduler::Schedule"
     ]
    }
   ]
  },
  "rule_on": {
   "types": [
    "AWS::Events::Rule",
    "AWS::Scheduler::Schedule"
   ],
   "where": [
    {
     "path": [
      "State"
     ],
     "op": "none_eq",
     "value": "DISABLED"
    }
   ]
  },
  "lg30": {
   "types": [
    "AWS::Logs::LogGroup"
   ],
   "where": [
    {
     "path": [
      "RetentionInDays"
     ],
     "op": "eq",
     "value": 30
    }
   ]
  }
 },
 "checks": [
  {
   "id": "lambda",
   "kind": "exists",
   "select": "fn",
   "tier": "core",
   "quote": "creates a scheduled Lambda function"
  },
  {
   "id": "lambda_name",
   "kind": "attr",
   "select": "fn",
   "cond": {
    "path": [
     "FunctionName"
    ],
    "op": "eq",
    "value": "DynamoDBCleanupFunction"
   },
   "tier": "core",
   "quote": "with the Lambda named \"DynamoDBCleanupFunction\""
  },
  {
   "id": "runtime",
   "kind": "attr",
   "select": "fn",
   "cond": {
    "path": [
     "Runtime"
    ],
    "op": "eq",
    "value": "python3.12"
   },
   "tier": "core",
   "quote": "using Python 3.12 runtime"
  },
  {
   "id": "timeout",
   "kind": "attr",
   "select": "fn",
   "cond": {
    "path": [
     "Timeout"
    ],
    "op": "eq",
    "value": 300
   },
   "tier": "core",
   "quote": "with a 5-minute timeout",
   "justify": "5 minutes = 300 seconds"
  },
  {
   "id": "hourly_schedule",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "rule_on",
     "cond": {
      "path": [
       "ScheduleExpression"
      ],
      "op": "regex",
      "value": "(?i)^\\s*(rate\\(\\s*1\\s+hour\\s*\\)|rate\\(\\s*60\\s+minutes\\s*\\)|cron\\(\\s*0\\s+(\\*|0/1|\\*/1)\\s+(\\*\\s+\\*\\s+\\?|\\?\\s+\\*\\s+\\*)\\s+\\*\\s*\\))\\s*$"
     }
    }
   ],
   "tier": "core",
   "quote": "triggered every hour by default",
   "justify": "every hour = rate(1 hour) or an hourly cron"
  },
  {
   "id": "schedule_targets_fn",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "rule",
     "to": "fn"
    },
    {
     "kind": "attr",
     "select": "rule",
     "cond": {
      "path": [
       "Targets",
       "*",
       "Arn"
      ],
      "op": "contains",
      "value": "DynamoDBCleanupFunction"
     }
    },
    {
     "kind": "attr",
     "select": "rule",
     "cond": {
      "path": [
       "Target",
       "Arn"
      ],
      "op": "contains",
      "value": "DynamoDBCleanupFunction"
     }
    }
   ],
   "tier": "core",
   "quote": "the function should be triggered every hour by default"
  },
  {
   "id": "schedule_optional",
   "kind": "attr",
   "select": "decl_sched",
   "cond": {
    "path": [
     "gated"
    ],
    "op": "truthy"
   },
   "tier": "detail",
   "quote": "allow the schedule to be disabled by passing an empty string",
   "justify": "disabling by an empty string means the schedule resources are conditional"
  },
  {
   "id": "schedule_param_default",
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
      "value": "(?i)^\\s*(rate\\(\\s*1\\s+hour\\s*\\)|rate\\(\\s*60\\s+minutes\\s*\\)|cron\\(\\s*0\\s+(\\*|0/1|\\*/1)\\s+(\\*\\s+\\*\\s+\\?|\\?\\s+\\*\\s+\\*)\\s+\\*\\s*\\))\\s*$"
     }
    ]
   },
   "tier": "detail",
   "quote": "triggered every hour by default but allow the schedule to be disabled by passing an empty string",
   "justify": "passing an empty string means the schedule is a parameter whose default is the hourly expression"
  },
  {
   "id": "log_retention",
   "kind": "attr",
   "select": "lg",
   "cond": {
    "path": [
     "RetentionInDays"
    ],
    "op": "eq",
    "value": 30
   },
   "tier": "core",
   "quote": "logs retained for 30 days"
  },
  {
   "id": "log_group_is_fn",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "lg30",
     "cond": {
      "path": [
       "LogGroupName"
      ],
      "op": "contains",
      "value": "/aws/lambda/DynamoDBCleanupFunction"
     }
    },
    {
     "kind": "ref",
     "from": "fn",
     "to": "lg30",
     "bidirectional": true
    }
   ],
   "tier": "detail",
   "quote": "logs retained for 30 days"
  },
  {
   "id": "table_throttle",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "fn",
     "cond": {
      "path": [
       "Environment"
      ],
      "op": "regex",
      "value": "\\bthrottle\\b"
     }
    },
    {
     "kind": "attr",
     "select": "fn",
     "cond": {
      "path": [
       "Code",
       "ZipFile"
      ],
      "op": "regex",
      "value": "\\bthrottle\\b"
     }
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*",
       "Resource",
       "*"
      ],
      "op": "contains",
      "value": "table/throttle"
     }
    },
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*",
       "Resource",
       "*"
      ],
      "op": "contains",
      "value": "table/throttle"
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::DynamoDB::Table"
      ],
      "where": [
       {
        "path": [
         "TableName"
        ],
        "op": "eq",
        "value": "throttle"
       }
      ]
     }
    }
   ],
   "tier": "core",
   "quote": "clean up old items from a DynamoDB table named \"throttle\""
  },
  {
   "id": "scan_permission",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
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
      "value": "dynamodb:Scan"
     }
    },
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "dynamodb:Scan"
     }
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "AmazonDynamoDBFullAccess$"
     }
    }
   ],
   "tier": "detail",
   "quote": "by scanning for expired records based on the range key"
  },
  {
   "id": "delete_permission",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
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
      "value": "dynamodb:BatchWriteItem"
     }
    },
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "dynamodb:BatchWriteItem"
     }
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "AmazonDynamoDBFullAccess$"
     }
    }
   ],
   "tier": "detail",
   "quote": "deleting them in batches",
   "justify": "batch deletes go through the DynamoDB BatchWriteItem action"
  },
  {
   "id": "x_fn_role",
   "kind": "ref",
   "tier": "extra",
   "from": "fn",
   "to": "role"
  },
  {
   "id": "x_role_lambda_trust",
   "kind": "attr",
   "tier": "extra",
   "select": "role",
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
    "value": "lambda.amazonaws.com"
   }
  },
  {
   "id": "extra_type_aws_lambda_permission",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::Lambda::Permission"
    ],
    "where": []
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
