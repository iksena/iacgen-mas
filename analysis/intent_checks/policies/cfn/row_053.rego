package intent.cfn.row_053

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
  "role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "rule": {
   "types": [
    "AWS::Events::Rule"
   ],
   "where": []
  },
  "iam": {
   "types": [
    "AWS::IAM::Role",
    "AWS::IAM::Policy",
    "AWS::IAM::ManagedPolicy"
   ],
   "where": []
  },
  "perm": {
   "types": [
    "AWS::Lambda::Permission"
   ],
   "where": []
  },
  "lambda_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "regex",
     "value": "lambda\\.amazonaws\\.com"
    }
   ]
  },
  "perm_events": {
   "types": [
    "AWS::Lambda::Permission"
   ],
   "where": [
    {
     "path": [
      "Principal"
     ],
     "op": "eq",
     "value": "events.amazonaws.com"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "lambda",
   "kind": "exists",
   "tier": "core",
   "quote": "creates a Lambda function",
   "select": "fn"
  },
  {
   "id": "python",
   "kind": "attr",
   "tier": "core",
   "quote": "written in Python",
   "select": "fn",
   "cond": {
    "path": [
     "Runtime"
    ],
    "op": "regex",
    "value": "^python"
   }
  },
  {
   "id": "logs_time",
   "kind": "attr",
   "tier": "detail",
   "quote": "logs the current time to CloudWatch Logs",
   "justify": "logging the current time means reading a clock in code",
   "select": "fn",
   "cond": {
    "path": [
     "Code",
     "ZipFile"
    ],
    "op": "regex",
    "value": "(?i)(datetime|time\\.|strftime|isoformat|now\\()"
   }
  },
  {
   "id": "event_rule",
   "kind": "exists",
   "tier": "core",
   "quote": "triggered every 5 minutes by a CloudWatch Events rule",
   "select": "rule"
  },
  {
   "id": "rate_5_min",
   "kind": "attr",
   "tier": "core",
   "quote": "using a rate expression",
   "justify": "every 5 minutes as a rate expression",
   "select": "rule",
   "cond": {
    "path": [
     "ScheduleExpression"
    ],
    "op": "regex",
    "value": "(?i)^rate\\(\\s*5\\s+minutes?\\s*\\)$"
   }
  },
  {
   "id": "rule_targets_fn",
   "kind": "any_of",
   "tier": "core",
   "quote": "triggered every 5 minutes by a CloudWatch Events rule",
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
      "op": "regex",
      "value": ":function:"
     }
    }
   ],
   "justify": "a literal target ARN names a Lambda function by its :function: segment"
  },
  {
   "id": "role",
   "kind": "exists",
   "tier": "core",
   "quote": "including the necessary IAM role for logging",
   "select": "role"
  },
  {
   "id": "fn_uses_role",
   "kind": "ref",
   "tier": "detail",
   "quote": "including the necessary IAM role for logging",
   "from": "fn",
   "to": "role"
  },
  {
   "id": "role_logging",
   "kind": "any_of",
   "tier": "core",
   "quote": "necessary IAM role for logging",
   "justify": "logging needs logs:PutLogEvents, which a wider logs grant or a logging managed policy includes",
   "checks": [
    {
     "kind": "ref",
     "from": "fn",
     "to": {
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
           "Effect"
          ],
          "op": "eq",
          "value": "Allow"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "glob_covers",
          "value": "logs:PutLogEvents"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "fn",
     "to": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": [
       {
        "path": [
         "ManagedPolicyArns",
         "*"
        ],
        "op": "regex",
        "value": "(?i)(AWSLambdaBasicExecutionRole|AWSLambdaVPCAccessExecutionRole|AWSLambdaExecute|CloudWatchLogsFullAccess|AdministratorAccess)"
       }
      ]
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
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "Effect"
          ],
          "op": "eq",
          "value": "Allow"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "glob_covers",
          "value": "logs:PutLogEvents"
         }
        ]
       }
      ]
     },
     "to": "lambda_role",
     "bidirectional": true
    }
   ]
  },
  {
   "id": "invoke_permission",
   "kind": "attr",
   "tier": "core",
   "quote": "grant the required permissions for the event rule to invoke the function",
   "justify": "EventBridge/CloudWatch Events principal",
   "select": "perm",
   "cond": {
    "path": [
     "Principal"
    ],
    "op": "eq",
    "value": "events.amazonaws.com"
   }
  },
  {
   "id": "invoke_action",
   "kind": "attr",
   "tier": "detail",
   "quote": "to invoke the function",
   "justify": "invoking a function is lambda:InvokeFunction",
   "select": "perm_events",
   "cond": {
    "path": [
     "Action"
    ],
    "op": "glob_covers",
    "value": "lambda:InvokeFunction"
   }
  },
  {
   "id": "permission_for_fn",
   "kind": "ref",
   "tier": "detail",
   "quote": "grant the required permissions for the event rule to invoke the function",
   "from": "perm_events",
   "to": "fn"
  },
  {
   "id": "x_permission_source_rule",
   "kind": "ref",
   "tier": "extra",
   "from": "perm_events",
   "to": "rule"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
