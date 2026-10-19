package intent.cfn.row_079

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "lg": {
   "types": [
    "AWS::Logs::LogGroup"
   ],
   "where": []
  },
  "role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "flow_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "contains",
     "value": "vpc-flow-logs.amazonaws.com"
    }
   ]
  },
  "auto_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "contains",
     "value": "ssm.amazonaws.com"
    }
   ]
  },
  "iam_any": {
   "types": [
    "AWS::IAM::Role",
    "AWS::IAM::Policy",
    "AWS::IAM::ManagedPolicy"
   ],
   "where": []
  },
  "doc": {
   "types": [
    "AWS::SSM::Document"
   ],
   "where": [
    {
     "path": [
      "DocumentType"
     ],
     "op": "eq",
     "value": "Automation"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "log_group",
   "kind": "exists",
   "select": "lg",
   "tier": "core",
   "quote": "create a CloudWatch Logs log group to receive the flow log data"
  },
  {
   "id": "log_group_long_retention",
   "kind": "attr",
   "select": "lg",
   "cond": {
    "path": [
     "RetentionInDays"
    ],
    "op": "gte",
    "value": 90
   },
   "tier": "detail",
   "quote": "with a long retention period suitable for compliance",
   "justify": "\"long retention suitable for compliance\" -> clearly longer than the short defaults; lenient floor of 90 days"
  },
  {
   "id": "flow_logs_role_trust",
   "kind": "exists",
   "select": "flow_role",
   "tier": "core",
   "quote": "an IAM role that flow logs and the automation can assume"
  },
  {
   "id": "flow_logs_role_write_logs",
   "kind": "any_of",
   "tier": "detail",
   "quote": "to write to that log group",
   "checks": [
    {
     "kind": "attr",
     "select": "flow_role",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*",
       "Action"
      ],
      "op": "glob_covers",
      "value": "logs:PutLogEvents"
     }
    },
    {
     "kind": "attr",
     "select": "flow_role",
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
      "value": "logs:PutLogEvents"
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
         "Action"
        ],
        "op": "glob_covers",
        "value": "logs:PutLogEvents"
       }
      ]
     },
     "to": "flow_role"
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
        "value": "logs:PutLogEvents"
       }
      ]
     },
     "to": "flow_role"
    }
   ]
  },
  {
   "id": "flow_logs_role_manage_ec2_flow_logs",
   "kind": "any_of",
   "tier": "detail",
   "quote": "manage EC2 flow log resources",
   "checks": [
    {
     "kind": "attr",
     "select": "flow_role",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*",
       "Action"
      ],
      "op": "glob_covers",
      "value": "ec2:CreateFlowLogs"
     }
    },
    {
     "kind": "attr",
     "select": "flow_role",
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
      "value": "ec2:CreateFlowLogs"
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
         "Action"
        ],
        "op": "glob_covers",
        "value": "ec2:CreateFlowLogs"
       }
      ]
     },
     "to": "flow_role"
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
        "value": "ec2:CreateFlowLogs"
       }
      ]
     },
     "to": "flow_role"
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*",
       "Action"
      ],
      "op": "glob_covers",
      "value": "ec2:CreateFlowLogs"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": []
     },
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
      "value": "ec2:CreateFlowLogs"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*",
       "Action"
      ],
      "op": "glob_covers",
      "value": "ec2:CreateFlowLogs"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "ec2:CreateFlowLogs"
     }
    }
   ]
  },
  {
   "id": "automation_execution_role",
   "kind": "exists",
   "select": "auto_role",
   "tier": "core",
   "quote": "a separate automation execution role"
  },
  {
   "id": "two_distinct_roles",
   "kind": "exists",
   "select": "role",
   "min": 2,
   "tier": "detail",
   "quote": "a separate automation execution role",
   "justify": "prompt states a flow-log role and a separate automation execution role"
  },
  {
   "id": "automation_documents",
   "kind": "exists",
   "select": "doc",
   "min": 2,
   "tier": "core",
   "quote": "define two SSM Automation documents"
  },
  {
   "id": "doc_enable_flow_logs",
   "kind": "attr",
   "select": "doc",
   "cond": {
    "path": [
     "Content"
    ],
    "op": "regex",
    "value": "(?i)create_?flow_?logs"
   },
   "tier": "core",
   "quote": "directly enables flow logging"
  },
  {
   "id": "doc_reject_traffic",
   "kind": "attr",
   "select": "doc",
   "cond": {
    "path": [
     "Content"
    ],
    "op": "regex",
    "value": "(?i)TrafficType\\\\?['\"]?\\s*[=:]\\s*\\\\?['\"]?REJECT"
   },
   "tier": "core",
   "quote": "capturing rejected traffic"
  },
  {
   "id": "doc_vpc_id_parameter",
   "kind": "attr",
   "select": "doc",
   "cond": {
    "path": [
     "Content"
    ],
    "op": "regex",
    "value": "(?i)vpc_?id"
   },
   "tier": "detail",
   "quote": "one that accepts a VPC ID"
  },
  {
   "id": "doc_python_script",
   "kind": "attr",
   "select": "doc",
   "cond": {
    "path": [
     "Content"
    ],
    "op": "regex",
    "value": "(?i)aws:executeScript(?s:.)*python|python(?s:.)*aws:executeScript"
   },
   "tier": "detail",
   "quote": "by invoking the AWS API from a Python script"
  },
  {
   "id": "doc_change_manager",
   "kind": "any_of",
   "tier": "core",
   "quote": "routes the same request through AWS Systems Manager Change Manager as a formal change request",
   "checks": [
    {
     "kind": "attr",
     "select": "doc",
     "cond": {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)start_?change_?request_?execution"
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::SSM::Document"
      ],
      "where": [
       {
        "path": [
         "DocumentType"
        ],
        "op": "eq",
        "value": "Automation.ChangeTemplate"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "doc_uses_log_group",
   "kind": "ref",
   "from": "doc",
   "to": "lg",
   "tier": "detail",
   "quote": "Using these, it should define two SSM Automation documents"
  },
  {
   "id": "doc_uses_automation_role",
   "kind": "ref",
   "from": "doc",
   "to": "auto_role",
   "tier": "detail",
   "quote": "Using these, it should define two SSM Automation documents"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
