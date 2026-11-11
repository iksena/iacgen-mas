package intent.cfn.row_061

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "rule": {
   "types": [
    "AWS::Events::Rule"
   ],
   "where": []
  },
  "roles": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "events_role": {
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
     "value": "events.amazonaws.com"
    }
   ]
  },
  "ssm_role": {
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
     "value": "ssm.amazonaws.com"
    }
   ]
  },
  "pol": {
   "types": [
    "AWS::IAM::Policy",
    "AWS::IAM::ManagedPolicy"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "rule",
   "kind": "exists",
   "select": "rule",
   "tier": "core",
   "quote": "via an EventBridge rule"
  },
  {
   "id": "disable_imdsv1",
   "kind": "attr",
   "select": "rule",
   "cond": {
    "path": [
     "Targets"
    ],
    "op": "regex",
    "value": "(?i)(EnforceIMDSv2|HttpTokens)[^a-z0-9]{0,12}required"
   },
   "tier": "core",
   "quote": "automatically disable IMDSv1",
   "justify": "disabling IMDSv1 means requiring session tokens (IMDSv2), passed to the automation as EnforceIMDSv2 or HttpTokens = required"
  },
  {
   "id": "rule_ec2_state_change",
   "kind": "attr",
   "select": "rule",
   "cond": {
    "path": [
     "EventPattern",
     "detail-type",
     "*"
    ],
    "op": "regex",
    "value": "(?i)ec2 instance state-change notification"
   },
   "tier": "core",
   "quote": "only trigger on EC2 state-change notifications"
  },
  {
   "id": "rule_running",
   "kind": "attr",
   "select": "rule",
   "cond": {
    "path": [
     "EventPattern",
     "detail",
     "state",
     "*"
    ],
    "op": "eq",
    "value": "running"
   },
   "tier": "core",
   "quote": "when the instance enters the running state"
  },
  {
   "id": "target_automation_doc",
   "kind": "attr",
   "select": "rule",
   "cond": {
    "path": [
     "Targets",
     "*",
     "Arn"
    ],
    "op": "contains",
    "value": "AWSSupport-ConfigureEC2Metadata"
   },
   "tier": "core",
   "quote": "triggering the AWSSupport-ConfigureEC2Metadata Systems Manager automation document"
  },
  {
   "id": "target_instance_id",
   "kind": "any_of",
   "tier": "core",
   "quote": "its target should pass the instance ID",
   "checks": [
    {
     "kind": "attr",
     "select": "rule",
     "cond": {
      "path": [
       "Targets",
       "*",
       "InputTransformer",
       "InputPathsMap"
      ],
      "op": "regex",
      "value": "\\$\\.detail\\.instance-id"
     }
    },
    {
     "kind": "attr",
     "select": "rule",
     "cond": {
      "path": [
       "Targets",
       "*",
       "InputPath"
      ],
      "op": "regex",
      "value": "^\\$\\.detail"
     }
    }
   ],
   "justify": "EventBridge passes an event value through InputPathsMap or InputPath; the instance ID is at detail.instance-id"
  },
  {
   "id": "target_hop_limit",
   "kind": "attr",
   "select": "rule",
   "cond": {
    "path": [
     "Targets"
    ],
    "op": "contains",
    "value": "HttpPutResponseHopLimit"
   },
   "tier": "detail",
   "quote": "a configurable parameter for the HTTP PUT response hop limit"
  },
  {
   "id": "param_hop_default",
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
      "op": "eq",
      "value": 1
     }
    ]
   },
   "tier": "core",
   "quote": "which should default to 1",
   "justify": "'default to 1' = default value 1"
  },
  {
   "id": "roles_two",
   "kind": "exists",
   "select": "roles",
   "tier": "core",
   "quote": "The stack should include the necessary IAM roles",
   "min": 2,
   "justify": "two roles are described: one for EventBridge and one for the automation"
  },
  {
   "id": "events_role",
   "kind": "exists",
   "select": "events_role",
   "tier": "core",
   "quote": "one that allows EventBridge to assume a role to start the automation"
  },
  {
   "id": "ssm_role",
   "kind": "exists",
   "select": "ssm_role",
   "tier": "core",
   "quote": "another that the automation itself uses to describe instances and modify their metadata options",
   "justify": "an SSM automation role is assumed by ssm.amazonaws.com"
  },
  {
   "id": "rule_uses_events_role",
   "kind": "ref",
   "from": {
    "types": [
     "AWS::Events::Rule"
    ],
    "where": []
   },
   "to": "events_role",
   "tier": "detail",
   "quote": "one that allows EventBridge to assume a role to start the automation"
  },
  {
   "id": "rule_passes_ssm_role",
   "kind": "ref",
   "from": {
    "types": [
     "AWS::Events::Rule"
    ],
    "where": []
   },
   "to": "ssm_role",
   "tier": "detail",
   "quote": "another that the automation itself uses",
   "justify": "an SSM automation role is assumed by ssm.amazonaws.com"
  },
  {
   "id": "events_start_automation",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "events_role",
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
      "value": "ssm:StartAutomationExecution"
     }
    },
    {
     "kind": "ref",
     "bidirectional": true,
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
        "value": "ssm:StartAutomationExecution"
       }
      ]
     },
     "to": "events_role"
    }
   ],
   "tier": "detail",
   "quote": "one that allows EventBridge to assume a role to start the automation"
  },
  {
   "id": "ssm_describe_instances",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "ssm_role",
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
      "value": "ec2:DescribeInstances"
     }
    },
    {
     "kind": "ref",
     "bidirectional": true,
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
        "value": "ec2:DescribeInstances"
       }
      ]
     },
     "to": "ssm_role"
    },
    {
     "kind": "attr",
     "select": "ssm_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "AmazonSSMAutomationRole"
     }
    }
   ],
   "tier": "core",
   "quote": "describe instances",
   "justify": "the automation role is the one assumed by ssm.amazonaws.com"
  },
  {
   "id": "ssm_modify_metadata",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "ssm_role",
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
      "value": "ec2:ModifyInstanceMetadataOptions"
     }
    },
    {
     "kind": "ref",
     "bidirectional": true,
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
        "value": "ec2:ModifyInstanceMetadataOptions"
       }
      ]
     },
     "to": "ssm_role"
    },
    {
     "kind": "attr",
     "select": "ssm_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "AmazonSSMAutomationRole"
     }
    }
   ],
   "tier": "core",
   "quote": "modify their metadata options",
   "justify": "the automation role is the one assumed by ssm.amazonaws.com"
  },
  {
   "id": "x_passrole",
   "kind": "any_of",
   "tier": "extra",
   "checks": [
    {
     "kind": "attr",
     "select": "events_role",
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
      "value": "iam:PassRole"
     }
    },
    {
     "kind": "ref",
     "bidirectional": true,
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
        "value": "iam:PassRole"
       }
      ]
     },
     "to": "events_role"
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
