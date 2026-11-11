package intent.cfn.row_035

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "user": {
   "types": [
    "AWS::IAM::User"
   ],
   "where": []
  },
  "group": {
   "types": [
    "AWS::IAM::Group"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "user",
   "kind": "exists",
   "select": "user",
   "tier": "core",
   "quote": "creates an IAM user"
  },
  {
   "id": "group",
   "kind": "exists",
   "select": "group",
   "tier": "core",
   "quote": "an IAM group"
  },
  {
   "id": "user_in_group",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "user",
     "to": "group"
    },
    {
     "kind": "join",
     "from": "user",
     "from_path": [
      "Groups",
      "*"
     ],
     "to": "group",
     "to_path": [
      "GroupName"
     ]
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::UserToGroupAddition"
      ],
      "where": [
       {
        "path": [
         "Users",
         "*"
        ],
        "op": "present"
       }
      ]
     },
     "to": "group"
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "AWS::IAM::UserToGroupAddition"
      ],
      "where": [
       {
        "path": [
         "Users",
         "*"
        ],
        "op": "present"
       }
      ]
     },
     "from_path": [
      "GroupName"
     ],
     "to": "group",
     "to_path": [
      "GroupName"
     ]
    }
   ],
   "tier": "core",
   "quote": "where the user is added to the group"
  },
  {
   "id": "policy_attached_to_group",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": []
     },
     "to": "group",
     "bidirectional": true
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": []
     },
     "from_path": [
      "Groups",
      "*"
     ],
     "to": "group",
     "to_path": [
      "GroupName"
     ]
    },
    {
     "kind": "attr",
     "select": "group",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument"
      ],
      "op": "present"
     }
    }
   ],
   "tier": "core",
   "quote": "the group is attached to a policy"
  },
  {
   "id": "act_create_log_group",
   "kind": "any_of",
   "checks": [
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
          "value": "logs:CreateLogGroup"
         }
        ]
       }
      ]
     },
     "to": "group",
     "bidirectional": true
    },
    {
     "kind": "join",
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
          "value": "logs:CreateLogGroup"
         }
        ]
       }
      ]
     },
     "from_path": [
      "Groups",
      "*"
     ],
     "to": "group",
     "to_path": [
      "GroupName"
     ]
    },
    {
     "kind": "attr",
     "select": "group",
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
        "value": "logs:CreateLogGroup"
       }
      ]
     }
    }
   ],
   "tier": "core",
   "quote": "granting permissions to create log groups, log streams, and put log events in CloudWatch Logs"
  },
  {
   "id": "act_create_log_stream",
   "kind": "any_of",
   "checks": [
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
          "value": "logs:CreateLogStream"
         }
        ]
       }
      ]
     },
     "to": "group",
     "bidirectional": true
    },
    {
     "kind": "join",
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
          "value": "logs:CreateLogStream"
         }
        ]
       }
      ]
     },
     "from_path": [
      "Groups",
      "*"
     ],
     "to": "group",
     "to_path": [
      "GroupName"
     ]
    },
    {
     "kind": "attr",
     "select": "group",
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
        "value": "logs:CreateLogStream"
       }
      ]
     }
    }
   ],
   "tier": "core",
   "quote": "granting permissions to create log groups, log streams, and put log events in CloudWatch Logs"
  },
  {
   "id": "act_put_log_events",
   "kind": "any_of",
   "checks": [
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
     "to": "group",
     "bidirectional": true
    },
    {
     "kind": "join",
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
     "from_path": [
      "Groups",
      "*"
     ],
     "to": "group",
     "to_path": [
      "GroupName"
     ]
    },
    {
     "kind": "attr",
     "select": "group",
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
    }
   ],
   "tier": "core",
   "quote": "granting permissions to create log groups, log streams, and put log events in CloudWatch Logs"
  },
  {
   "id": "act_put_metric",
   "kind": "any_of",
   "checks": [
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
          "value": "cloudwatch:PutMetricData"
         }
        ]
       }
      ]
     },
     "to": "group",
     "bidirectional": true
    },
    {
     "kind": "join",
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
          "value": "cloudwatch:PutMetricData"
         }
        ]
       }
      ]
     },
     "from_path": [
      "Groups",
      "*"
     ],
     "to": "group",
     "to_path": [
      "GroupName"
     ]
    },
    {
     "kind": "attr",
     "select": "group",
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
        "value": "cloudwatch:PutMetricData"
       }
      ]
     }
    }
   ],
   "tier": "core",
   "quote": "as well as put and list CloudWatch metrics and get metric data"
  },
  {
   "id": "act_list_metrics",
   "kind": "any_of",
   "checks": [
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
          "value": "cloudwatch:ListMetrics"
         }
        ]
       }
      ]
     },
     "to": "group",
     "bidirectional": true
    },
    {
     "kind": "join",
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
          "value": "cloudwatch:ListMetrics"
         }
        ]
       }
      ]
     },
     "from_path": [
      "Groups",
      "*"
     ],
     "to": "group",
     "to_path": [
      "GroupName"
     ]
    },
    {
     "kind": "attr",
     "select": "group",
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
        "value": "cloudwatch:ListMetrics"
       }
      ]
     }
    }
   ],
   "tier": "core",
   "quote": "as well as put and list CloudWatch metrics and get metric data"
  },
  {
   "id": "act_get_metric",
   "kind": "any_of",
   "checks": [
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
          "value": "cloudwatch:GetMetricData"
         }
        ]
       }
      ]
     },
     "to": "group",
     "bidirectional": true
    },
    {
     "kind": "join",
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
          "value": "cloudwatch:GetMetricData"
         }
        ]
       }
      ]
     },
     "from_path": [
      "Groups",
      "*"
     ],
     "to": "group",
     "to_path": [
      "GroupName"
     ]
    },
    {
     "kind": "attr",
     "select": "group",
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
        "value": "cloudwatch:GetMetricData"
       }
      ]
     }
    }
   ],
   "tier": "core",
   "quote": "as well as put and list CloudWatch metrics and get metric data"
  },
  {
   "id": "resource_all",
   "kind": "any_of",
   "checks": [
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
         "Resource",
         "*"
        ],
        "op": "eq",
        "value": "*",
        "every": true
       }
      ]
     },
     "to": "group",
     "bidirectional": true
    },
    {
     "kind": "join",
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
         "Resource",
         "*"
        ],
        "op": "eq",
        "value": "*",
        "every": true
       }
      ]
     },
     "from_path": [
      "Groups",
      "*"
     ],
     "to": "group",
     "to_path": [
      "GroupName"
     ]
    },
    {
     "kind": "attr",
     "select": "group",
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
      "op": "eq",
      "value": "*",
      "every": true
     }
    }
   ],
   "tier": "core",
   "quote": "with the policy allowing all resources for these actions",
   "justify": "all resources means Resource '*'"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
