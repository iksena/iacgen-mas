package intent.cfn.row_075

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
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
  "lam_role": {
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
     "value": "lambda.amazonaws.com"
    }
   ]
  },
  "doc": {
   "types": [
    "AWS::SSM::Document"
   ],
   "where": []
  },
  "fn": {
   "types": [
    "AWS::Lambda::Function"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "ssm_role",
   "kind": "exists",
   "tier": "core",
   "quote": "an IAM role for Systems Manager (SSM) with broad access across RDS, Route 53 Application Recovery Controller (ARC), Secrets Manager, and SSM",
   "select": "ssm_role"
  },
  {
   "id": "ssm_rds",
   "kind": "any_of",
   "tier": "core",
   "quote": "broad access across RDS",
   "justify": "RDS access has to cover the global cluster failover the document performs",
   "checks": [
    {
     "kind": "ref",
     "bidirectional": true,
     "to": "ssm_role",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::RolePolicy"
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
        "value": "rds:FailoverGlobalCluster"
       }
      ]
     }
    },
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
      "value": "rds:FailoverGlobalCluster"
     }
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
      "value": "AmazonRDSFullAccess"
     }
    }
   ]
  },
  {
   "id": "ssm_arc",
   "kind": "any_of",
   "tier": "core",
   "quote": "Route 53 Application Recovery Controller (ARC)",
   "justify": "any route53-recovery service action is ARC access",
   "checks": [
    {
     "kind": "ref",
     "bidirectional": true,
     "to": "ssm_role",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::RolePolicy"
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
        "value": "(?i)^(route53-recovery-[a-z-]+:.*|\\*)$"
       }
      ]
     }
    },
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
      "op": "regex",
      "value": "(?i)^(route53-recovery-[a-z-]+:.*|\\*)$"
     }
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
      "value": "Route53RecoveryCluster|Route53RecoveryControlConfig"
     }
    }
   ]
  },
  {
   "id": "ssm_secrets",
   "kind": "any_of",
   "tier": "core",
   "quote": "Secrets Manager",
   "justify": "updating a secret is what the document does",
   "checks": [
    {
     "kind": "ref",
     "bidirectional": true,
     "to": "ssm_role",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::RolePolicy"
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
        "value": "secretsmanager:UpdateSecret"
       }
      ]
     }
    },
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
      "value": "secretsmanager:UpdateSecret"
     }
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
      "value": "SecretsManagerReadWrite"
     }
    },
    {
     "kind": "ref",
     "bidirectional": true,
     "to": "ssm_role",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::RolePolicy"
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
        "value": "secretsmanager:PutSecretValue"
       }
      ]
     }
    },
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
      "value": "secretsmanager:PutSecretValue"
     }
    }
   ]
  },
  {
   "id": "ssm_ssm",
   "kind": "any_of",
   "tier": "core",
   "quote": "and SSM",
   "justify": "any SSM action counts as SSM access",
   "checks": [
    {
     "kind": "ref",
     "bidirectional": true,
     "to": "ssm_role",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::RolePolicy"
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
        "value": "(?i)^(ssm:.*|\\*)$"
       }
      ]
     }
    },
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
      "op": "regex",
      "value": "(?i)^(ssm:.*|\\*)$"
     }
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
      "value": "AmazonSSM"
     }
    }
   ]
  },
  {
   "id": "lambda_role",
   "kind": "exists",
   "tier": "core",
   "quote": "an IAM role for a Lambda function allowing it to start and monitor SSM automation executions",
   "select": "lam_role"
  },
  {
   "id": "lam_start",
   "kind": "any_of",
   "tier": "core",
   "quote": "start and monitor SSM automation executions",
   "justify": "start automation executions",
   "checks": [
    {
     "kind": "ref",
     "bidirectional": true,
     "to": "lam_role",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::RolePolicy"
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
     }
    },
    {
     "kind": "attr",
     "select": "lam_role",
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
    }
   ]
  },
  {
   "id": "lam_get",
   "kind": "any_of",
   "tier": "core",
   "quote": "start and monitor SSM automation executions",
   "justify": "monitor automation executions",
   "checks": [
    {
     "kind": "ref",
     "bidirectional": true,
     "to": "lam_role",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::RolePolicy"
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
        "value": "ssm:GetAutomationExecution"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "lam_role",
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
      "value": "ssm:GetAutomationExecution"
     }
    },
    {
     "kind": "ref",
     "bidirectional": true,
     "to": "lam_role",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::RolePolicy"
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
        "value": "ssm:DescribeAutomationExecutions"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "lam_role",
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
      "value": "ssm:DescribeAutomationExecutions"
     }
    }
   ]
  },
  {
   "id": "doc_name",
   "kind": "attr",
   "tier": "core",
   "quote": "named 'AuroraGlobalDatabaseFailoverSSMDocument'",
   "select": "doc",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "eq",
    "value": "AuroraGlobalDatabaseFailoverSSMDocument"
   }
  },
  {
   "id": "doc_automation",
   "kind": "attr",
   "tier": "core",
   "quote": "Create an SSM Automation document",
   "select": "doc",
   "cond": {
    "path": [
     "DocumentType"
    ],
    "op": "eq",
    "value": "Automation"
   }
  },
  {
   "id": "doc_params",
   "kind": "all_of",
   "tier": "core",
   "quote": "accepts a primary region (defaulting to us-east-1) and a secondary region parameter",
   "checks": [
    {
     "kind": "attr",
     "select": "doc",
     "cond": {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?is)\\bparameters\"?\\s*:.*primary.{0,200}us-east-1"
     }
    },
    {
     "kind": "attr",
     "select": "doc",
     "cond": {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?is)\\bparameters\"?\\s*:.*secondary"
     }
    }
   ]
  },
  {
   "id": "doc_three_scripts",
   "kind": "attr",
   "tier": "core",
   "quote": "three Python-based script steps",
   "justify": "three script steps",
   "select": "doc",
   "cond": {
    "path": [
     "Content"
    ],
    "op": "regex",
    "value": "(?s)(aws:executeScript.*){3}"
   }
  },
  {
   "id": "doc_python",
   "kind": "attr",
   "tier": "core",
   "quote": "Python-based script steps",
   "select": "doc",
   "cond": {
    "path": [
     "Content"
    ],
    "op": "regex",
    "value": "(?i)python3"
   }
  },
  {
   "id": "doc_arc_step",
   "kind": "attr",
   "tier": "core",
   "quote": "one to determine the active region by reading ARC routing control parameters",
   "select": "doc",
   "cond": {
    "path": [
     "Content"
    ],
    "op": "regex",
    "value": "(?i)get_?routing_?control_?state|list_?routing_?controls|describe_?routing_?control|get_?parameter"
   }
  },
  {
   "id": "doc_failover_step",
   "kind": "attr",
   "tier": "core",
   "quote": "one to perform the global cluster failover",
   "select": "doc",
   "cond": {
    "path": [
     "Content"
    ],
    "op": "regex",
    "value": "(?i)failover_?global_?cluster"
   }
  },
  {
   "id": "doc_flip_secret",
   "kind": "attr",
   "tier": "core",
   "quote": "update a Secrets Manager secret with the new writer endpoint",
   "select": "doc",
   "cond": {
    "path": [
     "Content"
    ],
    "op": "regex",
    "value": "(?i)update_?secret|put_?secret_?value"
   }
  },
  {
   "id": "doc_flip_routing",
   "kind": "attr",
   "tier": "core",
   "quote": "flip the ARC routing control states",
   "select": "doc",
   "cond": {
    "path": [
     "Content"
    ],
    "op": "regex",
    "value": "(?i)update_?routing_?control_?state"
   }
  },
  {
   "id": "fn_exists",
   "kind": "exists",
   "tier": "core",
   "quote": "provision a Python 3.13 Lambda function named 'TriggerFailover'",
   "select": "fn"
  },
  {
   "id": "fn_runtime",
   "kind": "attr",
   "tier": "core",
   "quote": "Python 3.13 Lambda function",
   "select": "fn",
   "cond": {
    "path": [
     "Runtime"
    ],
    "op": "eq",
    "value": "python3.13"
   }
  },
  {
   "id": "fn_name",
   "kind": "attr",
   "tier": "core",
   "quote": "named 'TriggerFailover'",
   "select": "fn",
   "cond": {
    "path": [
     "FunctionName"
    ],
    "op": "eq",
    "value": "TriggerFailover"
   }
  },
  {
   "id": "fn_role",
   "kind": "ref",
   "tier": "detail",
   "quote": "an IAM role for a Lambda function",
   "from": "fn",
   "to": "lam_role"
  },
  {
   "id": "fn_starts",
   "kind": "attr",
   "tier": "core",
   "quote": "initiates this SSM automation execution when invoked",
   "select": "fn",
   "cond": {
    "path": [
     "Code",
     "ZipFile"
    ],
    "op": "regex",
    "value": "(?i)start_?automation_?execution"
   }
  },
  {
   "id": "fn_targets_doc",
   "kind": "any_of",
   "tier": "detail",
   "quote": "initiates this SSM automation execution when invoked",
   "checks": [
    {
     "kind": "ref",
     "from": "fn",
     "to": "doc"
    },
    {
     "kind": "attr",
     "select": "fn",
     "cond": {
      "path": [],
      "op": "contains",
      "value": "AuroraGlobalDatabaseFailoverSSMDocument"
     }
    }
   ]
  },
  {
   "id": "x_doc_role",
   "kind": "ref",
   "tier": "extra",
   "from": "doc",
   "to": "ssm_role"
  },
  {
   "id": "x_schema",
   "kind": "attr",
   "tier": "extra",
   "select": "doc",
   "cond": {
    "path": [
     "Content"
    ],
    "op": "regex",
    "value": "0\\.3"
   }
  },
  {
   "id": "x_lambda_basic",
   "kind": "any_of",
   "tier": "extra",
   "checks": [
    {
     "kind": "attr",
     "select": "lam_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "contains",
      "value": "AWSLambdaBasicExecutionRole"
     }
    },
    {
     "kind": "attr",
     "select": "lam_role",
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
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
