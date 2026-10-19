package intent.cfn.row_166

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "guardduty_enabled",
   "kind": "attr",
   "select": {
    "types": [
     "AWS::GuardDuty::Detector"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "Enable"
    ],
    "op": "truthy"
   },
   "tier": "core",
   "quote": "enable GuardDuty in the region"
  },
  {
   "id": "guardduty_fifteen_minutes",
   "kind": "attr",
   "select": {
    "types": [
     "AWS::GuardDuty::Detector"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "FindingPublishingFrequency"
    ],
    "op": "eq",
    "value": "FIFTEEN_MINUTES"
   },
   "tier": "core",
   "quote": "a finding publishing frequency of fifteen minutes",
   "justify": "fifteen minutes = the FIFTEEN_MINUTES enum"
  },
  {
   "id": "lambda_readonly_role",
   "kind": "any_of",
   "tier": "core",
   "quote": "a Lambda execution role with read-only access for resource discovery",
   "checks": [
    {
     "kind": "attr",
     "select": {
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
        "value": "^lambda\\.amazonaws\\.com$"
       }
      ]
     },
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "(?i)(ReadOnlyAccess|ViewOnlyAccess)$"
     }
    },
    {
     "kind": "attr",
     "select": {
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
        "value": "^lambda\\.amazonaws\\.com$"
       }
      ]
     },
     "cond": {
      "path": [
       "Policies"
      ],
      "op": "regex",
      "value": "(?i)[a-z0-9-]+:(Describe|List|Get)\\*"
     }
    }
   ]
  },
  {
   "id": "lambda_cfn_cloudtrail_role",
   "kind": "any_of",
   "tier": "core",
   "quote": "a Lambda role for getting the caller identity and accessing CloudFormation and CloudTrail logs",
   "checks": [
    {
     "kind": "exists",
     "select": {
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
        "value": "^lambda\\.amazonaws\\.com$"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)cloudformation:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)cloudtrail:[A-Za-z*]"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "bidirectional": true,
     "to": {
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
        "value": "^lambda\\.amazonaws\\.com$"
       }
      ]
     },
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [],
        "op": "regex",
        "value": "(?i)cloudformation:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)cloudtrail:[A-Za-z*]"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "nodegroup_describe_role",
   "kind": "any_of",
   "tier": "core",
   "quote": "a role for describing EKS node groups",
   "checks": [
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
      "value": "eks:DescribeNodegroup"
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
      "value": "eks:DescribeNodegroup"
     }
    }
   ]
  },
  {
   "id": "exec_role_session_8400",
   "kind": "attr",
   "select": {
    "types": [
     "AWS::IAM::Role"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "MaxSessionDuration"
    ],
    "op": "eq",
    "value": 8400
   },
   "tier": "core",
   "quote": "a CloudFormation execution role with a maximum session duration of 8400 seconds"
  },
  {
   "id": "exec_role_broad_permissions",
   "kind": "any_of",
   "tier": "core",
   "quote": "broad permissions to manage EKS, Secrets Manager, KMS, S3, EC2, Lambda, and logging",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": [
       {
        "path": [
         "MaxSessionDuration"
        ],
        "op": "eq",
        "value": 8400
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\beks:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\bsecretsmanager:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\bkms:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\bs3:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\bec2:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\blambda:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\blogs:[A-Za-z*]"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": [
       {
        "path": [
         "MaxSessionDuration"
        ],
        "op": "eq",
        "value": 8400
       }
      ]
     },
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\beks:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\bsecretsmanager:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\bkms:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\bs3:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\bec2:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\blambda:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\blogs:[A-Za-z*]"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "log_delivery_role",
   "kind": "exists",
   "select": {
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
      "value": "cloudformation\\.amazonaws\\.com$"
     },
     {
      "path": [],
      "op": "regex",
      "value": "(?i)logs:(PutLogEvents|\\*)"
     },
     {
      "path": [
       "MaxSessionDuration"
      ],
      "op": "none_eq",
      "value": 8400
     }
    ]
   },
   "tier": "core",
   "quote": "a logging delivery role for CloudFormation registry logs",
   "justify": "a role CloudFormation assumes to deliver registry logs needs logs:PutLogEvents"
  },
  {
   "id": "codebuild_eks_role",
   "kind": "any_of",
   "tier": "core",
   "quote": "a role for CodeBuild and EKS service integration with permissions for ECR, S3, and EKS",
   "checks": [
    {
     "kind": "exists",
     "select": {
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
        "value": "^codebuild\\.amazonaws\\.com$"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\becr:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\beks:[A-Za-z*]"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "bidirectional": true,
     "to": {
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
        "value": "^codebuild\\.amazonaws\\.com$"
       }
      ]
     },
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\becr:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\beks:[A-Za-z*]"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "codebuild_eks_role_s3",
   "kind": "any_of",
   "tier": "detail",
   "quote": "with permissions for ECR, S3, and EKS",
   "checks": [
    {
     "kind": "exists",
     "select": {
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
        "value": "^codebuild\\.amazonaws\\.com$"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\bs3:[A-Za-z*]"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "bidirectional": true,
     "to": {
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
        "value": "^codebuild\\.amazonaws\\.com$"
       }
      ]
     },
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\bs3:[A-Za-z*]"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "hooks_role",
   "kind": "any_of",
   "tier": "core",
   "quote": "a role for CloudFormation extension hooks with permissions for Secrets Manager, KMS, EKS, S3, STS, IAM, EC2, Lambda, logs, CloudWatch, and SSM",
   "checks": [
    {
     "kind": "exists",
     "select": {
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
        "value": "cloudformation\\.amazonaws\\.com$"
       },
       {
        "path": [
         "MaxSessionDuration"
        ],
        "op": "none_eq",
        "value": 8400
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\bsecretsmanager:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\bkms:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\beks:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\bsts:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\biam:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\bec2:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\blambda:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\blogs:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\bcloudwatch:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\bssm:[A-Za-z*]"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "bidirectional": true,
     "to": {
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
        "value": "cloudformation\\.amazonaws\\.com$"
       },
       {
        "path": [
         "MaxSessionDuration"
        ],
        "op": "none_eq",
        "value": 8400
       }
      ]
     },
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\bsecretsmanager:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\bkms:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\beks:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\bsts:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\biam:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\bec2:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\blambda:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\blogs:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\bcloudwatch:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\bssm:[A-Za-z*]"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "hooks_role_s3",
   "kind": "any_of",
   "tier": "detail",
   "quote": "permissions for Secrets Manager, KMS, EKS, S3, STS",
   "checks": [
    {
     "kind": "exists",
     "select": {
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
        "value": "cloudformation\\.amazonaws\\.com$"
       },
       {
        "path": [
         "MaxSessionDuration"
        ],
        "op": "none_eq",
        "value": 8400
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\bs3:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\bssm:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\bcloudwatch:[A-Za-z*]"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "bidirectional": true,
     "to": {
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
        "value": "cloudformation\\.amazonaws\\.com$"
       },
       {
        "path": [
         "MaxSessionDuration"
        ],
        "op": "none_eq",
        "value": 8400
       }
      ]
     },
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\bs3:[A-Za-z*]"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "hooks_role_trust",
   "kind": "exists",
   "tier": "detail",
   "select": {
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
      "value": "^hooks\\.cloudformation\\.amazonaws\\.com$"
     }
    ]
   },
   "quote": "a role for CloudFormation extension hooks",
   "justify": "CloudFormation hooks assume roles via hooks.cloudformation.amazonaws.com"
  },
  {
   "id": "bastion_role",
   "kind": "any_of",
   "tier": "core",
   "quote": "a bastion instance role with access to the specified S3 bucket, ECR, EC2, EKS, CodeBuild, CodePipeline, and CloudWatch logs",
   "checks": [
    {
     "kind": "exists",
     "select": {
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
        "value": "^ec2\\.amazonaws\\.com$"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\becr:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\bec2:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\beks:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\bcodebuild:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\bcodepipeline:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\blogs:[A-Za-z*]"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": {
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
        "value": "^ec2\\.amazonaws\\.com$"
       }
      ]
     },
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\becr:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\bec2:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\beks:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\bcodebuild:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\bcodepipeline:[A-Za-z*]"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)\\blogs:[A-Za-z*]"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "bastion_s3_getobject_scoped",
   "kind": "any_of",
   "tier": "core",
   "quote": "scopes the bastion role's S3 GetObject access to only that bucket",
   "checks": [
    {
     "kind": "attr",
     "select": {
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
        "value": "^ec2\\.amazonaws\\.com$"
       }
      ]
     },
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
        "value": "s3:GetObject"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "none_eq",
        "value": "*"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "none_eq",
        "value": "arn:aws:s3:::*/*"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "none_eq",
        "value": "arn:aws:s3:::*"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": {
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
        "value": "^ec2\\.amazonaws\\.com$"
       }
      ]
     },
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
           "Action",
           "*"
          ],
          "op": "glob_covers",
          "value": "s3:GetObject"
         },
         {
          "path": [
           "Resource",
           "*"
          ],
          "op": "none_eq",
          "value": "*"
         },
         {
          "path": [
           "Resource",
           "*"
          ],
          "op": "none_eq",
          "value": "arn:aws:s3:::*/*"
         },
         {
          "path": [
           "Resource",
           "*"
          ],
          "op": "none_eq",
          "value": "arn:aws:s3:::*"
         }
        ]
       }
      ]
     }
    }
   ],
   "justify": "\"only that bucket\" rules out the all-bucket wildcards *, arn:aws:s3:::* and arn:aws:s3:::*/*"
  },
  {
   "id": "param_s3_bucket",
   "kind": "attr",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "name"
    ],
    "op": "regex",
    "value": "(?i)bucket"
   },
   "tier": "detail",
   "quote": "an S3 bucket name parameter"
  },
  {
   "id": "params_env_alias_hash",
   "kind": "all_of",
   "tier": "detail",
   "quote": "an optional environment alias and hash for naming",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)alias"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)hash"
     }
    }
   ]
  },
  {
   "id": "activate_three_types",
   "kind": "all_of",
   "tier": "core",
   "quote": "activate three CloudFormation resource types for Kubernetes (AWSQS-Kubernetes-Resource, AWSQS-Kubernetes-Helm, and AWSQS-EKS-Cluster)",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "regex",
        "value": "^(AWS::CloudFormation::(TypeActivation|ResourceVersion|CustomResource)|Custom::.+)$"
       },
       {
        "path": [
         "gated"
        ],
        "op": "falsy"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)AWSQS.{1,2}Kubernetes.{1,2}Resource"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "regex",
        "value": "^(AWS::CloudFormation::(TypeActivation|ResourceVersion|CustomResource)|Custom::.+)$"
       },
       {
        "path": [
         "gated"
        ],
        "op": "falsy"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)AWSQS.{1,2}Kubernetes.{1,2}Helm"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "regex",
        "value": "^(AWS::CloudFormation::(TypeActivation|ResourceVersion|CustomResource)|Custom::.+)$"
       },
       {
        "path": [
         "gated"
        ],
        "op": "falsy"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)AWSQS.{1,2}EKS.{1,2}Cluster"
     }
    }
   ]
  },
  {
   "id": "activation_execution_role",
   "kind": "ref",
   "from": {
    "types": [
     "__declared__"
    ],
    "where": [
     {
      "path": [
       "type"
      ],
      "op": "regex",
      "value": "^(AWS::CloudFormation::(TypeActivation|ResourceVersion|CustomResource)|Custom::.+)$"
     },
     {
      "path": [
       "gated"
      ],
      "op": "falsy"
     }
    ]
   },
   "to": {
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
      "value": "cloudformation\\.amazonaws\\.com$"
     },
     {
      "path": [
       "MaxSessionDuration"
      ],
      "op": "eq",
      "value": 8400
     }
    ]
   },
   "tier": "detail",
   "quote": "using the execution role for execution"
  },
  {
   "id": "activation_logging_role",
   "kind": "ref",
   "from": {
    "types": [
     "__declared__"
    ],
    "where": [
     {
      "path": [
       "type"
      ],
      "op": "regex",
      "value": "^(AWS::CloudFormation::(TypeActivation|ResourceVersion|CustomResource)|Custom::.+)$"
     },
     {
      "path": [
       "gated"
      ],
      "op": "falsy"
     }
    ]
   },
   "to": {
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
      "value": "cloudformation\\.amazonaws\\.com$"
     },
     {
      "path": [],
      "op": "regex",
      "value": "(?i)logs:(PutLogEvents|\\*)"
     },
     {
      "path": [
       "MaxSessionDuration"
      ],
      "op": "none_eq",
      "value": 8400
     }
    ]
   },
   "tier": "detail",
   "quote": "the logging delivery role for logging"
  },
  {
   "id": "activation_log_groups",
   "kind": "all_of",
   "tier": "detail",
   "quote": "each activation writing to a specific log group (e.g., cloudformation/registry/awsqs-kubernetes-resource, awsqs-kubernetes-helm-logs, and cloudformation/registry/awsqs-eks-cluster)",
   "checks": [
    {
     "kind": "attr",
     "quantifier": "all",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "regex",
        "value": "^(AWS::CloudFormation::(TypeActivation|ResourceVersion|CustomResource)|Custom::.+)$"
       },
       {
        "path": [
         "gated"
        ],
        "op": "falsy"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)LogGroupName"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "regex",
        "value": "^(AWS::Logs::LogGroup|AWS::CloudFormation::(TypeActivation|ResourceVersion|CustomResource)|Custom::.+)$"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)awsqs.?kubernetes.?resource"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "regex",
        "value": "^(AWS::Logs::LogGroup|AWS::CloudFormation::(TypeActivation|ResourceVersion|CustomResource)|Custom::.+)$"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)awsqs.?kubernetes.?helm"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "regex",
        "value": "^(AWS::Logs::LogGroup|AWS::CloudFormation::(TypeActivation|ResourceVersion|CustomResource)|Custom::.+)$"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)awsqs.?eks.?cluster"
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
