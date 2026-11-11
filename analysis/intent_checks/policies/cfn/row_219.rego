package intent.cfn.row_219

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "ec2_role": {
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
     "value": "(?i)^ec2\\."
    }
   ]
  },
  "cd_role": {
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
     "value": "(?i)^codedeploy\\."
    }
   ]
  },
  "cp_role": {
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
     "value": "(?i)^codepipeline\\."
    }
   ]
  },
  "profile": {
   "types": [
    "AWS::IAM::InstanceProfile"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "ec2_role",
   "kind": "exists",
   "select": "ec2_role",
   "tier": "core",
   "quote": "an EC2 instance role",
   "justify": "an EC2 instance role is assumed by ec2.amazonaws.com"
  },
  {
   "id": "instance_profile_for_role",
   "kind": "ref",
   "from": "profile",
   "to": "ec2_role",
   "tier": "core",
   "quote": "EC2 instance role and matching instance profile"
  },
  {
   "id": "ec2_role_admin",
   "kind": "any_of",
   "tier": "core",
   "quote": "granting broad administrative access for testing purposes",
   "justify": "broad administrative access means Action * or AdministratorAccess",
   "checks": [
    {
     "kind": "attr",
     "select": "ec2_role",
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
        "value": "*"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "ec2_role",
     "to": {
      "types": [
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::Policy"
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
          "value": "*"
         }
        ]
       }
      ]
     },
     "bidirectional": true
    },
    {
     "kind": "attr",
     "select": "ec2_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "(?i)AdministratorAccess"
     }
    }
   ]
  },
  {
   "id": "codedeploy_role",
   "kind": "exists",
   "select": "cd_role",
   "tier": "core",
   "quote": "a CodeDeploy service role that can be assumed by the CodeDeploy service",
   "justify": "CodeDeploy principal is codedeploy*.amazonaws.com"
  },
  {
   "id": "codedeploy_regions",
   "kind": "any_of",
   "tier": "detail",
   "quote": "in the us-east-1 and us-west-2 regions",
   "justify": "regional codedeploy principals name both regions; plain codedeploy.amazonaws.com is valid in all regions",
   "checks": [
    {
     "kind": "attr",
     "select": "cd_role",
     "cond": {
      "path": [
       "AssumeRolePolicyDocument"
      ],
      "op": "regex",
      "value": "(?s)us-east-1.*us-west-2"
     }
    },
    {
     "kind": "attr",
     "select": "cd_role",
     "cond": {
      "path": [
       "AssumeRolePolicyDocument"
      ],
      "op": "regex",
      "value": "(?s)us-west-2.*us-east-1"
     }
    },
    {
     "kind": "attr",
     "select": "cd_role",
     "cond": {
      "path": [
       "AssumeRolePolicyDocument",
       "Statement",
       "*",
       "Principal",
       "Service",
       "*"
      ],
      "op": "regex",
      "value": "(?i)^codedeploy\\.amazonaws\\.com$"
     }
    }
   ]
  },
  {
   "id": "codedeploy_describe_ec2",
   "kind": "any_of",
   "tier": "core",
   "quote": "permissions to describe EC2 instances",
   "checks": [
    {
     "kind": "attr",
     "select": "cd_role",
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
        "value": "ec2:DescribeInstances"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "cd_role",
     "to": {
      "types": [
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::Policy"
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
          "value": "ec2:DescribeInstances"
         }
        ]
       }
      ]
     },
     "bidirectional": true
    },
    {
     "kind": "attr",
     "select": "cd_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "(?i)AWSCodeDeployRole"
     }
    }
   ]
  },
  {
   "id": "codedeploy_lifecycle_hooks",
   "kind": "any_of",
   "tier": "core",
   "quote": "manage Auto Scaling lifecycle hooks",
   "checks": [
    {
     "kind": "attr",
     "select": "cd_role",
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
        "value": "autoscaling:PutLifecycleHook"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "cd_role",
     "to": {
      "types": [
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::Policy"
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
          "value": "autoscaling:PutLifecycleHook"
         }
        ]
       }
      ]
     },
     "bidirectional": true
    },
    {
     "kind": "attr",
     "select": "cd_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "(?i)AWSCodeDeployRole"
     }
    }
   ]
  },
  {
   "id": "codepipeline_role",
   "kind": "exists",
   "select": "cp_role",
   "tier": "core",
   "quote": "a CodePipeline service role",
   "justify": "CodePipeline principal is codepipeline.amazonaws.com"
  },
  {
   "id": "pipeline_s3_read",
   "kind": "any_of",
   "tier": "core",
   "quote": "read and write pipeline artifacts in S3",
   "justify": "reading and writing S3 objects means s3:GetObject / s3:PutObject",
   "checks": [
    {
     "kind": "attr",
     "select": "cp_role",
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
        "value": "s3:GetObject"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "cp_role",
     "to": {
      "types": [
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::Policy"
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
          "value": "s3:GetObject"
         }
        ]
       }
      ]
     },
     "bidirectional": true
    },
    {
     "kind": "attr",
     "select": "cp_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "AmazonS3FullAccess|AmazonS3ReadOnlyAccess"
     }
    }
   ]
  },
  {
   "id": "pipeline_s3_write",
   "kind": "any_of",
   "tier": "core",
   "quote": "read and write pipeline artifacts in S3",
   "justify": "reading and writing S3 objects means s3:GetObject / s3:PutObject",
   "checks": [
    {
     "kind": "attr",
     "select": "cp_role",
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
        "value": "s3:PutObject"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "cp_role",
     "to": {
      "types": [
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::Policy"
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
          "value": "s3:PutObject"
         }
        ]
       }
      ]
     },
     "bidirectional": true
    },
    {
     "kind": "attr",
     "select": "cp_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "AmazonS3FullAccess"
     }
    }
   ]
  },
  {
   "id": "pipeline_services",
   "kind": "any_of",
   "tier": "detail",
   "quote": "orchestrate deployments across Elastic Beanstalk, EC2, Elastic Load Balancing, Auto Scaling, CloudWatch, S3, CloudFormation, RDS, SQS, ECS, CodeDeploy, and Lambda",
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
        "value": "(?i)^codepipeline\\."
       },
       {
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
        "value": "(?i)^elasticbeanstalk:"
       },
       {
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
        "value": "(?i)^ec2:"
       },
       {
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
        "value": "(?i)^elasticloadbalancing:"
       },
       {
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
        "value": "(?i)^autoscaling:"
       },
       {
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
        "value": "(?i)^cloudwatch:"
       },
       {
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
        "value": "(?i)^s3:"
       },
       {
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
        "value": "(?i)^cloudformation:"
       },
       {
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
        "value": "(?i)^rds:"
       },
       {
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
        "value": "(?i)^sqs:"
       },
       {
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
        "value": "(?i)^ecs:"
       },
       {
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
        "value": "(?i)^codedeploy:"
       },
       {
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
        "value": "(?i)^lambda:"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "cp_role",
     "to": {
      "types": [
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::Policy"
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
        "value": "(?i)^elasticbeanstalk:"
       },
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "regex",
        "value": "(?i)^ec2:"
       },
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "regex",
        "value": "(?i)^elasticloadbalancing:"
       },
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "regex",
        "value": "(?i)^autoscaling:"
       },
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "regex",
        "value": "(?i)^cloudwatch:"
       },
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "regex",
        "value": "(?i)^s3:"
       },
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "regex",
        "value": "(?i)^cloudformation:"
       },
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "regex",
        "value": "(?i)^rds:"
       },
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "regex",
        "value": "(?i)^sqs:"
       },
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "regex",
        "value": "(?i)^ecs:"
       },
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "regex",
        "value": "(?i)^codedeploy:"
       },
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "regex",
        "value": "(?i)^lambda:"
       }
      ]
     },
     "bidirectional": true
    },
    {
     "kind": "attr",
     "select": "cp_role",
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
        "value": "*"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "cp_role",
     "to": {
      "types": [
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::Policy"
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
          "value": "*"
         }
        ]
       }
      ]
     },
     "bidirectional": true
    },
    {
     "kind": "attr",
     "select": "cp_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "(?i)AdministratorAccess"
     }
    }
   ]
  },
  {
   "id": "pipeline_passrole",
   "kind": "any_of",
   "tier": "detail",
   "quote": "including the ability to pass IAM roles to those services",
   "checks": [
    {
     "kind": "attr",
     "select": "cp_role",
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
        "value": "iam:PassRole"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "cp_role",
     "to": {
      "types": [
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::Policy"
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
          "value": "iam:PassRole"
         }
        ]
       }
      ]
     },
     "bidirectional": true
    }
   ]
  },
  {
   "id": "x_cd_complete_lifecycle",
   "kind": "any_of",
   "tier": "extra",
   "checks": [
    {
     "kind": "attr",
     "select": "cd_role",
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
        "value": "autoscaling:CompleteLifecycleAction"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "cd_role",
     "to": {
      "types": [
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::Policy"
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
          "value": "autoscaling:CompleteLifecycleAction"
         }
        ]
       }
      ]
     },
     "bidirectional": true
    }
   ]
  },
  {
   "id": "x_cp_codedeploy_create",
   "kind": "any_of",
   "tier": "extra",
   "checks": [
    {
     "kind": "attr",
     "select": "cp_role",
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
        "value": "codedeploy:CreateDeployment"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "cp_role",
     "to": {
      "types": [
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::Policy"
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
          "value": "codedeploy:CreateDeployment"
         }
        ]
       }
      ]
     },
     "bidirectional": true
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
