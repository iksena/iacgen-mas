package intent.cfn.row_208

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
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
     "op": "contains",
     "value": "lambda.amazonaws.com"
    }
   ]
  },
  "cp": {
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
     "op": "contains",
     "value": "eks.amazonaws.com"
    }
   ]
  },
  "fargate": {
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
     "op": "contains",
     "value": "eks-fargate-pods.amazonaws.com"
    }
   ]
  },
  "nodes": {
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
     "op": "contains",
     "value": "ec2.amazonaws.com"
    }
   ]
  },
  "profiles": {
   "types": [
    "AWS::IAM::InstanceProfile"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "lam_roles",
   "kind": "exists",
   "tier": "core",
   "quote": "Create Lambda execution roles for a set of custom-resource handlers",
   "select": "lam",
   "min": 10,
   "justify": "prompt lists ten distinct handler tasks"
  },
  {
   "id": "copy_s3",
   "kind": "any_of",
   "tier": "detail",
   "quote": "copying deployment assets between S3 buckets",
   "checks": [
    {
     "kind": "attr",
     "select": "lam",
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
      "value": "s3:GetObject"
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
      "value": "s3:GetObject"
     }
    }
   ],
   "justify": "copying assets from a bucket needs object read"
  },
  {
   "id": "reader",
   "kind": "any_of",
   "tier": "core",
   "quote": "reading arbitrary AWS resources",
   "checks": [
    {
     "kind": "attr",
     "select": "lam",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "/(ReadOnly|ViewOnly)Access$"
     }
    },
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
        "op": "contains",
        "value": "lambda.amazonaws.com"
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
        "value": "^ec2:(Describe|Get|List)"
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
        "value": "^(elasticloadbalancing|autoscaling|eks|s3):(Describe|Get|List)"
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
        "value": "^(iam|cloudformation|lambda|kms|ssm|acm):(Describe|Get|List)"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "lam",
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
      "value": "^\\*(:(Describe|Get|List)\\*)?$"
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
        "op": "regex",
        "value": "^ec2:(Describe|Get|List)"
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
        "value": "^(elasticloadbalancing|autoscaling|eks|s3):(Describe|Get|List)"
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
        "value": "^(iam|cloudformation|lambda|kms|ssm|acm):(Describe|Get|List)"
       }
      ]
     },
     "to": "lam"
    }
   ],
   "justify": "arbitrary resources means reads across services, not one service's Describe* on a cleanup role: AWS read-only managed policy, or one role reading compute, network or storage, and management services"
  },
  {
   "id": "vpc_createrole",
   "kind": "any_of",
   "tier": "core",
   "quote": "creating a VPC-related IAM role",
   "checks": [
    {
     "kind": "attr",
     "select": "lam",
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
      "value": "iam:CreateRole"
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
      "value": "iam:CreateRole"
     }
    }
   ]
  },
  {
   "id": "vpc_attach",
   "kind": "any_of",
   "tier": "detail",
   "quote": "creating a VPC-related IAM role",
   "checks": [
    {
     "kind": "attr",
     "select": "lam",
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
      "value": "iam:AttachRolePolicy"
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
      "value": "iam:AttachRolePolicy"
     }
    }
   ],
   "justify": "creating a role that Lambda later attaches policies to implies iam:AttachRolePolicy"
  },
  {
   "id": "cfn_role_creator",
   "kind": "any_of",
   "tier": "detail",
   "quote": "creating the IAM role that CloudFormation itself assumes when provisioning cluster VPC resources",
   "justify": "this handler is listed apart from the VPC-related one, so two Lambda roles create IAM roles, or the CloudFormation-trusted role itself is created",
   "checks": [
    {
     "kind": "exists",
     "min": 2,
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
        "op": "contains",
        "value": "lambda.amazonaws.com"
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
        "op": "glob_covers",
        "value": "iam:CreateRole"
       }
      ]
     }
    },
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
        "op": "contains",
        "value": "cloudformation.amazonaws.com"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "clean_lb",
   "kind": "any_of",
   "tier": "core",
   "quote": "cleaning up orphaned load balancers",
   "checks": [
    {
     "kind": "attr",
     "select": "lam",
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
      "value": "elasticloadbalancing:DeleteLoadBalancer"
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
      "value": "elasticloadbalancing:DeleteLoadBalancer"
     }
    }
   ]
  },
  {
   "id": "clean_sg",
   "kind": "any_of",
   "tier": "detail",
   "quote": "their dependent security groups",
   "checks": [
    {
     "kind": "attr",
     "select": "lam",
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
      "value": "ec2:DeleteSecurityGroup"
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
      "value": "ec2:DeleteSecurityGroup"
     }
    }
   ]
  },
  {
   "id": "clean_eni",
   "kind": "any_of",
   "tier": "detail",
   "quote": "network interfaces after cluster teardown",
   "checks": [
    {
     "kind": "attr",
     "select": "lam",
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
      "value": "ec2:DeleteNetworkInterface"
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
      "value": "ec2:DeleteNetworkInterface"
     }
    }
   ]
  },
  {
   "id": "clean_lambda",
   "kind": "any_of",
   "tier": "core",
   "quote": "cleaning up leftover Lambda functions",
   "checks": [
    {
     "kind": "attr",
     "select": "lam",
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
      "value": "lambda:DeleteFunction"
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
      "value": "lambda:DeleteFunction"
     }
    }
   ]
  },
  {
   "id": "caller_identity",
   "kind": "any_of",
   "tier": "detail",
   "quote": "looking up the calling identity",
   "checks": [
    {
     "kind": "attr",
     "select": "lam",
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
      "value": "cloudtrail:LookupEvents"
     }
    },
    {
     "kind": "attr",
     "select": "lam",
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
      "value": "sts:GetCallerIdentity"
     }
    },
    {
     "kind": "attr",
     "select": "lam",
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
      "value": "cloudformation:DescribeStacks"
     }
    }
   ],
   "justify": "caller lookup via CloudTrail/CloudFormation/STS"
  },
  {
   "id": "register_type",
   "kind": "any_of",
   "tier": "core",
   "quote": "registering CloudFormation resource provider types and associated custom resources",
   "checks": [
    {
     "kind": "attr",
     "select": "lam",
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
      "value": "cloudformation:RegisterType"
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
      "value": "cloudformation:RegisterType"
     }
    }
   ]
  },
  {
   "id": "ssm_params",
   "kind": "any_of",
   "tier": "core",
   "quote": "resolving Systems Manager parameters under a common configuration path",
   "checks": [
    {
     "kind": "attr",
     "select": "lam",
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
      "value": "ssm:GetParameter"
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
      "value": "ssm:GetParameter"
     }
    }
   ]
  },
  {
   "id": "ssm_path",
   "kind": "attr",
   "tier": "detail",
   "quote": "resolving Systems Manager parameters under a common configuration path",
   "select": "lam",
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
    "value": "parameter/"
   }
  },
  {
   "id": "cp_role",
   "kind": "exists",
   "tier": "core",
   "quote": "an IAM role for the EKS control plane itself",
   "select": "cp",
   "min": 1
  },
  {
   "id": "cp_managed",
   "kind": "attr",
   "tier": "core",
   "quote": "with the standard EKS managed policies",
   "select": "cp",
   "cond": {
    "path": [
     "ManagedPolicyArns",
     "*"
    ],
    "op": "contains",
    "value": "AmazonEKSClusterPolicy"
   },
   "justify": "standard EKS cluster managed policy"
  },
  {
   "id": "fargate",
   "kind": "exists",
   "tier": "core",
   "quote": "an IAM role that Fargate profiles assume",
   "select": "fargate",
   "min": 1
  },
  {
   "id": "nodes_two",
   "kind": "exists",
   "tier": "core",
   "quote": "both managed-node and unmanaged-node EC2 instance roles",
   "select": "nodes",
   "min": 2,
   "justify": "managed and unmanaged = two roles"
  },
  {
   "id": "profiles_two",
   "kind": "exists",
   "tier": "core",
   "quote": "each with a matching instance profile",
   "select": "profiles",
   "min": 2,
   "justify": "one per node role"
  },
  {
   "id": "profiles_ref",
   "kind": "ref",
   "tier": "core",
   "quote": "each with a matching instance profile",
   "from": "profiles",
   "to": "nodes"
  },
  {
   "id": "node_AmazonEKSWorkerNodePolicy",
   "kind": "attr",
   "tier": "core",
   "quote": "carrying the standard EKS worker node, CNI, container registry read, and EFS read-only managed policies",
   "select": "nodes",
   "quantifier": "all",
   "cond": {
    "path": [
     "ManagedPolicyArns",
     "*"
    ],
    "op": "contains",
    "value": "AmazonEKSWorkerNodePolicy"
   }
  },
  {
   "id": "node_AmazonEKS_CNI_Policy",
   "kind": "attr",
   "tier": "core",
   "quote": "carrying the standard EKS worker node, CNI, container registry read, and EFS read-only managed policies",
   "select": "nodes",
   "quantifier": "all",
   "cond": {
    "path": [
     "ManagedPolicyArns",
     "*"
    ],
    "op": "contains",
    "value": "AmazonEKS_CNI_Policy"
   }
  },
  {
   "id": "node_AmazonEC2ContainerRegistryReadOnly",
   "kind": "attr",
   "tier": "core",
   "quote": "carrying the standard EKS worker node, CNI, container registry read, and EFS read-only managed policies",
   "select": "nodes",
   "quantifier": "all",
   "cond": {
    "path": [
     "ManagedPolicyArns",
     "*"
    ],
    "op": "contains",
    "value": "AmazonEC2ContainerRegistryReadOnly"
   }
  },
  {
   "id": "node_AmazonElasticFileSystemReadOnlyAccess",
   "kind": "attr",
   "tier": "core",
   "quote": "carrying the standard EKS worker node, CNI, container registry read, and EFS read-only managed policies",
   "select": "nodes",
   "quantifier": "all",
   "cond": {
    "path": [
     "ManagedPolicyArns",
     "*"
    ],
    "op": "regex",
    "value": "AmazonElasticFileSystem(Client)?ReadOnlyAccess$"
   },
   "justify": "AWS's EFS read-only managed policies are AmazonElasticFileSystemReadOnlyAccess and AmazonElasticFileSystemClientReadOnlyAccess"
  },
  {
   "id": "node_signal",
   "kind": "any_of",
   "tier": "detail",
   "quote": "plus permission to signal CloudFormation on startup",
   "checks": [
    {
     "kind": "attr",
     "select": "nodes",
     "quantifier": "all",
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
      "value": "cloudformation:SignalResource"
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
        "value": "cloudformation:SignalResource"
       }
      ]
     },
     "to": "nodes"
    }
   ]
  },
  {
   "id": "lam_scoped",
   "kind": "attr",
   "tier": "detail",
   "quote": "each scoped to only the specific AWS actions that task requires",
   "select": "lam",
   "quantifier": "all",
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
    "op": "none_eq",
    "value": "*"
   }
  },
  {
   "id": "x_cp_ec2",
   "kind": "attr",
   "tier": "extra",
   "select": "cp",
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
    "value": "ec2:DescribeAddresses"
   }
  },
  {
   "id": "x_fargate_policy",
   "kind": "attr",
   "tier": "extra",
   "select": "fargate",
   "cond": {
    "path": [
     "ManagedPolicyArns",
     "*"
    ],
    "op": "contains",
    "value": "AmazonEKSFargatePodExecutionRolePolicy"
   }
  },
  {
   "id": "x_reader_basic",
   "kind": "attr",
   "tier": "extra",
   "select": "lam",
   "cond": {
    "path": [
     "ManagedPolicyArns",
     "*"
    ],
    "op": "contains",
    "value": "AWSLambdaBasicExecutionRole"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
