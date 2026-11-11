package intent.cfn.row_198

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "roles": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "mp": {
   "types": [
    "AWS::IAM::ManagedPolicy"
   ],
   "where": []
  },
  "ctrl_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "regex",
     "value": "(?i)pods\\.eks\\.amazonaws\\.com|AssumeRoleWithWebIdentity"
    },
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "contains",
     "value": "ec2.amazonaws.com"
    }
   ]
  },
  "ctrl_mp": {
   "types": [
    "AWS::IAM::ManagedPolicy"
   ],
   "where": [
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "eks:"
    },
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "(?i)iam:(CreateServiceLinkedRole|\\*)"
    },
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "elasticloadbalancing:"
    },
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "autoscaling:"
    },
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "ec2:"
    }
   ]
  },
  "group": {
   "types": [
    "AWS::IAM::Group"
   ],
   "where": []
  },
  "user": {
   "types": [
    "AWS::IAM::User"
   ],
   "where": []
  },
  "ip": {
   "types": [
    "AWS::IAM::InstanceProfile"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "four_roles",
   "kind": "exists",
   "tier": "core",
   "quote": "Create separate IAM roles for the control plane, the controllers, the worker nodes, and a role dedicated to the EKS control plane",
   "justify": "four named roles",
   "select": "roles",
   "min": 4
  },
  {
   "id": "instance_profiles",
   "kind": "exists",
   "tier": "core",
   "quote": "each with a matching instance profile where relevant",
   "justify": "control plane, controllers and nodes need profiles; EKS role may not",
   "select": "ip",
   "min": 2
  },
  {
   "id": "ip_role",
   "kind": "ref",
   "tier": "detail",
   "quote": "each with a matching instance profile where relevant",
   "from": "ip",
   "to": "roles"
  },
  {
   "id": "ec2_trust",
   "kind": "exists",
   "tier": "core",
   "quote": "assumable by the EC2 service",
   "justify": "control plane, controllers and worker nodes are assumed by EC2",
   "select": {
    "types": [
     "AWS::IAM::Role"
    ],
    "where": [
     {
      "path": [
       "AssumeRolePolicyDocument"
      ],
      "op": "contains",
      "value": "ec2.amazonaws.com"
     }
    ]
   },
   "min": 3
  },
  {
   "id": "pods_trust",
   "kind": "exists",
   "tier": "core",
   "quote": "assumable by the EC2 service (and, for the controllers role, also by EKS Pods)",
   "justify": "the controllers role trusts both EC2 and EKS Pods (pods.eks.amazonaws.com, or web identity)",
   "select": "ctrl_role"
  },
  {
   "id": "eks_trust",
   "kind": "exists",
   "tier": "detail",
   "quote": "a role dedicated to the EKS control plane",
   "justify": "EKS control plane role is assumed by the EKS service (eks.amazonaws.com, not pods.eks.amazonaws.com)",
   "select": {
    "types": [
     "AWS::IAM::Role"
    ],
    "where": [
     {
      "path": [
       "AssumeRolePolicyDocument"
      ],
      "op": "regex",
      "value": "(^|[^.a-z0-9-])eks\\.amazonaws\\.com"
     }
    ]
   }
  },
  {
   "id": "mp_eks_cluster",
   "kind": "attr",
   "tier": "detail",
   "quote": "the managed EKS cluster, worker node, and CNI policies",
   "justify": "managed EKS cluster policy name",
   "select": "roles",
   "cond": {
    "path": [
     "ManagedPolicyArns",
     "*"
    ],
    "op": "contains",
    "value": "AmazonEKSClusterPolicy"
   }
  },
  {
   "id": "mp_eks_worker",
   "kind": "attr",
   "tier": "detail",
   "quote": "the managed EKS cluster, worker node, and CNI policies",
   "justify": "managed worker node policy name",
   "select": "roles",
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
   "id": "mp_eks_cni",
   "kind": "attr",
   "tier": "detail",
   "quote": "the managed EKS cluster, worker node, and CNI policies",
   "justify": "managed CNI policy name",
   "select": "roles",
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
   "id": "aws_managed_any",
   "kind": "attr",
   "tier": "core",
   "quote": "each carrying the AWS managed policies appropriate to its function",
   "justify": "AWS managed policy ARN prefix",
   "select": "roles",
   "cond": {
    "path": [
     "ManagedPolicyArns",
     "*"
    ],
    "op": "regex",
    "value": "arn:[a-z-]*:iam::aws:policy/"
   }
  },
  {
   "id": "managed_policies",
   "kind": "exists",
   "tier": "core",
   "quote": "Attach managed IAM policies to the control plane and worker node roles",
   "justify": "cloud-provider policies plus the broader controllers policy",
   "select": "mp",
   "min": 2
  },
  {
   "id": "mp_attached_roles",
   "kind": "ref",
   "tier": "core",
   "quote": "Attach managed IAM policies to the control plane and worker node roles",
   "bidirectional": true,
   "from": "mp",
   "to": "roles"
  },
  {
   "id": "perm_ec2",
   "kind": "any_of",
   "tier": "detail",
   "quote": "EC2",
   "justify": "EC2 permissions mean ec2: actions",
   "checks": [
    {
     "kind": "attr",
     "select": "mp",
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "ec2:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "ec2:"
     }
    },
    {
     "kind": "attr",
     "select": "roles",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "ec2:"
     }
    }
   ]
  },
  {
   "id": "perm_elb",
   "kind": "any_of",
   "tier": "detail",
   "quote": "Elastic Load Balancing",
   "justify": "Elastic Load Balancing permissions mean elasticloadbalancing: actions",
   "checks": [
    {
     "kind": "attr",
     "select": "mp",
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "elasticloadbalancing:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "elasticloadbalancing:"
     }
    },
    {
     "kind": "attr",
     "select": "roles",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "elasticloadbalancing:"
     }
    }
   ]
  },
  {
   "id": "perm_asg",
   "kind": "any_of",
   "tier": "detail",
   "quote": "Auto Scaling",
   "justify": "Auto Scaling permissions mean autoscaling: actions",
   "checks": [
    {
     "kind": "attr",
     "select": "mp",
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "autoscaling:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "autoscaling:"
     }
    },
    {
     "kind": "attr",
     "select": "roles",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "autoscaling:"
     }
    }
   ]
  },
  {
   "id": "perm_ecr",
   "kind": "any_of",
   "tier": "detail",
   "quote": "ECR",
   "justify": "ECR permissions mean ecr: actions",
   "checks": [
    {
     "kind": "attr",
     "select": "mp",
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "ecr:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "ecr:"
     }
    },
    {
     "kind": "attr",
     "select": "roles",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "ecr:"
     }
    }
   ]
  },
  {
   "id": "perm_secrets",
   "kind": "any_of",
   "tier": "detail",
   "quote": "Secrets Manager",
   "justify": "Secrets Manager permissions mean secretsmanager: actions",
   "checks": [
    {
     "kind": "attr",
     "select": "mp",
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "secretsmanager:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "secretsmanager:"
     }
    },
    {
     "kind": "attr",
     "select": "roles",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "secretsmanager:"
     }
    }
   ]
  },
  {
   "id": "perm_ssm",
   "kind": "any_of",
   "tier": "detail",
   "quote": "Systems Manager",
   "justify": "Systems Manager permissions mean ssm: actions",
   "checks": [
    {
     "kind": "attr",
     "select": "mp",
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "ssm:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "ssm:"
     }
    },
    {
     "kind": "attr",
     "select": "roles",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "ssm:"
     }
    }
   ]
  },
  {
   "id": "controllers_policy",
   "kind": "exists",
   "tier": "core",
   "quote": "covering the EC2 networking, load balancing, auto scaling, EKS cluster and nodegroup management, and related service-linked role creation permissions",
   "justify": "EKS, service-linked role, ELB, auto scaling and EC2 action prefixes",
   "select": "ctrl_mp"
  },
  {
   "id": "controllers_policy_role",
   "kind": "ref",
   "tier": "core",
   "quote": "attach a broader managed policy to the controllers and control plane roles",
   "bidirectional": true,
   "from": "ctrl_mp",
   "to": "roles"
  },
  {
   "id": "group",
   "kind": "exists",
   "tier": "core",
   "quote": "an IAM group and an IAM user representing a bootstrapper identity",
   "select": "group"
  },
  {
   "id": "user",
   "kind": "exists",
   "tier": "core",
   "quote": "an IAM group and an IAM user representing a bootstrapper identity",
   "select": "user"
  },
  {
   "id": "user_in_group",
   "kind": "any_of",
   "tier": "detail",
   "quote": "an IAM group and an IAM user representing a bootstrapper identity",
   "checks": [
    {
     "kind": "ref",
     "from": "user",
     "to": "group"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::UserToGroupAddition"
      ],
      "where": []
     },
     "to": "user"
    }
   ]
  },
  {
   "id": "group_ctrl_policy",
   "kind": "ref",
   "tier": "core",
   "quote": "with the group granted the same controller-level managed policy",
   "bidirectional": true,
   "from": "ctrl_mp",
   "to": "group"
  },
  {
   "id": "x_tagsession",
   "kind": "attr",
   "tier": "extra",
   "select": "ctrl_role",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument"
    ],
    "op": "contains",
    "value": "sts:TagSession"
   }
  },
  {
   "id": "x_slr_nodegroup",
   "kind": "attr",
   "tier": "extra",
   "select": "mp",
   "cond": {
    "path": [
     "PolicyDocument"
    ],
    "op": "contains",
    "value": "eks-nodegroup.amazonaws.com"
   }
  },
  {
   "id": "x_ecr_pull",
   "kind": "attr",
   "tier": "extra",
   "select": "mp",
   "cond": {
    "path": [
     "PolicyDocument"
    ],
    "op": "contains",
    "value": "ecr:GetAuthorizationToken"
   }
  },
  {
   "id": "x_ssmmessages",
   "kind": "attr",
   "tier": "extra",
   "select": "mp",
   "cond": {
    "path": [
     "PolicyDocument"
    ],
    "op": "contains",
    "value": "ssmmessages:"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
