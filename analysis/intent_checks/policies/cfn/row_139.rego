# GENERATED from specs/cfn/row_139.json by intent_checks/build.py -- do not edit.
package intent.cfn.row_139

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "profile": {
   "types": [
    "AWS::IAM::InstanceProfile"
   ],
   "where": []
  },
  "controllers_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "contains",
     "value": "pods.eks.amazonaws.com"
    }
   ]
  },
  "nodes_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "ManagedPolicyArns"
     ],
     "op": "contains",
     "value": "AmazonEKSWorkerNodePolicy"
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
      "AssumeRolePolicyDocument"
     ],
     "op": "contains",
     "value": "ec2.amazonaws.com"
    },
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Principal",
      "Service"
     ],
     "op": "none_eq",
     "value": "pods.eks.amazonaws.com"
    },
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Principal",
      "Service",
      "*"
     ],
     "op": "none_eq",
     "value": "pods.eks.amazonaws.com"
    },
    {
     "path": [
      "ManagedPolicyArns",
      "*"
     ],
     "op": "none_eq",
     "value": "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
    }
   ]
  },
  "eks_cluster_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "ManagedPolicyArns"
     ],
     "op": "contains",
     "value": "AmazonEKSClusterPolicy"
    }
   ]
  },
  "cp_policy": {
   "types": [
    "AWS::IAM::ManagedPolicy"
   ],
   "where": [
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "contains",
     "value": "ec2:"
    },
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "contains",
     "value": "elasticloadbalancing:"
    },
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "contains",
     "value": "autoscaling:"
    },
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "contains",
     "value": "kms:"
    }
   ]
  },
  "controllers_policy": {
   "types": [
    "AWS::IAM::ManagedPolicy"
   ],
   "where": [
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "(?i)accessentr|eks:\\*"
    },
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "(?i)launchtemplate|ec2:\\*"
    }
   ]
  },
  "eks_policy": {
   "types": [
    "AWS::IAM::ManagedPolicy"
   ],
   "where": [
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "(?i)eks:(\\*|[a-z]*nodegroup)"
    },
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "(?i)ssm:(\\*|getparameter)"
    }
   ]
  },
  "nodes_policy": {
   "types": [
    "AWS::IAM::ManagedPolicy"
   ],
   "where": [
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "contains",
     "value": "ecr:"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "three_instance_profiles",
   "kind": "exists",
   "select": "profile",
   "min": 3,
   "tier": "core",
   "quote": "provisioning three instance profiles"
  },
  {
   "id": "profiles_have_roles",
   "kind": "attr",
   "select": "profile",
   "quantifier": "all",
   "cond": {
    "path": [
     "Roles"
    ],
    "op": "len_gte",
    "value": 1
   },
   "tier": "core",
   "quote": "each associated with a corresponding IAM role"
  },
  {
   "id": "profiles_per_role",
   "kind": "all_of",
   "tier": "detail",
   "quote": "each associated with a corresponding IAM role",
   "checks": [
    {
     "kind": "ref",
     "from": "profile",
     "to": "cp_role"
    },
    {
     "kind": "ref",
     "from": "profile",
     "to": "controllers_role"
    },
    {
     "kind": "ref",
     "from": "profile",
     "to": "nodes_role"
    }
   ],
   "justify": "the control-plane role is told apart from the nodes role by not carrying AmazonEKSWorkerNodePolicy, which the prompt names for the nodes role only"
  },
  {
   "id": "control_plane_role_ec2",
   "kind": "exists",
   "select": "cp_role",
   "tier": "core",
   "quote": "the control plane role allows EC2 to assume it",
   "justify": "the control-plane role is told apart from the nodes role by not carrying AmazonEKSWorkerNodePolicy, which the prompt names for the nodes role only"
  },
  {
   "id": "control_plane_policy_attached",
   "kind": "any_of",
   "tier": "core",
   "quote": "attached to a custom managed policy granting broad permissions for EC2, ELB, auto scaling, and KMS operations",
   "checks": [
    {
     "kind": "ref",
     "from": "cp_policy",
     "to": "cp_role"
    },
    {
     "kind": "ref",
     "from": "cp_role",
     "to": "cp_policy"
    }
   ],
   "justify": "the control-plane role is told apart from the nodes role by not carrying AmazonEKSWorkerNodePolicy, which the prompt names for the nodes role only; \"ELB\" permissions are elasticloadbalancing: actions"
  },
  {
   "id": "controllers_role_trust",
   "kind": "attr",
   "select": "controllers_role",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument"
    ],
    "op": "contains",
    "value": "ec2.amazonaws.com"
   },
   "tier": "core",
   "quote": "the controllers role allows both EC2 and pods.eks.amazonaws.com to assume it"
  },
  {
   "id": "controllers_policy_attached",
   "kind": "any_of",
   "tier": "core",
   "quote": "is attached to a custom managed policy with extensive permissions",
   "checks": [
    {
     "kind": "ref",
     "from": "controllers_policy",
     "to": "controllers_role"
    },
    {
     "kind": "ref",
     "from": "controllers_role",
     "to": "controllers_policy"
    }
   ]
  },
  {
   "id": "controllers_policy_scope",
   "kind": "all_of",
   "tier": "detail",
   "quote": "managing VPCs, subnets, security groups, load balancers, auto scaling groups, launch templates, EKS access entries, and service-linked roles scoped to specific ARNs",
   "checks": [
    {
     "kind": "attr",
     "select": "controllers_policy",
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "(?i)ec2:(\\*|[a-z]*vpc)"
     }
    },
    {
     "kind": "attr",
     "select": "controllers_policy",
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "(?i)ec2:(\\*|[a-z]*subnet)"
     }
    },
    {
     "kind": "attr",
     "select": "controllers_policy",
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "(?i)ec2:(\\*|[a-z]*securitygroup)"
     }
    },
    {
     "kind": "attr",
     "select": "controllers_policy",
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "contains",
      "value": "elasticloadbalancing:"
     }
    },
    {
     "kind": "attr",
     "select": "controllers_policy",
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "(?i)autoscaling:(\\*|[a-z]*autoscalinggroup)"
     }
    },
    {
     "kind": "attr",
     "select": "controllers_policy",
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "(?i)iam:createservicelinkedrole.*aws-service-role|aws-service-role.*iam:createservicelinkedrole"
     }
    }
   ],
   "justify": "\"load balancers\" permissions are elasticloadbalancing: actions"
  },
  {
   "id": "eks_policy_attached_controllers",
   "kind": "any_of",
   "tier": "core",
   "quote": "a separate controllers-eks custom managed policy attached to the controllers and control plane roles",
   "checks": [
    {
     "kind": "ref",
     "from": "eks_policy",
     "to": "controllers_role"
    },
    {
     "kind": "ref",
     "from": "controllers_role",
     "to": "eks_policy"
    }
   ]
  },
  {
   "id": "eks_policy_attached_control_plane",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a separate controllers-eks custom managed policy attached to the controllers and control plane roles",
   "checks": [
    {
     "kind": "ref",
     "from": "eks_policy",
     "to": "cp_role"
    },
    {
     "kind": "ref",
     "from": "cp_role",
     "to": "eks_policy"
    }
   ],
   "justify": "the control-plane role is told apart from the nodes role by not carrying AmazonEKSWorkerNodePolicy, which the prompt names for the nodes role only"
  },
  {
   "id": "eks_policy_permissions",
   "kind": "all_of",
   "tier": "detail",
   "quote": "grants permissions for EKS cluster and nodegroup management, SSM parameter retrieval, IAM role and policy inspection",
   "checks": [
    {
     "kind": "attr",
     "select": "eks_policy",
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "(?i)eks:(\\*|[a-z]*cluster)"
     }
    },
    {
     "kind": "attr",
     "select": "eks_policy",
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "(?i)iam:(\\*|get|list)[a-z]*role"
     }
    },
    {
     "kind": "attr",
     "select": "eks_policy",
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "(?i)iam:(\\*|get|list)[a-z]*polic"
     }
    }
   ]
  },
  {
   "id": "eks_policy_kms_alias",
   "kind": "all_of",
   "tier": "detail",
   "quote": "KMS key operations conditioned on a specific alias pattern",
   "checks": [
    {
     "kind": "attr",
     "select": "eks_policy",
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "contains",
      "value": "kms:"
     }
    },
    {
     "kind": "attr",
     "select": "eks_policy",
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "contains",
      "value": "alias/"
     }
    }
   ]
  },
  {
   "id": "eks_policy_service_linked_roles",
   "kind": "all_of",
   "tier": "detail",
   "quote": "service-linked role creation for EKS, EKS nodegroups, and EKS Fargate",
   "checks": [
    {
     "kind": "attr",
     "select": "eks_policy",
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "contains",
      "value": "iam:CreateServiceLinkedRole"
     }
    },
    {
     "kind": "attr",
     "select": "eks_policy",
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "contains",
      "value": "eks-nodegroup"
     }
    },
    {
     "kind": "attr",
     "select": "eks_policy",
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "contains",
      "value": "eks-fargate"
     }
    }
   ]
  },
  {
   "id": "nodes_role_trust",
   "kind": "attr",
   "select": "nodes_role",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument"
    ],
    "op": "contains",
    "value": "ec2.amazonaws.com"
   },
   "tier": "detail",
   "quote": "the nodes role allows EC2 to assume it"
  },
  {
   "id": "nodes_role_cni_policy",
   "kind": "attr",
   "select": "nodes_role",
   "cond": {
    "path": [
     "ManagedPolicyArns"
    ],
    "op": "contains",
    "value": "AmazonEKS_CNI_Policy"
   },
   "tier": "core",
   "quote": "attached to both the AmazonEKSWorkerNodePolicy and AmazonEKS_CNI_Policy AWS-managed policies"
  },
  {
   "id": "nodes_policy_attached",
   "kind": "any_of",
   "tier": "core",
   "quote": "as well as a custom managed policy granting EC2, ECR, secrets manager",
   "checks": [
    {
     "kind": "ref",
     "from": "nodes_policy",
     "to": "nodes_role"
    },
    {
     "kind": "ref",
     "from": "nodes_role",
     "to": "nodes_policy"
    }
   ]
  },
  {
   "id": "nodes_policy_permissions",
   "kind": "all_of",
   "tier": "detail",
   "quote": "granting EC2, ECR, secrets manager (scoped to the aws.cluster.x-k8s.io secret path), SSM, and S3 permissions",
   "checks": [
    {
     "kind": "attr",
     "select": "nodes_policy",
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "contains",
      "value": "ec2:"
     }
    },
    {
     "kind": "attr",
     "select": "nodes_policy",
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "(?i)secretsmanager:"
     }
    },
    {
     "kind": "attr",
     "select": "nodes_policy",
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "contains",
      "value": "aws.cluster.x-k8s.io"
     }
    },
    {
     "kind": "attr",
     "select": "nodes_policy",
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "contains",
      "value": "ssm"
     }
    },
    {
     "kind": "attr",
     "select": "nodes_policy",
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "contains",
      "value": "s3:"
     }
    }
   ]
  },
  {
   "id": "eks_control_plane_role",
   "kind": "exists",
   "select": "eks_cluster_role",
   "tier": "core",
   "quote": "a separate EKS control plane role with the AmazonEKSClusterPolicy attached"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
