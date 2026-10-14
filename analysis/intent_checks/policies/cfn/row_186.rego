# GENERATED from specs/cfn/row_186.json by intent_checks/build.py -- do not edit.
package intent.cfn.row_186

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
      "Service"
     ],
     "op": "contains",
     "value": "ec2.amazonaws.com"
    }
   ]
  },
  "ctrl_role": {
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
      "Service"
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
     "op": "contains",
     "value": "pods.eks.amazonaws.com"
    }
   ]
  },
  "eks_cp_role": {
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
      "Service"
     ],
     "op": "regex",
     "value": "(^|[^.a-z])eks\\.amazonaws\\.com"
    }
   ]
  },
  "iprof": {
   "types": [
    "AWS::IAM::InstanceProfile"
   ],
   "where": []
  },
  "cp_cloud_pol": {
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
     "value": "autoscaling:"
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
     "value": "kms:"
    }
   ]
  },
  "nodes_pol": {
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
     "value": "ecr:"
    },
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "contains",
     "value": "secretsmanager:"
    },
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "contains",
     "value": "ssm"
    }
   ]
  },
  "eks_pol_l": {
   "types": [
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
     "value": "eks:CreateCluster"
    },
    {
     "path": [
      "PolicyDocument",
      "Statement",
      "*",
      "Action",
      "*"
     ],
     "op": "glob_covers",
     "value": "eks:CreateNodegroup"
    },
    {
     "path": [
      "PolicyDocument",
      "Statement",
      "*",
      "Action",
      "*"
     ],
     "op": "glob_covers",
     "value": "eks:CreateAddon"
    },
    {
     "path": [
      "PolicyDocument",
      "Statement",
      "*",
      "Action",
      "*"
     ],
     "op": "glob_covers",
     "value": "eks:CreateFargateProfile"
    }
   ]
  },
  "eks_pol_s": {
   "types": [
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
     "value": "eks:CreateCluster"
    },
    {
     "path": [
      "PolicyDocument",
      "Statement",
      "*",
      "Action"
     ],
     "op": "glob_covers",
     "value": "eks:CreateNodegroup"
    },
    {
     "path": [
      "PolicyDocument",
      "Statement",
      "*",
      "Action"
     ],
     "op": "glob_covers",
     "value": "eks:CreateAddon"
    },
    {
     "path": [
      "PolicyDocument",
      "Statement",
      "*",
      "Action"
     ],
     "op": "glob_covers",
     "value": "eks:CreateFargateProfile"
    }
   ]
  },
  "console_pol_l": {
   "types": [
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
     "value": "eks:DescribeCluster"
    },
    {
     "path": [
      "PolicyDocument",
      "Statement",
      "*",
      "Action",
      "*"
     ],
     "op": "glob_covers",
     "value": "eks:ListClusters"
    },
    {
     "path": [
      "PolicyDocument",
      "Statement",
      "*",
      "Action",
      "*"
     ],
     "op": "glob_covers",
     "value": "eks:DescribeNodegroup"
    },
    {
     "path": [
      "Roles"
     ],
     "op": "absent"
    }
   ]
  },
  "console_pol_s": {
   "types": [
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
     "value": "eks:DescribeCluster"
    },
    {
     "path": [
      "PolicyDocument",
      "Statement",
      "*",
      "Action"
     ],
     "op": "glob_covers",
     "value": "eks:ListClusters"
    },
    {
     "path": [
      "PolicyDocument",
      "Statement",
      "*",
      "Action"
     ],
     "op": "glob_covers",
     "value": "eks:DescribeNodegroup"
    },
    {
     "path": [
      "Roles"
     ],
     "op": "absent"
    }
   ]
  },
  "console_any": {
   "types": [
    "AWS::IAM::ManagedPolicy"
   ],
   "where": [
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "contains",
     "value": "eks:"
    },
    {
     "path": [
      "Roles"
     ],
     "op": "absent"
    }
   ]
  },
  "ctrl_pol": {
   "types": [
    "AWS::IAM::ManagedPolicy"
   ],
   "where": [
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "(?i)ec2:"
    },
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "(?i)ec2:(\\*|[A-Za-z*]*LaunchTemplate)"
    },
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "(?i)autoscaling:"
    },
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "(?i)elasticloadbalancing:"
    },
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "(?i)iam:(CreateServiceLinkedRole|\\*)"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "three_ec2_roles",
   "kind": "exists",
   "select": "ec2_role",
   "min": 3,
   "max": 3,
   "tier": "core",
   "quote": "three IAM roles assumable by EC2"
  },
  {
   "id": "controllers_role_eks_pods",
   "kind": "exists",
   "select": "ctrl_role",
   "tier": "core",
   "quote": "a controllers role that is also assumable by EKS pods"
  },
  {
   "id": "eks_control_plane_role",
   "kind": "exists",
   "select": "eks_cp_role",
   "tier": "core",
   "quote": "a separate EKS control plane role assumable by the EKS service"
  },
  {
   "id": "eks_cluster_policy_attached",
   "kind": "attr",
   "select": "eks_cp_role",
   "tier": "core",
   "quote": "with the AWS managed EKS cluster policy attached",
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
   "id": "three_instance_profiles",
   "kind": "exists",
   "select": "iprof",
   "min": 3,
   "tier": "core",
   "quote": "matching instance profiles for the control-plane, controllers, and nodes roles",
   "justify": "three instance profiles stated: control-plane, controllers, nodes"
  },
  {
   "id": "instance_profiles_wrap_ec2_roles",
   "kind": "ref",
   "tier": "detail",
   "quote": "matching instance profiles for the control-plane, controllers, and nodes roles",
   "from": "iprof",
   "to": "ec2_role"
  },
  {
   "id": "cloud_provider_control_plane_policy",
   "kind": "ref",
   "from": "cp_cloud_pol",
   "to": "ec2_role",
   "bidirectional": true,
   "tier": "core",
   "quote": "granting the control plane role the EC2, Auto Scaling, load balancer, and KMS permissions needed to run the legacy in-tree AWS cloud provider",
   "justify": "\"load balancer\" permissions are the elasticloadbalancing: service prefix"
  },
  {
   "id": "nodes_policy",
   "kind": "ref",
   "from": "nodes_pol",
   "to": "ec2_role",
   "bidirectional": true,
   "tier": "core",
   "quote": "the EC2, ECR, Secrets Manager, and SSM permissions needed for cluster nodes to register and pull images"
  },
  {
   "id": "nodes_policy_two_roles",
   "kind": "any_of",
   "tier": "detail",
   "quote": "granting both the control plane and nodes roles",
   "checks": [
    {
     "kind": "attr",
     "select": "nodes_pol",
     "cond": {
      "path": [
       "Roles"
      ],
      "op": "len_gte",
      "value": 2
     }
    },
    {
     "kind": "exists",
     "select": "nodes_pol",
     "min": 2
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
         "Service"
        ],
        "op": "contains",
        "value": "ec2.amazonaws.com"
       },
       {
        "path": [
         "ManagedPolicyArns",
         "*",
         "ref"
        ],
        "op": "present"
       }
      ]
     },
     "min": 2
    }
   ],
   "justify": "two roles stated: control plane and nodes"
  },
  {
   "id": "controllers_policy",
   "kind": "ref",
   "tier": "core",
   "quote": "the broad EC2 networking, Auto Scaling, load balancer, launch template, and service-linked-role permissions needed by the Cluster API controllers",
   "from": "ctrl_pol",
   "to": "ec2_role",
   "bidirectional": true,
   "justify": "\"load balancer\" permissions are the elasticloadbalancing: service prefix; launch template and service-linked-role grants are stated"
  },
  {
   "id": "controllers_policy_two_roles",
   "kind": "any_of",
   "tier": "detail",
   "quote": "granting the controllers and control-plane roles the broad EC2 networking",
   "checks": [
    {
     "kind": "attr",
     "select": "ctrl_pol",
     "cond": {
      "path": [
       "Roles"
      ],
      "op": "len_gte",
      "value": 2
     }
    },
    {
     "kind": "exists",
     "select": "ctrl_pol",
     "min": 2
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
         "Service"
        ],
        "op": "contains",
        "value": "ec2.amazonaws.com"
       },
       {
        "path": [
         "ManagedPolicyArns",
         "*",
         "ref"
        ],
        "op": "present"
       }
      ]
     },
     "min": 2
    }
   ],
   "justify": "two roles stated: controllers and control-plane"
  },
  {
   "id": "eks_policy",
   "kind": "any_of",
   "tier": "core",
   "quote": "EKS-specific permissions to create and manage EKS clusters, node groups, add-ons, Fargate profiles",
   "checks": [
    {
     "kind": "ref",
     "from": "eks_pol_l",
     "to": "ec2_role",
     "bidirectional": true
    },
    {
     "kind": "ref",
     "from": "eks_pol_s",
     "to": "ec2_role",
     "bidirectional": true
    }
   ]
  },
  {
   "id": "eks_policy_two_roles",
   "kind": "any_of",
   "tier": "detail",
   "quote": "granting the controllers and control-plane roles EKS-specific permissions",
   "checks": [
    {
     "kind": "attr",
     "select": "eks_pol_l",
     "cond": {
      "path": [
       "Roles"
      ],
      "op": "len_gte",
      "value": 2
     }
    },
    {
     "kind": "attr",
     "select": "eks_pol_s",
     "cond": {
      "path": [
       "Roles"
      ],
      "op": "len_gte",
      "value": 2
     }
    },
    {
     "kind": "exists",
     "select": "eks_pol_l",
     "min": 2
    },
    {
     "kind": "exists",
     "select": "eks_pol_s",
     "min": 2
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
         "Service"
        ],
        "op": "contains",
        "value": "ec2.amazonaws.com"
       },
       {
        "path": [
         "ManagedPolicyArns",
         "*",
         "ref"
        ],
        "op": "present"
       }
      ]
     },
     "min": 2
    }
   ],
   "justify": "two roles stated: controllers and control-plane"
  },
  {
   "id": "eks_policy_iam_kms",
   "kind": "attr",
   "tier": "detail",
   "quote": "and related IAM and KMS operations",
   "select": {
    "types": [
     "AWS::IAM::ManagedPolicy"
    ],
    "where": [
     {
      "path": [
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "(?i)eks:"
     }
    ]
   },
   "cond": {
    "path": [],
    "op": "match",
    "value": [
     {
      "path": [
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "(?i)iam:"
     },
     {
      "path": [
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "(?i)kms:"
     }
    ]
   }
  },
  {
   "id": "eks_console_policy_unattached",
   "kind": "any_of",
   "tier": "core",
   "quote": "a standalone managed IAM policy intended for human users or groups that only need read only visibility into EKS clusters, node groups, and workloads through the console, without attaching it to any role",
   "checks": [
    {
     "kind": "exists",
     "select": "console_pol_l"
    },
    {
     "kind": "exists",
     "select": "console_pol_s"
    }
   ]
  },
  {
   "id": "eks_console_policy_read_only",
   "kind": "any_of",
   "tier": "detail",
   "quote": "only need read only visibility into EKS clusters, node groups, and workloads",
   "checks": [
    {
     "kind": "attr",
     "select": "console_any",
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "regex",
      "value": "(?i)^[a-z0-9-]+:(Describe|List|Get|AccessKubernetesApi)[A-Za-z*]*$",
      "every": true
     }
    },
    {
     "kind": "attr",
     "select": "console_any",
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*",
       "Action"
      ],
      "op": "regex",
      "value": "(?i)^[a-z0-9-]+:(Describe|List|Get|AccessKubernetesApi)[A-Za-z*]*$",
      "every": true
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
