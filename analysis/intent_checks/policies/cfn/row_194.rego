package intent.cfn.row_194

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
  "ec2_roles": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "regex",
     "value": "ec2\\.amazonaws\\.com"
    }
   ]
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
     "op": "regex",
     "value": "ec2\\.amazonaws\\.com"
    },
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "regex",
     "value": "pods\\.eks\\.amazonaws\\.com|AssumeRoleWithWebIdentity"
    }
   ]
  },
  "profiles": {
   "types": [
    "AWS::IAM::InstanceProfile"
   ],
   "where": []
  },
  "eks_cp_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "regex",
     "value": "(^|[^.\\w-])eks\\.amazonaws\\.com"
    },
    {
     "path": [
      "ManagedPolicyArns",
      "*"
     ],
     "op": "regex",
     "value": "AmazonEKSClusterPolicy"
    }
   ]
  },
  "fargate_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "regex",
     "value": "eks-fargate-pods\\.amazonaws\\.com"
    },
    {
     "path": [
      "ManagedPolicyArns",
      "*"
     ],
     "op": "regex",
     "value": "AmazonEKSFargatePodExecutionRolePolicy"
    }
   ]
  },
  "ng_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "regex",
     "value": "ec2\\.amazonaws\\.com"
    },
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "regex",
     "value": "(^|[^.\\w-])eks\\.amazonaws\\.com"
    }
   ]
  },
  "ng_role_pols": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "regex",
     "value": "ec2\\.amazonaws\\.com"
    },
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "regex",
     "value": "(^|[^.\\w-])eks\\.amazonaws\\.com"
    },
    {
     "path": [
      "ManagedPolicyArns",
      "*"
     ],
     "op": "regex",
     "value": "AmazonEKSWorkerNodePolicy"
    },
    {
     "path": [
      "ManagedPolicyArns",
      "*"
     ],
     "op": "regex",
     "value": "AmazonEKS_CNI_Policy"
    },
    {
     "path": [
      "ManagedPolicyArns",
      "*"
     ],
     "op": "regex",
     "value": "AmazonEC2ContainerRegistryReadOnly"
    }
   ]
  },
  "pol_a": {
   "types": [
    "AWS::IAM::ManagedPolicy"
   ],
   "where": [
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "(^|[^:])ec2:"
    },
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "(^|[^:])autoscaling:"
    },
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "(^|[^:])elasticloadbalancing:"
    },
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "(^|[^:])kms:"
    }
   ]
  },
  "pol_b": {
   "types": [
    "AWS::IAM::ManagedPolicy"
   ],
   "where": [
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "(^|[^:])ec2:"
    },
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "(^|[^:])ecr:"
    },
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "(^|[^:])secretsmanager:"
    },
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "(^|[^:])ssm:"
    }
   ]
  },
  "pol_c": {
   "types": [
    "AWS::IAM::ManagedPolicy"
   ],
   "where": [
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "(^|[^:])ec2:"
    },
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "(^|[^:])autoscaling:"
    },
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "(^|[^:])elasticloadbalancing:"
    },
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "(?i)launchtemplate"
    },
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "iam:CreateServiceLinkedRole"
    }
   ]
  },
  "pol_d": {
   "types": [
    "AWS::IAM::ManagedPolicy"
   ],
   "where": [
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "(?i)(^|[^:])eks:(\\*|Create\\*|CreateCluster\\*?)([^A-Za-z0-9_]|$)"
    },
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "(?i)(^|[^:])eks:(\\*|Create\\*|CreateNodegroup\\*?)([^A-Za-z0-9_]|$)"
    },
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "(?i)(^|[^:])eks:(\\*|Create\\*|CreateAddon\\*?)([^A-Za-z0-9_]|$)"
    },
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "(?i)(^|[^:])eks:(\\*|Create\\*|CreateFargate\\*|CreateFargateProfile\\*?)([^A-Za-z0-9_]|$)"
    },
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "(^|[^:])iam:"
    },
    {
     "path": [
      "PolicyDocument"
     ],
     "op": "regex",
     "value": "(^|[^:])kms:"
    }
   ]
  },
  "mpols": {
   "types": [
    "AWS::IAM::ManagedPolicy"
   ],
   "where": []
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
     "op": "regex",
     "value": "ec2\\.amazonaws\\.com"
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
     "value": "eks.amazonaws.com"
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
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Action",
      "*"
     ],
     "op": "none_eq",
     "value": "sts:AssumeRoleWithWebIdentity"
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
  "nodes_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "regex",
     "value": "ec2\\.amazonaws\\.com"
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
     "value": "eks.amazonaws.com"
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
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Action",
      "*"
     ],
     "op": "none_eq",
     "value": "sts:AssumeRoleWithWebIdentity"
    },
    {
     "path": [
      "ManagedPolicyArns",
      "*"
     ],
     "op": "regex",
     "value": "AmazonEKSWorkerNodePolicy"
    },
    {
     "path": [
      "ManagedPolicyArns",
      "*"
     ],
     "op": "regex",
     "value": "AmazonEKS_CNI_Policy"
    },
    {
     "path": [
      "ManagedPolicyArns",
      "*"
     ],
     "op": "regex",
     "value": "AmazonEC2ContainerRegistryReadOnly"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "ec2_roles",
   "tier": "core",
   "quote": "IAM roles assumable by EC2 for the control plane, controllers (also assumable by EKS pods), and nodes",
   "kind": "exists",
   "select": "ec2_roles",
   "min": 4,
   "justify": "control plane, controllers and nodes roles, plus the node group role that is also assumable by EC2"
  },
  {
   "id": "controllers_role_ec2_and_pods",
   "tier": "core",
   "quote": "controllers (also assumable by EKS pods)",
   "kind": "exists",
   "select": "controllers_role",
   "justify": "EKS pod identity trusts pods.eks.amazonaws.com; IRSA uses web-identity federation"
  },
  {
   "id": "instance_profiles",
   "kind": "exists",
   "select": "profiles",
   "min": 3,
   "tier": "core",
   "quote": "matching instance profiles for those three roles",
   "justify": "one per role"
  },
  {
   "id": "instance_profiles_distinct_roles",
   "kind": "exists",
   "select": "profiles",
   "min": 3,
   "distinct_path": [
    "Roles",
    0
   ],
   "tier": "detail",
   "quote": "matching instance profiles for those three roles",
   "justify": "each profile matches a different role"
  },
  {
   "id": "instance_profiles_ref_roles",
   "tier": "detail",
   "quote": "matching instance profiles for those three roles",
   "kind": "all_of",
   "checks": [
    {
     "kind": "ref",
     "from": "profiles",
     "to": "controllers_role"
    },
    {
     "kind": "ref",
     "from": "profiles",
     "to": "cp_role"
    }
   ],
   "justify": "the control-plane and nodes roles are told apart by the trust and AWS managed worker policies the prompt states: EC2-only, no EKS pods or web identity, and only the nodes role carries the worker node policy"
  },
  {
   "id": "eks_control_plane_role",
   "kind": "exists",
   "select": "eks_cp_role",
   "tier": "core",
   "quote": "an EKS control plane role assumable by the EKS service with the AWS managed EKS cluster policy attached"
  },
  {
   "id": "fargate_role",
   "kind": "exists",
   "select": "fargate_role",
   "tier": "core",
   "quote": "an EKS Fargate execution role assumable by the EKS Fargate pods service with the AWS managed Fargate pod execution policy attached"
  },
  {
   "id": "nodegroup_role_trust",
   "kind": "exists",
   "select": "ng_role",
   "tier": "core",
   "quote": "an EKS managed node group role assumable by both EC2 and EKS"
  },
  {
   "id": "nodegroup_role_policies",
   "kind": "exists",
   "select": "ng_role_pols",
   "tier": "core",
   "quote": "with the AWS managed worker node, CNI, and container registry read only policies attached"
  },
  {
   "id": "worker_policies_on_nodes_role_too",
   "tier": "core",
   "quote": "in addition to attaching those same three worker node policies directly to the plain nodes role",
   "kind": "exists",
   "select": "nodes_role",
   "justify": "the plain nodes role is assumable by EC2 only, not EKS, and carries the three policies"
  },
  {
   "id": "customer_managed_policies",
   "kind": "exists",
   "select": "mpols",
   "min": 3,
   "tier": "core",
   "quote": "Attach customer managed IAM policies",
   "justify": "at least three distinct permission sets; two may share a policy"
  },
  {
   "id": "policy_cloud_provider_control_plane",
   "kind": "ref",
   "tier": "core",
   "quote": "granting the control plane role the EC2, Auto Scaling, load balancer, and KMS permissions needed to run the legacy in-tree AWS cloud provider",
   "justify": "load balancer permissions use the elasticloadbalancing IAM prefix",
   "bidirectional": true,
   "from": "pol_a",
   "to": "ec2_roles"
  },
  {
   "id": "policy_nodes_registration",
   "kind": "ref",
   "tier": "core",
   "quote": "granting both the control plane and nodes roles the EC2, ECR, Secrets Manager, and SSM permissions needed for cluster nodes to register and pull images",
   "bidirectional": true,
   "from": "pol_b",
   "to": "ec2_roles"
  },
  {
   "id": "policy_capi_controllers",
   "kind": "ref",
   "tier": "core",
   "quote": "the broad EC2 networking, Auto Scaling, load balancer, launch template, and service-linked-role permissions needed by the Cluster API controllers",
   "justify": "load balancer permissions use the elasticloadbalancing IAM prefix",
   "bidirectional": true,
   "from": "pol_c",
   "to": "ec2_roles"
  },
  {
   "id": "policy_eks_management",
   "kind": "ref",
   "tier": "core",
   "quote": "EKS-specific permissions to create and manage EKS clusters, node groups, add-ons, Fargate profiles, and related IAM and KMS operations",
   "bidirectional": true,
   "from": "pol_d",
   "to": "ec2_roles"
  },
  {
   "id": "attach_cloud_provider_policy",
   "tier": "detail",
   "quote": "granting the control plane role the EC2, Auto Scaling, load balancer, and KMS permissions",
   "kind": "ref",
   "bidirectional": true,
   "from": "pol_a",
   "to": "cp_role",
   "justify": "load balancer permissions use the elasticloadbalancing IAM prefix"
  },
  {
   "id": "attach_nodes_policy",
   "tier": "detail",
   "quote": "granting both the control plane and nodes roles",
   "kind": "all_of",
   "checks": [
    {
     "kind": "ref",
     "bidirectional": true,
     "from": "pol_b",
     "to": "cp_role"
    },
    {
     "kind": "ref",
     "bidirectional": true,
     "from": "pol_b",
     "to": "nodes_role"
    }
   ],
   "justify": "the control-plane and nodes roles are told apart by the trust and AWS managed worker policies the prompt states: EC2-only, no EKS pods or web identity, and only the nodes role carries the worker node policy"
  },
  {
   "id": "attach_controllers_policy",
   "tier": "detail",
   "quote": "granting the controllers and control-plane roles the broad EC2 networking",
   "kind": "all_of",
   "justify": "load balancer permissions use the elasticloadbalancing IAM prefix",
   "checks": [
    {
     "kind": "ref",
     "bidirectional": true,
     "from": "pol_c",
     "to": "controllers_role"
    },
    {
     "kind": "ref",
     "bidirectional": true,
     "from": "pol_c",
     "to": "cp_role"
    }
   ]
  },
  {
   "id": "attach_eks_policy",
   "tier": "detail",
   "quote": "granting the controllers and control-plane roles EKS-specific permissions",
   "kind": "all_of",
   "checks": [
    {
     "kind": "ref",
     "bidirectional": true,
     "from": "pol_d",
     "to": "controllers_role"
    },
    {
     "kind": "ref",
     "bidirectional": true,
     "from": "pol_d",
     "to": "cp_role"
    }
   ],
   "justify": "the control-plane and nodes roles are told apart by the trust and AWS managed worker policies the prompt states: EC2-only, no EKS pods or web identity, and only the nodes role carries the worker node policy"
  },
  {
   "id": "x_controllers_tag_session",
   "kind": "attr",
   "select": "controllers_role",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument"
    ],
    "op": "regex",
    "value": "sts:TagSession"
   },
   "tier": "extra"
  },
  {
   "id": "x_slr_condition",
   "kind": "attr",
   "select": "pol_d",
   "cond": {
    "path": [
     "PolicyDocument"
    ],
    "op": "regex",
    "value": "iam:AWSServiceName"
   },
   "tier": "extra"
  },
  {
   "id": "x_secrets_delete",
   "kind": "attr",
   "select": "pol_b",
   "cond": {
    "path": [
     "PolicyDocument"
    ],
    "op": "regex",
    "value": "secretsmanager:(\\*|GetSecretValue)"
   },
   "tier": "extra"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
