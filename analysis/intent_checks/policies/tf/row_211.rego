package intent.tf.row_211

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "master_role": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "tf-legion"
    }
   ]
  },
  "node_role": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "tf-legion-node"
    }
   ]
  },
  "as_policy_named": {
   "types": [
    "aws_iam_policy",
    "aws_iam_role_policy"
   ],
   "where": [
    {
     "path": [
      "policy"
     ],
     "op": "contains",
     "value": "autoscaling:SetDesiredCapacity"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "cluster_name_var",
   "kind": "exists",
   "tier": "detail",
   "quote": "declare a cluster_name variable defaulting to \"legion\"",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "cluster_name"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "legion"
     }
    ]
   }
  },
  {
   "id": "master_role_named",
   "kind": "exists",
   "select": "master_role",
   "tier": "core",
   "quote": "one named with a \"tf-\" prefix followed by the cluster name value for the master control plane"
  },
  {
   "id": "node_role_named",
   "kind": "exists",
   "select": "node_role",
   "tier": "core",
   "quote": "another named with the same prefix followed by the cluster name value and a \"-node\" suffix for the worker nodes"
  },
  {
   "id": "master_trusts_eks",
   "kind": "attr",
   "select": "master_role",
   "tier": "core",
   "quote": "The master role must allow assume role trust for the EKS service",
   "cond": {
    "path": [
     "assume_role_policy"
    ],
    "op": "contains",
    "value": "eks.amazonaws.com"
   }
  },
  {
   "id": "master_cluster_policy",
   "kind": "ref",
   "tier": "core",
   "to": "master_role",
   "quote": "attach the AWS managed policies \"AmazonEKSClusterPolicy\"",
   "from": {
    "types": [
     "aws_iam_role_policy_attachment",
     "aws_iam_policy_attachment"
    ],
    "where": [
     {
      "path": [
       "policy_arn"
      ],
      "op": "regex",
      "value": "policy/AmazonEKSClusterPolicy$"
     }
    ]
   }
  },
  {
   "id": "master_service_policy",
   "kind": "ref",
   "tier": "detail",
   "to": "master_role",
   "quote": "\"AmazonEKSServicePolicy\"",
   "from": {
    "types": [
     "aws_iam_role_policy_attachment",
     "aws_iam_policy_attachment"
    ],
    "where": [
     {
      "path": [
       "policy_arn"
      ],
      "op": "regex",
      "value": "policy/AmazonEKSServicePolicy$"
     }
    ]
   }
  },
  {
   "id": "node_trusts_ec2",
   "kind": "attr",
   "select": "node_role",
   "tier": "core",
   "quote": "The worker node role must allow assume role trust for EC2",
   "cond": {
    "path": [
     "assume_role_policy"
    ],
    "op": "contains",
    "value": "ec2.amazonaws.com"
   }
  },
  {
   "id": "node_managed_policies",
   "kind": "all_of",
   "tier": "core",
   "quote": "attach the managed policies \"AmazonEKSWorkerNodePolicy\", \"AmazonEKS_CNI_Policy\", and \"AmazonEC2ContainerRegistryReadOnly\"",
   "checks": [
    {
     "kind": "ref",
     "to": "node_role",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment",
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "policy/AmazonEKSWorkerNodePolicy$"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "node_role",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment",
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "policy/AmazonEKS_CNI_Policy$"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "node_role",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment",
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "policy/AmazonEC2ContainerRegistryReadOnly$"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "node_instance_profile",
   "kind": "ref",
   "tier": "detail",
   "to": "node_role",
   "quote": "be associated with a matching EC2 instance profile whose name follows the same \"tf-\" prefix, cluster name value, and \"-node\" suffix pattern",
   "from": {
    "types": [
     "aws_iam_instance_profile"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "tf-legion-node"
     }
    ]
   }
  },
  {
   "id": "autoscaling_policy_prefix",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a custom, dynamically-generated IAM policy whose name is prefixed with \"eks-worker-autoscaling-\" followed by the cluster name value",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name_prefix"
      ],
      "op": "regex",
      "value": "^eks-worker-autoscaling-legion"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "^eks-worker-autoscaling-legion"
     }
    }
   ]
  },
  {
   "id": "autoscaling_policy_on_node_role",
   "kind": "any_of",
   "tier": "core",
   "quote": "the worker node role must be attached to a custom, dynamically-generated IAM policy",
   "checks": [
    {
     "kind": "ref",
     "to": "as_policy_named",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "role"
        ],
        "op": "eq",
        "value": "tf-legion-node"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "as_policy_named",
     "from": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "roles",
         "*"
        ],
        "op": "eq",
        "value": "tf-legion-node"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "as_policy_named",
     "to": "node_role"
    }
   ]
  },
  {
   "id": "autoscaling_describe_global",
   "kind": "all_of",
   "tier": "detail",
   "quote": "permitting global describe actions for Auto Scaling groups, Auto Scaling instances, launch configurations, tags, and launch template versions",
   "checks": [
    {
     "kind": "attr",
     "select": "as_policy_named",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "autoscaling:Describe(AutoScalingGroups|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": "as_policy_named",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "autoscaling:Describe(AutoScalingInstances|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": "as_policy_named",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "autoscaling:Describe(LaunchConfigurations|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": "as_policy_named",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "autoscaling:Describe(Tags|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": "as_policy_named",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(ec2|autoscaling):Describe(LaunchTemplateVersions|\\*)"
     }
    }
   ]
  },
  {
   "id": "autoscaling_modify_actions",
   "kind": "all_of",
   "tier": "detail",
   "quote": "restricting capacity modification actions (\"autoscaling:SetDesiredCapacity\", \"autoscaling:TerminateInstanceInAutoScalingGroup\", and \"autoscaling:UpdateAutoScalingGroup\")",
   "checks": [
    {
     "kind": "attr",
     "select": "as_policy_named",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "contains",
      "value": "autoscaling:SetDesiredCapacity"
     }
    },
    {
     "kind": "attr",
     "select": "as_policy_named",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "contains",
      "value": "autoscaling:TerminateInstanceInAutoScalingGroup"
     }
    },
    {
     "kind": "attr",
     "select": "as_policy_named",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "contains",
      "value": "autoscaling:UpdateAutoScalingGroup"
     }
    }
   ]
  },
  {
   "id": "modify_restricted_by_tags",
   "kind": "all_of",
   "tier": "core",
   "quote": "strictly to resources tagged with a key of \"kubernetes.io/cluster/\" followed by the cluster name value, equal to \"owned\", and \"k8s.io/cluster-autoscaler/enabled\" equal to \"true\"",
   "checks": [
    {
     "kind": "attr",
     "select": "as_policy_named",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "ResourceTag/kubernetes\\.io/cluster/legion\\\"\\s*:\\s*\\[?\\s*\\\"owned\\\""
     }
    },
    {
     "kind": "attr",
     "select": "as_policy_named",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "ResourceTag/k8s\\.io/cluster-autoscaler/enabled\\\"\\s*:\\s*\\[?\\s*\\\"true\\\""
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
