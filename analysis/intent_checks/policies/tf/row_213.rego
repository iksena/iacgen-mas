package intent.tf.row_213

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "cp_role": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "aws_ccm_k8s_controlplane"
    }
   ]
  },
  "cp_prof": {
   "types": [
    "aws_iam_instance_profile"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "aws_ccm_k8s_controlplane"
    }
   ]
  },
  "cp_pol": {
   "types": [
    "aws_iam_policy"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "aws_ccm_k8s_controlplane"
    }
   ]
  },
  "cp_pol_decl": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "aws_iam_policy"
    },
    {
     "path": [
      "properties",
      "name"
     ],
     "op": "eq",
     "value": "aws_ccm_k8s_controlplane"
    }
   ]
  },
  "cp_inl": {
   "types": [
    "aws_iam_role_policy"
   ],
   "where": [
    {
     "path": [
      "role"
     ],
     "op": "eq",
     "value": "aws_ccm_k8s_controlplane"
    },
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "aws_ccm_k8s_controlplane"
    }
   ]
  },
  "cp_att": {
   "types": [
    "aws_iam_role_policy_attachment"
   ],
   "where": [
    {
     "path": [
      "role"
     ],
     "op": "eq",
     "value": "aws_ccm_k8s_controlplane"
    }
   ]
  },
  "cp_patt": {
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
     "value": "aws_ccm_k8s_controlplane"
    }
   ]
  },
  "w_role": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "aws_ccm_k8s_worker"
    }
   ]
  },
  "w_prof": {
   "types": [
    "aws_iam_instance_profile"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "aws_ccm_k8s_worker"
    }
   ]
  },
  "w_pol": {
   "types": [
    "aws_iam_policy"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "aws_ccm_k8s_worker"
    }
   ]
  },
  "w_pol_decl": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "aws_iam_policy"
    },
    {
     "path": [
      "properties",
      "name"
     ],
     "op": "eq",
     "value": "aws_ccm_k8s_worker"
    }
   ]
  },
  "w_inl": {
   "types": [
    "aws_iam_role_policy"
   ],
   "where": [
    {
     "path": [
      "role"
     ],
     "op": "eq",
     "value": "aws_ccm_k8s_worker"
    },
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "aws_ccm_k8s_worker"
    }
   ]
  },
  "w_att": {
   "types": [
    "aws_iam_role_policy_attachment"
   ],
   "where": [
    {
     "path": [
      "role"
     ],
     "op": "eq",
     "value": "aws_ccm_k8s_worker"
    }
   ]
  },
  "w_patt": {
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
     "value": "aws_ccm_k8s_worker"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "cp_role",
   "kind": "exists",
   "select": "cp_role",
   "tier": "core",
   "quote": "two IAM roles for EC2 assume role access named \"aws_ccm_k8s_controlplane\""
  },
  {
   "id": "cp_role_ec2_trust",
   "kind": "any_of",
   "tier": "core",
   "quote": "IAM roles for EC2 assume role access",
   "checks": [
    {
     "kind": "attr",
     "select": "cp_role",
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "ec2.amazonaws.com"
     }
    },
    {
     "kind": "ref",
     "from": "cp_role",
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "ec2.amazonaws.com"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_iam_role"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "aws_ccm_k8s_controlplane"
       },
       {
        "path": [
         "properties",
         "assume_role_policy"
        ],
        "op": "contains",
        "value": "ec2.amazonaws.com"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "cp_profile",
   "kind": "any_of",
   "tier": "core",
   "quote": "each associated with a matching EC2 instance profile of the same name",
   "checks": [
    {
     "kind": "ref",
     "from": "cp_prof",
     "to": "cp_role"
    },
    {
     "kind": "join",
     "from": "cp_prof",
     "from_path": [
      "role"
     ],
     "to": "cp_role",
     "to_path": [
      "name"
     ]
    }
   ]
  },
  {
   "id": "cp_policy",
   "kind": "any_of",
   "tier": "core",
   "quote": "an IAM policy named \"aws_ccm_k8s_controlplane\"",
   "checks": [
    {
     "kind": "exists",
     "select": "cp_pol"
    },
    {
     "kind": "exists",
     "select": "cp_inl"
    }
   ]
  },
  {
   "id": "cp_attached",
   "kind": "any_of",
   "tier": "core",
   "quote": "The control plane role must be attached to an IAM policy",
   "checks": [
    {
     "kind": "ref",
     "from": "cp_att",
     "to": "cp_pol"
    },
    {
     "kind": "ref",
     "from": "cp_patt",
     "to": "cp_pol"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "role"
        ],
        "op": "absent"
       }
      ]
     },
     "to": "cp_pol"
    },
    {
     "kind": "ref",
     "from": "cp_role",
     "to": "cp_pol"
    },
    {
     "kind": "exists",
     "select": "cp_inl"
    }
   ]
  },
  {
   "id": "w_role",
   "kind": "exists",
   "select": "w_role",
   "tier": "core",
   "quote": "and \"aws_ccm_k8s_worker\""
  },
  {
   "id": "w_role_ec2_trust",
   "kind": "any_of",
   "tier": "core",
   "quote": "IAM roles for EC2 assume role access",
   "checks": [
    {
     "kind": "attr",
     "select": "w_role",
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "ec2.amazonaws.com"
     }
    },
    {
     "kind": "ref",
     "from": "w_role",
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "ec2.amazonaws.com"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_iam_role"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "aws_ccm_k8s_worker"
       },
       {
        "path": [
         "properties",
         "assume_role_policy"
        ],
        "op": "contains",
        "value": "ec2.amazonaws.com"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "w_profile",
   "kind": "any_of",
   "tier": "core",
   "quote": "each associated with a matching EC2 instance profile of the same name",
   "checks": [
    {
     "kind": "ref",
     "from": "w_prof",
     "to": "w_role"
    },
    {
     "kind": "join",
     "from": "w_prof",
     "from_path": [
      "role"
     ],
     "to": "w_role",
     "to_path": [
      "name"
     ]
    }
   ]
  },
  {
   "id": "w_policy",
   "kind": "any_of",
   "tier": "core",
   "quote": "an IAM policy named \"aws_ccm_k8s_worker\"",
   "checks": [
    {
     "kind": "exists",
     "select": "w_pol"
    },
    {
     "kind": "exists",
     "select": "w_inl"
    }
   ]
  },
  {
   "id": "w_attached",
   "kind": "any_of",
   "tier": "core",
   "quote": "The worker role must be attached to an IAM policy",
   "checks": [
    {
     "kind": "ref",
     "from": "w_att",
     "to": "w_pol"
    },
    {
     "kind": "ref",
     "from": "w_patt",
     "to": "w_pol"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "role"
        ],
        "op": "absent"
       }
      ]
     },
     "to": "w_pol"
    },
    {
     "kind": "ref",
     "from": "w_role",
     "to": "w_pol"
    },
    {
     "kind": "exists",
     "select": "w_inl"
    }
   ]
  },
  {
   "id": "tags_var",
   "kind": "exists",
   "tier": "detail",
   "quote": "a configurable map of tags defaulting to an empty map",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)tag"
     },
     {
      "path": [
       "default"
      ],
      "op": "regex",
      "value": "^\\{\\}$"
     }
    ]
   }
  },
  {
   "id": "cp_ec2_net",
   "kind": "any_of",
   "tier": "core",
   "quote": "granting global permissions for EC2 networking",
   "checks": [
    {
     "kind": "attr",
     "select": "cp_pol",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ec2:(\\*|[A-Za-z]*(Route|SecurityGroup|Subnet|Vpc|Network))"
     }
    },
    {
     "kind": "attr",
     "select": "cp_pol_decl",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ec2:(\\*|[A-Za-z]*(Route|SecurityGroup|Subnet|Vpc|Network))"
     }
    },
    {
     "kind": "ref",
     "from": "cp_pol",
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ec2:(\\*|[A-Za-z]*(Route|SecurityGroup|Subnet|Vpc|Network))"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "cp_inl",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ec2:(\\*|[A-Za-z]*(Route|SecurityGroup|Subnet|Vpc|Network))"
     }
    },
    {
     "kind": "ref",
     "from": "cp_inl",
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ec2:(\\*|[A-Za-z]*(Route|SecurityGroup|Subnet|Vpc|Network))"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "cp_asg_describe",
   "kind": "any_of",
   "tier": "core",
   "quote": "Auto Scaling group description",
   "checks": [
    {
     "kind": "attr",
     "select": "cp_pol",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)autoscaling:(Describe|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": "cp_pol_decl",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)autoscaling:(Describe|\\*)"
     }
    },
    {
     "kind": "ref",
     "from": "cp_pol",
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)autoscaling:(Describe|\\*)"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "cp_inl",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)autoscaling:(Describe|\\*)"
     }
    },
    {
     "kind": "ref",
     "from": "cp_inl",
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)autoscaling:(Describe|\\*)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "cp_elb",
   "kind": "any_of",
   "tier": "core",
   "quote": "Elastic Load Balancing management",
   "checks": [
    {
     "kind": "attr",
     "select": "cp_pol",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)elasticloadbalancing:(\\*|Add|Apply|Attach|Configure|Create|Delete|Deregister|Detach|Modify|Register|Remove|Set)"
     }
    },
    {
     "kind": "attr",
     "select": "cp_pol_decl",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)elasticloadbalancing:(\\*|Add|Apply|Attach|Configure|Create|Delete|Deregister|Detach|Modify|Register|Remove|Set)"
     }
    },
    {
     "kind": "ref",
     "from": "cp_pol",
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)elasticloadbalancing:(\\*|Add|Apply|Attach|Configure|Create|Delete|Deregister|Detach|Modify|Register|Remove|Set)"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "cp_inl",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)elasticloadbalancing:(\\*|Add|Apply|Attach|Configure|Create|Delete|Deregister|Detach|Modify|Register|Remove|Set)"
     }
    },
    {
     "kind": "ref",
     "from": "cp_inl",
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)elasticloadbalancing:(\\*|Add|Apply|Attach|Configure|Create|Delete|Deregister|Detach|Modify|Register|Remove|Set)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "cp_kms_describe",
   "kind": "any_of",
   "tier": "core",
   "quote": "KMS key description",
   "checks": [
    {
     "kind": "attr",
     "select": "cp_pol",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)kms:(DescribeKey|Describe\\*|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": "cp_pol_decl",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)kms:(DescribeKey|Describe\\*|\\*)"
     }
    },
    {
     "kind": "ref",
     "from": "cp_pol",
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)kms:(DescribeKey|Describe\\*|\\*)"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "cp_inl",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)kms:(DescribeKey|Describe\\*|\\*)"
     }
    },
    {
     "kind": "ref",
     "from": "cp_inl",
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)kms:(DescribeKey|Describe\\*|\\*)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "cp_slr",
   "kind": "any_of",
   "tier": "core",
   "quote": "service-linked role creation",
   "checks": [
    {
     "kind": "attr",
     "select": "cp_pol",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)iam:(CreateServiceLinkedRole|Create\\*|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": "cp_pol_decl",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)iam:(CreateServiceLinkedRole|Create\\*|\\*)"
     }
    },
    {
     "kind": "ref",
     "from": "cp_pol",
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)iam:(CreateServiceLinkedRole|Create\\*|\\*)"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "cp_inl",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)iam:(CreateServiceLinkedRole|Create\\*|\\*)"
     }
    },
    {
     "kind": "ref",
     "from": "cp_inl",
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)iam:(CreateServiceLinkedRole|Create\\*|\\*)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "w_ec2_describe_instances",
   "kind": "any_of",
   "tier": "core",
   "quote": "permissions to describe EC2 instances and regions",
   "checks": [
    {
     "kind": "attr",
     "select": "w_pol",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ec2:(DescribeInstances|Describe\\*|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": "w_pol_decl",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ec2:(DescribeInstances|Describe\\*|\\*)"
     }
    },
    {
     "kind": "ref",
     "from": "w_pol",
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ec2:(DescribeInstances|Describe\\*|\\*)"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "w_inl",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ec2:(DescribeInstances|Describe\\*|\\*)"
     }
    },
    {
     "kind": "ref",
     "from": "w_inl",
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ec2:(DescribeInstances|Describe\\*|\\*)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "w_ec2_describe_regions",
   "kind": "any_of",
   "tier": "core",
   "quote": "permissions to describe EC2 instances and regions",
   "checks": [
    {
     "kind": "attr",
     "select": "w_pol",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ec2:(DescribeRegions|Describe\\*|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": "w_pol_decl",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ec2:(DescribeRegions|Describe\\*|\\*)"
     }
    },
    {
     "kind": "ref",
     "from": "w_pol",
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ec2:(DescribeRegions|Describe\\*|\\*)"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "w_inl",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ec2:(DescribeRegions|Describe\\*|\\*)"
     }
    },
    {
     "kind": "ref",
     "from": "w_inl",
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ec2:(DescribeRegions|Describe\\*|\\*)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "w_ecr_read",
   "kind": "any_of",
   "tier": "core",
   "quote": "read-only access to ECR repositories to fetch container images",
   "checks": [
    {
     "kind": "attr",
     "select": "w_pol",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ecr:(BatchGetImage|GetDownloadUrlForLayer|BatchGet\\*|Get\\*)"
     }
    },
    {
     "kind": "attr",
     "select": "w_pol_decl",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ecr:(BatchGetImage|GetDownloadUrlForLayer|BatchGet\\*|Get\\*)"
     }
    },
    {
     "kind": "ref",
     "from": "w_pol",
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ecr:(BatchGetImage|GetDownloadUrlForLayer|BatchGet\\*|Get\\*)"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "w_inl",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ecr:(BatchGetImage|GetDownloadUrlForLayer|BatchGet\\*|Get\\*)"
     }
    },
    {
     "kind": "ref",
     "from": "w_inl",
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ecr:(BatchGetImage|GetDownloadUrlForLayer|BatchGet\\*|Get\\*)"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "role"
        ],
        "op": "eq",
        "value": "aws_ccm_k8s_worker"
       },
       {
        "path": [
         "policy_arn"
        ],
        "op": "contains",
        "value": "AmazonEC2ContainerRegistryReadOnly"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "w_role",
     "cond": {
      "path": [
       "managed_policy_arns",
       "*"
      ],
      "op": "contains",
      "value": "AmazonEC2ContainerRegistryReadOnly"
     }
    }
   ]
  },
  {
   "id": "cp_global_resource",
   "kind": "any_of",
   "tier": "detail",
   "quote": "granting global permissions",
   "checks": [
    {
     "kind": "attr",
     "select": "cp_pol",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)resources?[\"']?: *\\[?[\"']\\*[\"']"
     }
    },
    {
     "kind": "attr",
     "select": "cp_pol_decl",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)resources?[\"']?: *\\[?[\"']\\*[\"']"
     }
    },
    {
     "kind": "ref",
     "from": "cp_pol",
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)resources?[\"']?: *\\[?[\"']\\*[\"']"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "cp_inl",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)resources?[\"']?: *\\[?[\"']\\*[\"']"
     }
    },
    {
     "kind": "ref",
     "from": "cp_inl",
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)resources?[\"']?: *\\[?[\"']\\*[\"']"
       }
      ]
     }
    }
   ],
   "justify": "\"global permissions\" implies Resource \"*\""
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
