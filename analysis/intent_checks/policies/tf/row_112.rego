package intent.tf.row_112

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "user",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_user"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "terraform-bot"
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
        "op": "eq",
        "value": "aws_iam_user"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "name"
      ],
      "op": "eq",
      "value": "terraform-bot"
     }
    }
   ],
   "quote": "a dedicated IAM deployment identity named \"terraform-bot\""
  },
  {
   "id": "policy",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_iam_policy"
    ],
    "where": []
   },
   "quote": "a custom IAM policy named \"terraform-policy\""
  },
  {
   "id": "policy_name",
   "tier": "core",
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
    "op": "eq",
    "value": "terraform-policy"
   },
   "quote": "a custom IAM policy named \"terraform-policy\""
  },
  {
   "id": "policy_path",
   "tier": "detail",
   "kind": "attr",
   "select": {
    "types": [
     "aws_iam_policy"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "path"
    ],
    "op": "eq",
    "value": "/"
   },
   "quote": "under path \"/\""
  },
  {
   "id": "policy_desc",
   "tier": "detail",
   "kind": "attr",
   "select": {
    "types": [
     "aws_iam_policy"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "description"
    ],
    "op": "eq",
    "value": "Permissions for Terraform-controlled EKS cluster creation and management"
   },
   "quote": "the description \"Permissions for Terraform-controlled EKS cluster creation and management\""
  },
  {
   "id": "policy_resources",
   "tier": "detail",
   "kind": "any_of",
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
       "policy"
      ],
      "op": "regex",
      "value": "(?is)([\"']Resource[\"']\\s*:\\s*\\[?\\s*[\"']\\*[\"']|resources\\s*:\\s*\\[\\*\\]|resources\\W+\\*)"
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
        "op": "eq",
        "value": "aws_iam_policy"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?is)([\"']Resource[\"']\\s*:\\s*\\[?\\s*[\"']\\*[\"']|resources\\s*:\\s*\\[\\*\\]|resources\\W+\\*)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "statement"
      ],
      "op": "regex",
      "value": "(?is)([\"']Resource[\"']\\s*:\\s*\\[?\\s*[\"']\\*[\"']|resources\\s*:\\s*\\[\\*\\]|resources\\W+\\*)"
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
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?is)([\"']Resource[\"']\\s*:\\s*\\[?\\s*[\"']\\*[\"']|resources\\s*:\\s*\\[\\*\\]|resources\\W+\\*)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_user_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?is)([\"']Resource[\"']\\s*:\\s*\\[?\\s*[\"']\\*[\"']|resources\\s*:\\s*\\[\\*\\]|resources\\W+\\*)"
     }
    }
   ],
   "quote": "across all resources"
  },
  {
   "id": "policy_sid",
   "tier": "detail",
   "kind": "any_of",
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
       "policy"
      ],
      "op": "regex",
      "value": "VisualEditor0"
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
        "op": "eq",
        "value": "aws_iam_policy"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "VisualEditor0"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "statement"
      ],
      "op": "regex",
      "value": "VisualEditor0"
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
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "VisualEditor0"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_user_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "VisualEditor0"
     }
    }
   ],
   "quote": "under statement ID \"VisualEditor0\""
  },
  {
   "id": "attach_custom",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_user_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "user"
        ],
        "op": "eq",
        "value": "terraform-bot"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "terraform-policy"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "users",
         "*"
        ],
        "op": "eq",
        "value": "terraform-bot"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "terraform-policy"
       }
      ]
     }
    }
   ],
   "quote": "attach both this custom policy and the AWS-managed \"AmazonElasticFileSystemFullAccess\" policy directly to the \"terraform-bot\" IAM user"
  },
  {
   "id": "attach_custom_user",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_user_policy_attachment"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_iam_user"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_iam_user"
      ],
      "where": []
     }
    }
   ],
   "quote": "directly to the \"terraform-bot\" IAM user"
  },
  {
   "id": "attach_efs",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_user_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "user"
        ],
        "op": "eq",
        "value": "terraform-bot"
       }
      ]
     },
     "cond": {
      "path": [
       "policy_arn"
      ],
      "op": "regex",
      "value": "iam::aws:policy/AmazonElasticFileSystemFullAccess$"
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
        "op": "eq",
        "value": "aws_iam_user_policy_attachment"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy_arn"
      ],
      "op": "regex",
      "value": "iam::aws:policy/AmazonElasticFileSystemFullAccess$"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "users",
         "*"
        ],
        "op": "eq",
        "value": "terraform-bot"
       }
      ]
     },
     "cond": {
      "path": [
       "policy_arn"
      ],
      "op": "regex",
      "value": "iam::aws:policy/AmazonElasticFileSystemFullAccess$"
     }
    }
   ],
   "quote": "the AWS-managed \"AmazonElasticFileSystemFullAccess\" policy"
  },
  {
   "id": "attach_efs_user",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_user_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "contains",
        "value": "AmazonElasticFileSystemFullAccess"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_user"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "contains",
        "value": "AmazonElasticFileSystemFullAccess"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_user"
      ],
      "where": []
     }
    }
   ],
   "quote": "directly to the \"terraform-bot\" IAM user"
  },
  {
   "id": "act_autoscaling_1",
   "tier": "core",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)autoscaling:AttachInstances([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)autoscaling:CreateAutoScalingGroup([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)autoscaling:CreateLaunchConfiguration([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)autoscaling:CreateOrUpdateTags([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)autoscaling:DeleteAutoScalingGroup([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)autoscaling:DeleteLaunchConfiguration([\"'\\s\\]\\\\]|$)"
     }
    }
   ],
   "quote": "Auto Scaling (AttachInstances, CreateAutoScalingGroup, CreateLaunchConfiguration, CreateOrUpdateTags, DeleteAutoScalingGroup, DeleteLaunchConfiguration, DeleteTags, Describe*, DetachInstances, SetDesiredCapacity, UpdateAutoScalingGroup, SuspendProcesses)"
  },
  {
   "id": "act_autoscaling_2",
   "tier": "core",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)autoscaling:DeleteTags([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)autoscaling:Describe\\*([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)autoscaling:DetachInstances([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)autoscaling:SetDesiredCapacity([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)autoscaling:UpdateAutoScalingGroup([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)autoscaling:SuspendProcesses([\"'\\s\\]\\\\]|$)"
     }
    }
   ],
   "quote": "Auto Scaling (AttachInstances, CreateAutoScalingGroup, CreateLaunchConfiguration, CreateOrUpdateTags, DeleteAutoScalingGroup, DeleteLaunchConfiguration, DeleteTags, Describe*, DetachInstances, SetDesiredCapacity, UpdateAutoScalingGroup, SuspendProcesses)"
  },
  {
   "id": "act_ec2_1",
   "tier": "core",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:AllocateAddress([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:AssignPrivateIpAddresses([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:Associate\\*([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:AttachInternetGateway([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:AttachNetworkInterface([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:AuthorizeSecurityGroupEgress([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:AuthorizeSecurityGroupIngress([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:CreateDefaultSubnet([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:CreateDhcpOptions([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:CreateEgressOnlyInternetGateway([\"'\\s\\]\\\\]|$)"
     }
    }
   ],
   "quote": "EC2 networking and compute (AllocateAddress, AssignPrivateIpAddresses, Associate*, AttachInternetGateway"
  },
  {
   "id": "act_ec2_2",
   "tier": "core",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:CreateInternetGateway([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:CreateNatGateway([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:CreateNetworkInterface([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:CreateRoute([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:CreateRouteTable([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:CreateSecurityGroup([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:CreateSubnet([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:CreateTags([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:CreateVolume([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:CreateVpc([\"'\\s\\]\\\\]|$)"
     }
    }
   ],
   "quote": "EC2 networking and compute (AllocateAddress, AssignPrivateIpAddresses, Associate*, AttachInternetGateway"
  },
  {
   "id": "act_ec2_3",
   "tier": "core",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:DeleteDhcpOptions([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:DeleteEgressOnlyInternetGateway([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:DeleteInternetGateway([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:DeleteNatGateway([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:DeleteNetworkInterface([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:DeleteRoute([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:DeleteRouteTable([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:DeleteSecurityGroup([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:DeleteSubnet([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:DeleteTags([\"'\\s\\]\\\\]|$)"
     }
    }
   ],
   "quote": "EC2 networking and compute (AllocateAddress, AssignPrivateIpAddresses, Associate*, AttachInternetGateway"
  },
  {
   "id": "act_ec2_4",
   "tier": "core",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:DeleteVolume([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:DeleteVpc([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:DeleteVpnGateway([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:Describe\\*([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:DetachInternetGateway([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:DetachNetworkInterface([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:DetachVolume([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:Disassociate\\*([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:ModifySubnetAttribute([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:ModifyVpcAttribute([\"'\\s\\]\\\\]|$)"
     }
    }
   ],
   "quote": "EC2 networking and compute (AllocateAddress, AssignPrivateIpAddresses, Associate*, AttachInternetGateway"
  },
  {
   "id": "act_ec2_5",
   "tier": "core",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:ModifyVpcEndpoint([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:ReleaseAddress([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:RevokeSecurityGroupEgress([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:RevokeSecurityGroupIngress([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:UpdateSecurityGroupRuleDescriptionsEgress([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:UpdateSecurityGroupRuleDescriptionsIngress([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:CreateLaunchTemplate([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:CreateLaunchTemplateVersion([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:DeleteLaunchTemplate([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:DeleteLaunchTemplateVersions([\"'\\s\\]\\\\]|$)"
     }
    }
   ],
   "quote": "EC2 networking and compute (AllocateAddress, AssignPrivateIpAddresses, Associate*, AttachInternetGateway"
  },
  {
   "id": "act_ec2_6",
   "tier": "core",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:DescribeLaunchTemplates([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:DescribeLaunchTemplateVersions([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:GetLaunchTemplateData([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:ModifyLaunchTemplate([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:RunInstances([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:TerminateInstances([\"'\\s\\]\\\\]|$)"
     }
    }
   ],
   "quote": "EC2 networking and compute (AllocateAddress, AssignPrivateIpAddresses, Associate*, AttachInternetGateway"
  },
  {
   "id": "act_eks_1",
   "tier": "core",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)eks:CreateCluster([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)eks:DeleteCluster([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)eks:DescribeCluster([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)eks:ListClusters([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)eks:TagResource([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)eks:UntagResource([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)eks:UpdateClusterConfig([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)eks:UpdateClusterVersion([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)eks:DescribeUpdate([\"'\\s\\]\\\\]|$)"
     }
    }
   ],
   "quote": "EKS (CreateCluster, DeleteCluster, DescribeCluster, ListClusters, TagResource, UntagResource, UpdateClusterConfig, UpdateClusterVersion, DescribeUpdate)"
  },
  {
   "id": "act_iam_1",
   "tier": "core",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)iam:AddRoleToInstanceProfile([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)iam:AttachRolePolicy([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)iam:CreateInstanceProfile([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)iam:CreateOpenIDConnectProvider([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)iam:CreateServiceLinkedRole([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)iam:CreatePolicy([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)iam:CreatePolicyVersion([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)iam:CreateRole([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)iam:DeleteInstanceProfile([\"'\\s\\]\\\\]|$)"
     }
    }
   ],
   "quote": "IAM (AddRoleToInstanceProfile, AttachRolePolicy, CreateInstanceProfile, CreateOpenIDConnectProvider, CreateServiceLinkedRole, CreatePolicy, CreatePolicyVersion, CreateRole, DeleteInstanceProfile, DeleteOpenIDConnectProvider, DeletePolicy, DeleteRole"
  },
  {
   "id": "act_iam_2",
   "tier": "core",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)iam:DeleteOpenIDConnectProvider([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)iam:DeletePolicy([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)iam:DeleteRole([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)iam:DeleteRolePolicy([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)iam:DeleteServiceLinkedRole([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)iam:DetachRolePolicy([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)iam:GetInstanceProfile([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)iam:GetOpenIDConnectProvider([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)iam:GetPolicy([\"'\\s\\]\\\\]|$)"
     }
    }
   ],
   "quote": "IAM (AddRoleToInstanceProfile, AttachRolePolicy, CreateInstanceProfile, CreateOpenIDConnectProvider, CreateServiceLinkedRole, CreatePolicy, CreatePolicyVersion, CreateRole, DeleteInstanceProfile, DeleteOpenIDConnectProvider, DeletePolicy, DeleteRole"
  },
  {
   "id": "act_iam_3",
   "tier": "core",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)iam:GetPolicyVersion([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)iam:GetRole([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)iam:GetRolePolicy([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)iam:List\\*([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)iam:PassRole([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)iam:PutRolePolicy([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)iam:RemoveRoleFromInstanceProfile([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)iam:TagRole([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)iam:UpdateAssumeRolePolicy([\"'\\s\\]\\\\]|$)"
     }
    }
   ],
   "quote": "IAM (AddRoleToInstanceProfile, AttachRolePolicy, CreateInstanceProfile, CreateOpenIDConnectProvider, CreateServiceLinkedRole, CreatePolicy, CreatePolicyVersion, CreateRole, DeleteInstanceProfile, DeleteOpenIDConnectProvider, DeletePolicy, DeleteRole"
  },
  {
   "id": "act_s3_1",
   "tier": "core",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)s3:CreateBucket([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)s3:DeleteBucket([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)s3:DescribeJob([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)s3:Get\\*([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)s3:HeadBucket([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)s3:List\\*([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)s3:PutBucketAcl([\"'\\s\\]\\\\]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "data.aws_iam_policy_document",
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)s3:PutBucketTagging([\"'\\s\\]\\\\]|$)"
     }
    }
   ],
   "quote": "S3 (CreateBucket, DeleteBucket, DescribeJob, Get*, HeadBucket, List*, PutBucketAcl, PutBucketTagging)"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
