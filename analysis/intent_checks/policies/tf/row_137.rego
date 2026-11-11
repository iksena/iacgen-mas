package intent.tf.row_137

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "user_exists",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_iam_user"
    ],
    "where": []
   },
   "quote": "deploy an IAM user with force_destroy enabled"
  },
  {
   "id": "user_force_destroy",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_iam_user"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "force_destroy"
    ],
    "op": "truthy"
   },
   "quote": "an IAM user with force_destroy enabled"
  },
  {
   "id": "user_name",
   "tier": "detail",
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
      "value": "my_vpn_infra_user"
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
       "default"
      ],
      "op": "eq",
      "value": "my_vpn_infra_user"
     }
    }
   ],
   "quote": "a username variable defaulting to \"my_vpn_infra_user\""
  },
  {
   "id": "group_exists",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_iam_group"
    ],
    "where": []
   },
   "quote": "an IAM group defined by group_name"
  },
  {
   "id": "group_name",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_group"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "my-vpn-infra-group"
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
       "default"
      ],
      "op": "eq",
      "value": "my-vpn-infra-group"
     }
    }
   ],
   "quote": "group_name defaulting to \"my-vpn-infra-group\""
  },
  {
   "id": "membership_exists",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_group_membership"
      ],
      "where": []
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_user_group_membership"
      ],
      "where": []
     }
    }
   ],
   "quote": "group membership defined by membership_name"
  },
  {
   "id": "membership_name",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_group_membership"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "my-vpn-infra-manager-group"
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
       "default"
      ],
      "op": "eq",
      "value": "my-vpn-infra-manager-group"
     }
    }
   ],
   "quote": "membership_name defaulting to \"my-vpn-infra-manager-group\""
  },
  {
   "id": "membership_links",
   "tier": "detail",
   "kind": "all_of",
   "quote": "group membership defined by membership_name",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_group_membership",
       "aws_iam_user_group_membership"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_iam_group"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_group_membership",
       "aws_iam_user_group_membership"
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
   ]
  },
  {
   "id": "access_key",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_iam_access_key"
    ],
    "where": []
   },
   "quote": "an active IAM access key for the user"
  },
  {
   "id": "access_key_active",
   "tier": "detail",
   "kind": "attr",
   "select": {
    "types": [
     "aws_iam_access_key"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "status"
    ],
    "op": "eq",
    "value": "Active"
   },
   "quote": "an active IAM access key"
  },
  {
   "id": "access_key_user",
   "tier": "detail",
   "kind": "ref",
   "from": {
    "types": [
     "aws_iam_access_key"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_iam_user"
    ],
    "where": []
   },
   "quote": "an active IAM access key for the user"
  },
  {
   "id": "user_tag",
   "tier": "detail",
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
       "tags",
       "ProjectTag"
      ],
      "op": "eq",
      "value": "my-vpn-tag"
     },
     "quantifier": "all"
    },
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
       "tags_all",
       "ProjectTag"
      ],
      "op": "eq",
      "value": "my-vpn-tag"
     },
     "quantifier": "all"
    }
   ],
   "quote": "All created policies and the IAM user must apply a ProjectTag tag matching a project_tag variable defaulting to \"my-vpn-tag\""
  },
  {
   "id": "policy_tag",
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
       "tags",
       "ProjectTag"
      ],
      "op": "eq",
      "value": "my-vpn-tag"
     },
     "quantifier": "all"
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
       "tags_all",
       "ProjectTag"
      ],
      "op": "eq",
      "value": "my-vpn-tag"
     },
     "quantifier": "all"
    }
   ],
   "quote": "All created policies and the IAM user must apply a ProjectTag tag matching a project_tag variable defaulting to \"my-vpn-tag\""
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
    "value": "/my_vpn_infra/"
   },
   "quantifier": "all",
   "quote": "a custom policy path variable defaulting to \"/my_vpn_infra/\""
  },
  {
   "id": "seven_policies",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_iam_policy"
    ],
    "where": []
   },
   "min": 7,
   "quote": "seven distinct IAM policies attached to the group"
  },
  {
   "id": "policy_names",
   "tier": "detail",
   "kind": "all_of",
   "quote": "The template must create seven distinct IAM policies attached to the group: basic_policy",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "contains",
        "value": "basic_policy"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "contains",
        "value": "create_policy"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "contains",
        "value": "read_policy"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "contains",
        "value": "update_policy"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "contains",
        "value": "delete_policy"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "contains",
        "value": "instance_policy"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "contains",
        "value": "terraform_backend_access"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "policies_attached_to_group",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_group_policy_attachment"
      ],
      "where": []
     },
     "min": 7
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": []
     },
     "min": 7
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_group_policy"
      ],
      "where": []
     },
     "min": 7
    }
   ],
   "quote": "all policies must be attached to the IAM group"
  },
  {
   "id": "attachments_ref_group",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_group_policy_attachment"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_iam_group"
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
       "aws_iam_group"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_group_policy"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_iam_group"
      ],
      "where": []
     }
    }
   ],
   "quote": "all policies must be attached to the IAM group"
  },
  {
   "id": "basic_policy",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "sts:GetCallerIdentity"
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
        "op": "in",
        "value": [
         "aws_iam_policy",
         "aws_iam_group_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "sts:GetCallerIdentity"
       }
      ]
     }
    }
   ],
   "quote": "basic_policy granting \"sts:GetCallerIdentity\""
  },
  {
   "id": "create_policy",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "ec2:CreateKeyPair"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "ec2:CreateVpc"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "ec2:CreateSubnet"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "ec2:CreateInternetGateway"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "ec2:CreateRoute"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "ec2:CreateRouteTable"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "ec2:CreateLocalGatewayRouteTableVpcAssociation"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "ec2:CreateSecurityGroup"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "ec2:AuthorizeSecurityGroupEgress"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "ec2:AuthorizeSecurityGroupIngress"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "ec2:CreateReplaceRootVolumeTask"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "ec2:CreateTags"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "ec2:AllocateAddress"
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
        "op": "in",
        "value": [
         "aws_iam_policy",
         "aws_iam_group_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "ec2:CreateKeyPair"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "ec2:CreateVpc"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "ec2:CreateSubnet"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "ec2:CreateInternetGateway"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "ec2:CreateRoute"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "ec2:CreateRouteTable"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "ec2:CreateLocalGatewayRouteTableVpcAssociation"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "ec2:CreateSecurityGroup"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "ec2:AuthorizeSecurityGroupEgress"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "ec2:AuthorizeSecurityGroupIngress"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "ec2:CreateReplaceRootVolumeTask"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "ec2:CreateTags"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "ec2:AllocateAddress"
       }
      ]
     }
    }
   ],
   "quote": "create_policy granting explicit EC2 resource creation actions"
  },
  {
   "id": "read_policy",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "ec2:Describe"
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
        "op": "in",
        "value": [
         "aws_iam_policy",
         "aws_iam_group_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "ec2:Describe"
       }
      ]
     }
    }
   ],
   "quote": "read_policy granting a comprehensive set of EC2 read actions",
   "justify": "read actions on EC2 are the ec2:Describe* family"
  },
  {
   "id": "update_policy",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "ec2:Modify"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)ec2:(associate|attach|replace\\w*association)"
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
        "op": "in",
        "value": [
         "aws_iam_policy",
         "aws_iam_group_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "ec2:Modify"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ec2:(associate|attach|replace\\w*association)"
       }
      ]
     }
    }
   ],
   "quote": "update_policy granting EC2 modification and association actions",
   "justify": "modification means ec2:Modify*, association means ec2:Associate*/Attach*/Replace*Association"
  },
  {
   "id": "delete_policy",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "ec2:Delete"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "ec2:Detach"
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
        "op": "in",
        "value": [
         "aws_iam_policy",
         "aws_iam_group_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "ec2:Delete"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "ec2:Detach"
       }
      ]
     }
    }
   ],
   "quote": "delete_policy granting EC2 deletion and detachment actions",
   "justify": "deletion means ec2:Delete*, detachment means ec2:Detach*"
  },
  {
   "id": "instance_policy",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "ec2:RunInstances"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "ec2:StartInstances"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "ec2:ResetInstanceAttribute"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "ec2:ModifyInstanceAttribute"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "ec2:StopInstances"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "ec2:TerminateInstances"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "ec2:RebootInstances"
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
        "op": "in",
        "value": [
         "aws_iam_policy",
         "aws_iam_group_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "ec2:RunInstances"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "ec2:StartInstances"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "ec2:ResetInstanceAttribute"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "ec2:ModifyInstanceAttribute"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "ec2:StopInstances"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "ec2:TerminateInstances"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "ec2:RebootInstances"
       }
      ]
     }
    }
   ],
   "quote": "instance_policy granting EC2 lifecycle actions"
  },
  {
   "id": "backend_policy",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "dynamodb:DescribeTable"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "dynamodb:GetItem"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "dynamodb:PutItem"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "dynamodb:DeleteItem"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "s3:ListBucket"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "s3:GetObject"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "s3:PutObject"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "s3:DeleteObject"
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
        "op": "in",
        "value": [
         "aws_iam_policy",
         "aws_iam_group_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "dynamodb:DescribeTable"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "dynamodb:GetItem"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "dynamodb:PutItem"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "dynamodb:DeleteItem"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "s3:ListBucket"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "s3:GetObject"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "s3:PutObject"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "s3:DeleteObject"
       }
      ]
     }
    }
   ],
   "quote": "terraform_backend_access granting DynamoDB state lock access (\"dynamodb:DescribeTable\", \"dynamodb:GetItem\", \"dynamodb:PutItem\", and \"dynamodb:DeleteItem\") alongside S3 backend access"
  },
  {
   "id": "backend_all_resources",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "dynamodb:DescribeTable"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "dynamodb:GetItem"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "dynamodb:PutItem"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "dynamodb:DeleteItem"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "s3:ListBucket"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "s3:GetObject"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "s3:PutObject"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "s3:DeleteObject"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?is)resources?\\W{1,8}\\*"
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
        "op": "in",
        "value": [
         "aws_iam_policy",
         "aws_iam_group_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "dynamodb:DescribeTable"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "dynamodb:GetItem"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "dynamodb:PutItem"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "dynamodb:DeleteItem"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "s3:ListBucket"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "s3:GetObject"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "s3:PutObject"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "s3:DeleteObject"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?is)resources?\\W{1,8}\\*"
     }
    }
   ],
   "quote": "on all resources"
  },
  {
   "id": "x_output_access_key",
   "tier": "extra",
   "kind": "ref",
   "from": {
    "types": [
     "__output__"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_iam_access_key"
    ],
    "where": []
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
