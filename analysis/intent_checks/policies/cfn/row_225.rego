package intent.cfn.row_225

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "prof": {
   "types": [
    "AWS::IAM::InstanceProfile"
   ],
   "where": []
  },
  "eip": {
   "types": [
    "AWS::EC2::EIP"
   ],
   "where": []
  },
  "par": {
   "types": [
    "__parameter__"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "Environment"
    }
   ]
  },
  "tagged": {
   "types": [
    "AWS::IAM::Role",
    "AWS::EC2::EIP"
   ],
   "where": []
  },
  "named_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "RoleName"
     ],
     "op": "eq",
     "value": "cocktaildb-prod-ec2-role"
    }
   ]
  },
  "outs_plain": {
   "types": [
    "__output__"
   ],
   "where": [
    {
     "path": [
      "value",
      "attr"
     ],
     "op": "absent"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "env_default",
   "kind": "attr",
   "tier": "core",
   "select": "par",
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": "prod"
   },
   "quote": "an Environment parameter defaulting to \"prod\""
  },
  {
   "id": "env_dev",
   "kind": "attr",
   "tier": "detail",
   "select": "par",
   "cond": {
    "path": [
     "allowed_values",
     "*"
    ],
    "op": "eq",
    "value": "dev"
   },
   "quote": "(with allowed values \"dev\" or \"prod\")"
  },
  {
   "id": "env_prod",
   "kind": "attr",
   "tier": "detail",
   "select": "par",
   "cond": {
    "path": [
     "allowed_values",
     "*"
    ],
    "op": "eq",
    "value": "prod"
   },
   "quote": "(with allowed values \"dev\" or \"prod\")"
  },
  {
   "id": "role",
   "kind": "exists",
   "tier": "core",
   "select": "role",
   "quote": "an IAM role"
  },
  {
   "id": "role_name",
   "kind": "attr",
   "tier": "core",
   "select": "role",
   "cond": {
    "path": [
     "RoleName"
    ],
    "op": "eq",
    "value": "cocktaildb-prod-ec2-role"
   },
   "quote": "an IAM role named \"cocktaildb-{Environment}-ec2-role\"",
   "justify": "the Environment default prod fills the name"
  },
  {
   "id": "role_trust",
   "kind": "attr",
   "tier": "core",
   "select": "named_role",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument",
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
       "Principal",
       "Service",
       "*"
      ],
      "op": "eq",
      "value": "ec2.amazonaws.com"
     },
     {
      "path": [
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "sts:AssumeRole"
     }
    ]
   },
   "quote": "can be assumed by \"ec2.amazonaws.com\"",
   "justify": "being assumed by a service is an Allow of sts:AssumeRole"
  },
  {
   "id": "managed",
   "kind": "attr",
   "tier": "core",
   "select": "named_role",
   "cond": {
    "path": [
     "ManagedPolicyArns",
     "*"
    ],
    "op": "regex",
    "value": "CloudWatchAgentServerPolicy$"
   },
   "quote": "attached to the managed policy \"CloudWatchAgentServerPolicy\""
  },
  {
   "id": "act_getobject",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "named_role",
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
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::RolePolicy"
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
     "to": "named_role"
    },
    {
     "kind": "exists",
     "select": {
      "types": [
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
       },
       {
        "path": [
         "Roles",
         "*"
        ],
        "op": "eq",
        "value": "cocktaildb-prod-ec2-role"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::IAM::RolePolicy"
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
       },
       {
        "path": [
         "RoleName"
        ],
        "op": "eq",
        "value": "cocktaildb-prod-ec2-role"
       }
      ]
     }
    }
   ],
   "quote": "an inline policy granting get, put, list, and delete S3 actions",
   "justify": "get/put/list/delete S3 actions map to GetObject/PutObject/ListBucket/DeleteObject"
  },
  {
   "id": "act_putobject",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "named_role",
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
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::RolePolicy"
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
     "to": "named_role"
    },
    {
     "kind": "exists",
     "select": {
      "types": [
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
       },
       {
        "path": [
         "Roles",
         "*"
        ],
        "op": "eq",
        "value": "cocktaildb-prod-ec2-role"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::IAM::RolePolicy"
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
       },
       {
        "path": [
         "RoleName"
        ],
        "op": "eq",
        "value": "cocktaildb-prod-ec2-role"
       }
      ]
     }
    }
   ],
   "quote": "an inline policy granting get, put, list, and delete S3 actions",
   "justify": "get/put/list/delete S3 actions map to GetObject/PutObject/ListBucket/DeleteObject"
  },
  {
   "id": "act_listbucket",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "named_role",
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
        "value": "s3:ListBucket"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::RolePolicy"
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
          "value": "s3:ListBucket"
         }
        ]
       }
      ]
     },
     "to": "named_role"
    },
    {
     "kind": "exists",
     "select": {
      "types": [
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
          "value": "s3:ListBucket"
         }
        ]
       },
       {
        "path": [
         "Roles",
         "*"
        ],
        "op": "eq",
        "value": "cocktaildb-prod-ec2-role"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::IAM::RolePolicy"
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
          "value": "s3:ListBucket"
         }
        ]
       },
       {
        "path": [
         "RoleName"
        ],
        "op": "eq",
        "value": "cocktaildb-prod-ec2-role"
       }
      ]
     }
    }
   ],
   "quote": "an inline policy granting get, put, list, and delete S3 actions",
   "justify": "get/put/list/delete S3 actions map to GetObject/PutObject/ListBucket/DeleteObject"
  },
  {
   "id": "act_deleteobject",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "named_role",
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
        "value": "s3:DeleteObject"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::RolePolicy"
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
          "value": "s3:DeleteObject"
         }
        ]
       }
      ]
     },
     "to": "named_role"
    },
    {
     "kind": "exists",
     "select": {
      "types": [
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
          "value": "s3:DeleteObject"
         }
        ]
       },
       {
        "path": [
         "Roles",
         "*"
        ],
        "op": "eq",
        "value": "cocktaildb-prod-ec2-role"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::IAM::RolePolicy"
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
          "value": "s3:DeleteObject"
         }
        ]
       },
       {
        "path": [
         "RoleName"
        ],
        "op": "eq",
        "value": "cocktaildb-prod-ec2-role"
       }
      ]
     }
    }
   ],
   "quote": "an inline policy granting get, put, list, and delete S3 actions",
   "justify": "get/put/list/delete S3 actions map to GetObject/PutObject/ListBucket/DeleteObject"
  },
  {
   "id": "res_analytics",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "named_role",
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
      "op": "regex",
      "value": "cocktailanalytics-.+-prod"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::RolePolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "cocktailanalytics-.+-prod"
       }
      ]
     },
     "to": "named_role"
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::IAM::Policy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "cocktailanalytics-.+-prod"
       },
       {
        "path": [
         "Roles",
         "*"
        ],
        "op": "eq",
        "value": "cocktaildb-prod-ec2-role"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::IAM::RolePolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "cocktailanalytics-.+-prod"
       },
       {
        "path": [
         "RoleName"
        ],
        "op": "eq",
        "value": "cocktaildb-prod-ec2-role"
       }
      ]
     }
    }
   ],
   "quote": "analytics (\"cocktailanalytics-{AccountId}-{Environment}\")",
   "justify": "default Environment prod"
  },
  {
   "id": "res_backups",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "named_role",
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
      "op": "regex",
      "value": "cocktaildbbackups-.+-prod"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::RolePolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "cocktaildbbackups-.+-prod"
       }
      ]
     },
     "to": "named_role"
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::IAM::Policy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "cocktaildbbackups-.+-prod"
       },
       {
        "path": [
         "Roles",
         "*"
        ],
        "op": "eq",
        "value": "cocktaildb-prod-ec2-role"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::IAM::RolePolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "cocktaildbbackups-.+-prod"
       },
       {
        "path": [
         "RoleName"
        ],
        "op": "eq",
        "value": "cocktaildb-prod-ec2-role"
       }
      ]
     }
    }
   ],
   "quote": "backup (\"cocktaildbbackups-{AccountId}-{Environment}\") S3 buckets",
   "justify": "default Environment prod"
  },
  {
   "id": "profile",
   "kind": "exists",
   "tier": "core",
   "select": "prof",
   "quote": "an IAM instance profile"
  },
  {
   "id": "profile_name",
   "kind": "attr",
   "tier": "core",
   "select": "prof",
   "cond": {
    "path": [
     "InstanceProfileName"
    ],
    "op": "eq",
    "value": "cocktaildb-prod-ec2-profile"
   },
   "quote": "an IAM instance profile named \"cocktaildb-{Environment}-ec2-profile\"",
   "justify": "default Environment prod fills the name"
  },
  {
   "id": "profile_role",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "ref",
     "from": "prof",
     "to": "named_role"
    },
    {
     "kind": "attr",
     "select": "prof",
     "cond": {
      "path": [
       "Roles",
       "*"
      ],
      "op": "eq",
      "value": "cocktaildb-prod-ec2-role"
     }
    }
   ],
   "quote": "referencing the IAM role",
   "justify": "the role's stated name fills the reference"
  },
  {
   "id": "eip",
   "kind": "exists",
   "tier": "core",
   "select": "eip",
   "quote": "a VPC-domain Elastic IP"
  },
  {
   "id": "eip_domain",
   "kind": "attr",
   "tier": "core",
   "select": "eip",
   "cond": {
    "path": [
     "Domain"
    ],
    "op": "eq",
    "value": "vpc"
   },
   "quote": "a VPC-domain Elastic IP"
  },
  {
   "id": "eip_name",
   "kind": "attr",
   "tier": "detail",
   "select": "eip",
   "cond": {
    "path": [
     "Tags",
     "*"
    ],
    "op": "has_kv",
    "value": {
     "key": "Name",
     "value": "cocktaildb-prod"
    }
   },
   "quote": "tagged with Name \"cocktaildb-{Environment}\"",
   "justify": "default Environment prod fills the tag"
  },
  {
   "id": "tag_env",
   "kind": "attr",
   "tier": "detail",
   "select": "tagged",
   "cond": {
    "path": [
     "Tags",
     "*",
     "Key"
    ],
    "op": "eq",
    "value": "Environment"
   },
   "quantifier": "all",
   "quote": "applying Environment and Project tags across resources"
  },
  {
   "id": "tag_proj",
   "kind": "attr",
   "tier": "detail",
   "select": "tagged",
   "cond": {
    "path": [
     "Tags",
     "*",
     "Key"
    ],
    "op": "eq",
    "value": "Project"
   },
   "quantifier": "all",
   "quote": "applying Environment and Project tags across resources"
  },
  {
   "id": "out_rolename",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "ref",
     "from": "outs_plain",
     "to": "role"
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__output__"
      ],
      "where": [
       {
        "path": [
         "value"
        ],
        "op": "eq",
        "value": "cocktaildb-prod-ec2-role"
       }
      ]
     }
    }
   ],
   "quote": "exporting the role name, role ARN, instance profile name, Elastic IP address, and allocation ID in the stack outputs"
  },
  {
   "id": "out_rolearn",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "__output__"
      ],
      "where": [
       {
        "path": [
         "value",
         "attr"
        ],
        "op": "eq",
        "value": "Arn"
       }
      ]
     },
     "to": "role"
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__output__"
      ],
      "where": [
       {
        "path": [
         "value"
        ],
        "op": "regex",
        "value": "role/cocktaildb-prod-ec2-role$"
       }
      ]
     }
    }
   ],
   "quote": "exporting the role name, role ARN, instance profile name, Elastic IP address, and allocation ID in the stack outputs"
  },
  {
   "id": "out_profile",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "ref",
     "from": "outs_plain",
     "to": "prof"
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__output__"
      ],
      "where": [
       {
        "path": [
         "value"
        ],
        "op": "eq",
        "value": "cocktaildb-prod-ec2-profile"
       }
      ]
     }
    }
   ],
   "quote": "exporting the role name, role ARN, instance profile name, Elastic IP address, and allocation ID in the stack outputs"
  },
  {
   "id": "out_eip",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "ref",
     "from": "outs_plain",
     "to": "eip"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "__output__"
      ],
      "where": [
       {
        "path": [
         "value",
         "attr"
        ],
        "op": "eq",
        "value": "PublicIp"
       }
      ]
     },
     "to": "eip"
    }
   ],
   "quote": "exporting the role name, role ARN, instance profile name, Elastic IP address, and allocation ID in the stack outputs",
   "justify": "an Elastic IP address output is Ref or GetAtt PublicIp"
  },
  {
   "id": "out_alloc",
   "kind": "ref",
   "tier": "detail",
   "from": {
    "types": [
     "__output__"
    ],
    "where": [
     {
      "path": [
       "value",
       "attr"
      ],
      "op": "eq",
      "value": "AllocationId"
     }
    ]
   },
   "to": "eip",
   "quote": "exporting the role name, role ARN, instance profile name, Elastic IP address, and allocation ID in the stack outputs"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
