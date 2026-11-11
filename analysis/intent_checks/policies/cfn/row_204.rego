package intent.cfn.row_204

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "docpol": {
   "types": [
    "AWS::IAM::ManagedPolicy",
    "AWS::IAM::Policy"
   ],
   "where": []
  },
  "inline": {
   "types": [
    "AWS::IAM::Role",
    "AWS::IAM::Group"
   ],
   "where": []
  },
  "ec2role": {
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
  "out": {
   "types": [
    "__output__"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "groups",
   "tier": "core",
   "quote": "a baseline set of IAM groups, roles, instance profiles, and managed policies representing common operational personas",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::IAM::Group"
    ],
    "where": []
   },
   "min": 5,
   "justify": "five personas are listed; Output the IDs of each of the created groups"
  },
  {
   "id": "ec2_role",
   "tier": "core",
   "quote": "Every EC2-assumable role",
   "kind": "exists",
   "select": "ec2role"
  },
  {
   "id": "profile",
   "tier": "core",
   "quote": "Every EC2-assumable role should have a corresponding instance profile",
   "kind": "ref",
   "from": {
    "types": [
     "AWS::IAM::InstanceProfile"
    ],
    "where": []
   },
   "to": "ec2role"
  },
  {
   "id": "managed_policies",
   "tier": "detail",
   "quote": "managed policies representing common operational personas",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::IAM::ManagedPolicy"
    ],
    "where": []
   },
   "min": 5,
   "justify": "five personas, each with its own managed policy"
  },
  {
   "id": "sysadmin",
   "tier": "core",
   "quote": "a system administrator persona with near-full access outside of IAM itself",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "docpol",
     "cond": {
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
         "NotAction",
         "*"
        ],
        "op": "regex",
        "value": "(?i)^iam:\\*$"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::ManagedPolicy",
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
          "value": "Deny"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "regex",
          "value": "(?i)^iam:"
         }
        ]
       }
      ]
     },
     "cond": {
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
        "op": "eq",
        "value": "*"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "inline",
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
         "NotAction",
         "*"
        ],
        "op": "regex",
        "value": "(?i)^iam:\\*$"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "inline",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "(?i):policy/PowerUserAccess$"
     }
    }
   ],
   "justify": "AWS managed PowerUserAccess is full access except IAM"
  },
  {
   "id": "iam_admin",
   "tier": "core",
   "quote": "an IAM administrator persona with full IAM access",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "docpol",
     "cond": {
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
        "value": "iam:*"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "inline",
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
        "value": "iam:*"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "inline",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "(?i):policy/IAMFullAccess$"
     }
    }
   ],
   "justify": "AWS managed IAMFullAccess is full IAM access"
  },
  {
   "id": "ops_ec2",
   "tier": "core",
   "quote": "an instance operations persona limited to EC2",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::ManagedPolicy",
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
          "value": "Deny"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "regex",
          "value": "(?i)^ec2:.*(vpc|subnet|route|gateway|networkacl|peering)"
         }
        ]
       }
      ]
     },
     "cond": {
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
        "value": "ec2:RunInstances"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Role",
       "AWS::IAM::Group"
      ],
      "where": [
       {
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
          "value": "Deny"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "regex",
          "value": "(?i)^ec2:.*(vpc|subnet|route|gateway|networkacl|peering)"
         }
        ]
       }
      ]
     },
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
        "value": "ec2:RunInstances"
       }
      ]
     }
    }
   ],
   "justify": "EC2 actions are allowed (ec2:RunInstances covered) in the policy that also carries the VPC deny"
  },
  {
   "id": "ops_elb",
   "tier": "detail",
   "quote": "Elastic Load Balancing",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::ManagedPolicy",
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
          "value": "Deny"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "regex",
          "value": "(?i)^ec2:.*(vpc|subnet|route|gateway|networkacl|peering)"
         }
        ]
       },
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
          "value": "ec2:RunInstances"
         }
        ]
       }
      ]
     },
     "cond": {
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
        "op": "regex",
        "value": "(?i)^elasticloadbalancing:"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Role",
       "AWS::IAM::Group"
      ],
      "where": [
       {
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
          "value": "Deny"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "regex",
          "value": "(?i)^ec2:.*(vpc|subnet|route|gateway|networkacl|peering)"
         }
        ]
       },
       {
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
          "value": "ec2:RunInstances"
         }
        ]
       }
      ]
     },
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
        "op": "regex",
        "value": "(?i)^elasticloadbalancing:"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "ops_cw",
   "tier": "detail",
   "quote": "CloudWatch",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::ManagedPolicy",
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
          "value": "Deny"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "regex",
          "value": "(?i)^ec2:.*(vpc|subnet|route|gateway|networkacl|peering)"
         }
        ]
       },
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
          "value": "ec2:RunInstances"
         }
        ]
       }
      ]
     },
     "cond": {
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
        "op": "regex",
        "value": "(?i)^cloudwatch:"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Role",
       "AWS::IAM::Group"
      ],
      "where": [
       {
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
          "value": "Deny"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "regex",
          "value": "(?i)^ec2:.*(vpc|subnet|route|gateway|networkacl|peering)"
         }
        ]
       },
       {
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
          "value": "ec2:RunInstances"
         }
        ]
       }
      ]
     },
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
        "op": "regex",
        "value": "(?i)^cloudwatch:"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "ops_asg",
   "tier": "detail",
   "quote": "and Auto Scaling actions",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::ManagedPolicy",
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
          "value": "Deny"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "regex",
          "value": "(?i)^ec2:.*(vpc|subnet|route|gateway|networkacl|peering)"
         }
        ]
       },
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
          "value": "ec2:RunInstances"
         }
        ]
       }
      ]
     },
     "cond": {
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
        "op": "regex",
        "value": "(?i)^autoscaling:"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Role",
       "AWS::IAM::Group"
      ],
      "where": [
       {
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
          "value": "Deny"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "regex",
          "value": "(?i)^ec2:.*(vpc|subnet|route|gateway|networkacl|peering)"
         }
        ]
       },
       {
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
          "value": "ec2:RunInstances"
         }
        ]
       }
      ]
     },
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
        "op": "regex",
        "value": "(?i)^autoscaling:"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "ops_deny_vpc",
   "tier": "core",
   "quote": "being explicitly denied the ability to modify VPC networking constructs",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::ManagedPolicy",
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
          "value": "ec2:RunInstances"
         }
        ]
       }
      ]
     },
     "cond": {
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
        "value": "Deny"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "regex",
        "value": "(?i)^ec2:.*(vpc|subnet|route|gateway|networkacl|peering)"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Role",
       "AWS::IAM::Group"
      ],
      "where": [
       {
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
          "value": "ec2:RunInstances"
         }
        ]
       }
      ]
     },
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
        "value": "Deny"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "regex",
        "value": "(?i)^ec2:.*(vpc|subnet|route|gateway|networkacl|peering)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "ro_admin",
   "tier": "core",
   "quote": "a read-only administrator persona covering broad read-only access across core services",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "docpol",
     "cond": {
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
        "op": "regex",
        "value": "(?i)^ec2:(describe|get|list)"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "regex",
        "value": "(?i)^s3:(get|list)"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "none_eq",
        "value": "*"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "none_eq",
        "value": "ec2:*"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "none_eq",
        "value": "s3:*"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "inline",
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
        "op": "regex",
        "value": "(?i)^ec2:(describe|get|list)"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "regex",
        "value": "(?i)^s3:(get|list)"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "none_eq",
        "value": "*"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "none_eq",
        "value": "ec2:*"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "none_eq",
        "value": "s3:*"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "inline",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "(?i):policy/(ReadOnlyAccess|ViewOnlyAccess)$"
     }
    }
   ],
   "justify": "broad read-only access across core services implies read actions on at least EC2 and S3 and no service-wide wildcard"
  },
  {
   "id": "ro_billing",
   "tier": "core",
   "quote": "a read-only billing persona limited to viewing billing information",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "docpol",
     "cond": {
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
        "op": "regex",
        "value": "(?i)^(aws-portal:(view|\\*)|billing:(get|view|\\*)|ce:|cur:)"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "inline",
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
        "op": "regex",
        "value": "(?i)^(aws-portal:(view|\\*)|billing:(get|view|\\*)|ce:|cur:)"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "inline",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "(?i):policy/AWSBillingReadOnlyAccess$"
     }
    }
   ]
  },
  {
   "id": "mfa",
   "tier": "core",
   "quote": "Every non-billing policy must require that the caller has multi-factor authentication present",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::Policy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument"
        ],
        "op": "regex",
        "value": "aws:MultiFactorAuthPresent"
       }
      ]
     },
     "min": 2
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::IAM::Role",
       "AWS::IAM::Group"
      ],
      "where": [
       {
        "path": [
         "Policies"
        ],
        "op": "regex",
        "value": "aws:MultiFactorAuthPresent"
       }
      ]
     },
     "min": 2
    }
   ],
   "justify": "the ground truth guarantees MFA conditions on two policies"
  },
  {
   "id": "deny_billing",
   "tier": "core",
   "quote": "must deny access to the AWS Billing console",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::IAM::ManagedPolicy",
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
          "value": "Deny"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "regex",
          "value": "(?i)^(aws-portal:|billing:)"
         }
        ]
       }
      ]
     },
     "min": 4
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::IAM::Role",
       "AWS::IAM::Group"
      ],
      "where": [
       {
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
          "value": "Deny"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "regex",
          "value": "(?i)^(aws-portal:|billing:)"
         }
        ]
       }
      ]
     },
     "min": 4
    }
   ],
   "justify": "four non-billing personas"
  },
  {
   "id": "deny_kms",
   "tier": "core",
   "quote": "must deny the ability to disable, delete, or otherwise tamper with logging-related KMS keys",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::IAM::ManagedPolicy",
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
          "value": "Deny"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "glob_covers",
          "value": "kms:DisableKey"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "regex",
          "value": "(?i)^kms:(delete|schedulekeydeletion|\\*)"
         }
        ]
       }
      ]
     },
     "min": 2
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::IAM::Role",
       "AWS::IAM::Group"
      ],
      "where": [
       {
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
          "value": "Deny"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "glob_covers",
          "value": "kms:DisableKey"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "regex",
          "value": "(?i)^kms:(delete|schedulekeydeletion|\\*)"
         }
        ]
       }
      ]
     },
     "min": 2
    }
   ],
   "justify": "the ground truth guarantees KMS-tamper denials in two policies"
  },
  {
   "id": "out_groups",
   "tier": "detail",
   "quote": "Output the IDs of each of the created groups",
   "kind": "exists",
   "select": {
    "types": [
     "__output__"
    ],
    "where": [
     {
      "path": [
       "value",
       "ref"
      ],
      "op": "present"
     }
    ]
   },
   "min": 5,
   "justify": "five groups"
  },
  {
   "id": "out_ref_group",
   "tier": "detail",
   "quote": "Output the IDs of each of the created groups",
   "kind": "ref",
   "from": "out",
   "to": {
    "types": [
     "AWS::IAM::Group"
    ],
    "where": []
   }
  },
  {
   "id": "x_trust",
   "kind": "attr",
   "select": "ec2role",
   "tier": "extra",
   "quantifier": "all",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument",
     "Statement",
     "*",
     "Action",
     "*"
    ],
    "op": "glob_covers",
    "value": "sts:AssumeRole"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
