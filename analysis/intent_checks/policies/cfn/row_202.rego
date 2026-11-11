package intent.cfn.row_202

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
  "out": {
   "types": [
    "__output__"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "role",
   "tier": "core",
   "quote": "creates an IAM execution role for a SageMaker HyperPod cluster",
   "kind": "exists",
   "select": "role"
  },
  {
   "id": "role_name",
   "tier": "core",
   "quote": "the role must be named by appending \"ExecRole\" to the prefix",
   "kind": "attr",
   "select": "role",
   "cond": {
    "path": [
     "RoleName"
    ],
    "op": "regex",
    "value": "ExecRole$"
   }
  },
  {
   "id": "trust",
   "tier": "core",
   "quote": "allow the SageMaker service principal to assume it",
   "kind": "attr",
   "select": "role",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument"
    ],
    "op": "contains",
    "value": "sagemaker.amazonaws.com"
   }
  },
  {
   "id": "managed",
   "tier": "core",
   "quote": "be attached to the AWS managed policy for SageMaker cluster instance roles",
   "kind": "attr",
   "select": "role",
   "cond": {
    "path": [
     "ManagedPolicyArns",
     "*"
    ],
    "op": "regex",
    "value": "(?i)policy/AmazonSageMakerClusterInstanceRolePolicy$"
   }
  },
  {
   "id": "params",
   "tier": "detail",
   "quote": "accepts parameters for a resource name prefix, an EKS cluster name, a VPC ID, a list of security group IDs, a list of private subnet IDs, an S3 bucket name for lifecycle scripts, and optional parameters for a RIG input S3 bucket, a RIG output S3 bucket, a flag to create RIG resources, and a flag to enable gated access",
   "kind": "exists",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": []
   },
   "min": 10,
   "justify": "ten parameters are enumerated"
  },
  {
   "id": "list_params",
   "tier": "detail",
   "quote": "a list of security group IDs, a list of private subnet IDs",
   "kind": "exists",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "type"
      ],
      "op": "regex",
      "value": "(?i)list"
     }
    ]
   },
   "min": 2,
   "justify": "a security group list and a subnet list"
  },
  {
   "id": "cni",
   "tier": "core",
   "quote": "grants the EKS CNI plugin permissions for attaching network interfaces, describing instances, tags, network interfaces, instance types, and subnets, and creating tags on network interfaces",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": [
       {
        "path": [
         "Policies",
         "*",
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "ec2:AttachNetworkInterface"
       },
       {
        "path": [
         "Policies",
         "*",
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "ec2:DescribeInstances"
       },
       {
        "path": [
         "Policies",
         "*",
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "ec2:DescribeTags"
       },
       {
        "path": [
         "Policies",
         "*",
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "ec2:DescribeNetworkInterfaces"
       },
       {
        "path": [
         "Policies",
         "*",
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "ec2:DescribeInstanceTypes"
       },
       {
        "path": [
         "Policies",
         "*",
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "ec2:DescribeSubnets"
       },
       {
        "path": [
         "Policies",
         "*",
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "ec2:CreateTags"
       }
      ]
     },
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "ec2:AttachNetworkInterface"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy",
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
        "value": "ec2:AttachNetworkInterface"
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
        "value": "ec2:DescribeInstances"
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
        "value": "ec2:DescribeTags"
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
        "value": "ec2:DescribeNetworkInterfaces"
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
        "value": "ec2:DescribeInstanceTypes"
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
        "value": "ec2:DescribeSubnets"
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
        "value": "ec2:CreateTags"
       }
      ]
     },
     "to": "role",
     "bidirectional": true
    }
   ]
  },
  {
   "id": "eni",
   "tier": "core",
   "quote": "broader ENI management actions such as assigning private IP addresses, creating, deleting, and modifying network interfaces and permissions, and detaching network interfaces",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": [
       {
        "path": [
         "Policies",
         "*",
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "ec2:AssignPrivateIpAddresses"
       },
       {
        "path": [
         "Policies",
         "*",
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "ec2:CreateNetworkInterface"
       },
       {
        "path": [
         "Policies",
         "*",
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "ec2:DeleteNetworkInterface"
       },
       {
        "path": [
         "Policies",
         "*",
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "ec2:ModifyNetworkInterfaceAttribute"
       },
       {
        "path": [
         "Policies",
         "*",
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "ec2:DetachNetworkInterface"
       }
      ]
     },
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "ec2:AssignPrivateIpAddresses"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy",
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
        "value": "ec2:AssignPrivateIpAddresses"
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
        "value": "ec2:CreateNetworkInterface"
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
        "value": "ec2:DeleteNetworkInterface"
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
        "value": "ec2:ModifyNetworkInterfaceAttribute"
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
        "value": "ec2:DetachNetworkInterface"
       }
      ]
     },
     "to": "role",
     "bidirectional": true
    }
   ]
  },
  {
   "id": "eni_perm",
   "tier": "detail",
   "quote": "creating, deleting, and modifying network interfaces and permissions",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": [
       {
        "path": [
         "Policies",
         "*",
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "ec2:CreateNetworkInterfacePermission"
       },
       {
        "path": [
         "Policies",
         "*",
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "ec2:DeleteNetworkInterfacePermission"
       }
      ]
     },
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "ec2:CreateNetworkInterfacePermission"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy",
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
        "value": "ec2:CreateNetworkInterfacePermission"
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
        "value": "ec2:DeleteNetworkInterfacePermission"
       }
      ]
     },
     "to": "role",
     "bidirectional": true
    }
   ]
  },
  {
   "id": "eni_scope",
   "tier": "detail",
   "quote": "scoped to instances, network interfaces, and the specified VPC",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Role"
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
           "Action",
           "*"
          ],
          "op": "glob_covers",
          "value": "ec2:CreateNetworkInterface"
         },
         {
          "path": [],
          "op": "regex",
          "value": "(?i)(:vpc/|ec2:vpc)"
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
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "ec2:CreateNetworkInterface"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)(:vpc/|ec2:vpc)"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
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
           "Action",
           "*"
          ],
          "op": "glob_covers",
          "value": "ec2:CreateNetworkInterface"
         },
         {
          "path": [],
          "op": "regex",
          "value": "(?i)(:vpc/|ec2:vpc)"
         }
        ]
       }
      ]
     },
     "to": "role",
     "bidirectional": true
    }
   ]
  },
  {
   "id": "reads",
   "tier": "detail",
   "quote": "plus read permissions for VPCs, DHCP options, and security groups",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": [
       {
        "path": [
         "Policies",
         "*",
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "ec2:DescribeVpcs"
       },
       {
        "path": [
         "Policies",
         "*",
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "ec2:DescribeDhcpOptions"
       },
       {
        "path": [
         "Policies",
         "*",
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "ec2:DescribeSecurityGroups"
       }
      ]
     },
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "ec2:DescribeVpcs"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy",
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
        "value": "ec2:DescribeVpcs"
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
        "value": "ec2:DescribeDhcpOptions"
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
        "value": "ec2:DescribeSecurityGroups"
       }
      ]
     },
     "to": "role",
     "bidirectional": true
    }
   ]
  },
  {
   "id": "ecr",
   "tier": "detail",
   "quote": "ECR actions for pulling container images",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": [
       {
        "path": [
         "Policies",
         "*",
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "ecr:BatchGetImage"
       },
       {
        "path": [
         "Policies",
         "*",
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "ecr:GetDownloadUrlForLayer"
       }
      ]
     },
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "ecr:BatchGetImage"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy",
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
        "value": "ecr:BatchGetImage"
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
        "value": "ecr:GetDownloadUrlForLayer"
       }
      ]
     },
     "to": "role",
     "bidirectional": true
    }
   ],
   "justify": "pulling an image needs ecr:BatchGetImage and ecr:GetDownloadUrlForLayer"
  },
  {
   "id": "cw",
   "tier": "detail",
   "quote": "CloudWatch alarm describe permissions",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": [
       {
        "path": [
         "Policies",
         "*",
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "cloudwatch:DescribeAlarms"
       }
      ]
     },
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "cloudwatch:DescribeAlarms"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy",
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
        "value": "cloudwatch:DescribeAlarms"
       }
      ]
     },
     "to": "role",
     "bidirectional": true
    }
   ]
  },
  {
   "id": "podid",
   "tier": "detail",
   "quote": "the eks-auth:AssumeRoleForPodIdentity action scoped to the provided EKS cluster",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Role"
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
           "Action",
           "*"
          ],
          "op": "glob_covers",
          "value": "eks-auth:AssumeRoleForPodIdentity"
         },
         {
          "path": [],
          "op": "regex",
          "value": "(?i)(:cluster/|eks:cluster-name)"
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
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "eks-auth:AssumeRoleForPodIdentity"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)(:cluster/|eks:cluster-name)"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
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
           "Action",
           "*"
          ],
          "op": "glob_covers",
          "value": "eks-auth:AssumeRoleForPodIdentity"
         },
         {
          "path": [],
          "op": "regex",
          "value": "(?i)(:cluster/|eks:cluster-name)"
         }
        ]
       }
      ]
     },
     "to": "role",
     "bidirectional": true
    }
   ]
  },
  {
   "id": "lifecycle_s3",
   "tier": "detail",
   "quote": "list and get object access to the lifecycle scripts S3 bucket",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Role"
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
           "Action",
           "*"
          ],
          "op": "glob_covers",
          "value": "s3:ListBucket"
         },
         {
          "path": [
           "Resource",
           "*"
          ],
          "op": "regex",
          "value": "^arn:aws[a-z-]*:s3:::"
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
           "Action",
           "*"
          ],
          "op": "glob_covers",
          "value": "s3:GetObject"
         },
         {
          "path": [
           "Resource",
           "*"
          ],
          "op": "regex",
          "value": "^arn:aws[a-z-]*:s3:::"
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
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "s3:ListBucket"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "^arn:aws[a-z-]*:s3:::"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
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
           "Action",
           "*"
          ],
          "op": "glob_covers",
          "value": "s3:ListBucket"
         },
         {
          "path": [
           "Resource",
           "*"
          ],
          "op": "regex",
          "value": "^arn:aws[a-z-]*:s3:::"
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
           "Action",
           "*"
          ],
          "op": "glob_covers",
          "value": "s3:GetObject"
         },
         {
          "path": [
           "Resource",
           "*"
          ],
          "op": "regex",
          "value": "^arn:aws[a-z-]*:s3:::"
         }
        ]
       }
      ]
     },
     "to": "role",
     "bidirectional": true
    }
   ]
  },
  {
   "id": "rig_policy",
   "tier": "core",
   "quote": "conditionally create a RIG policy when the RIG flag is true and a RIG input bucket is provided",
   "kind": "ref",
   "from": {
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
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ]
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "properties",
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "lambda:InvokeFunction"
     }
    ]
   },
   "to": "role",
   "bidirectional": true
  },
  {
   "id": "rig_s3",
   "tier": "detail",
   "quote": "granting list and get object access to that bucket",
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
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ]
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "properties",
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "lambda:InvokeFunction"
     },
     {
      "path": [
       "properties",
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "s3:ListBucket"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "^arn:aws[a-z-]*:s3:::"
       }
      ]
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "PolicyDocument",
     "Statement",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "s3:GetObject"
     },
     {
      "path": [
       "Resource",
       "*"
      ],
      "op": "regex",
      "value": "^arn:aws[a-z-]*:s3:::"
     }
    ]
   }
  },
  {
   "id": "rig_lambda",
   "tier": "detail",
   "quote": "allowing Lambda invocation for functions with names containing SageMaker or sagemaker",
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
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ]
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "properties",
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "lambda:InvokeFunction"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "PolicyDocument",
     "Statement",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "lambda:InvokeFunction"
     },
     {
      "path": [],
      "op": "regex",
      "value": "(?i)(function:\\*?sagemaker|functionname.{0,80}sagemaker)"
     }
    ]
   }
  },
  {
   "id": "subnet_sg_policies",
   "tier": "core",
   "quote": "additional policies for each provided private subnet and security group that grant the same ENI management actions",
   "kind": "all_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
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
         "AWS::IAM::Policy",
         "AWS::IAM::ManagedPolicy"
        ]
       },
       {
        "path": [
         "properties",
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "ec2:CreateNetworkInterface"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)(:subnet/[^*]|ec2:subnet)"
       }
      ]
     },
     "to": "role",
     "bidirectional": true
    },
    {
     "kind": "ref",
     "from": {
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
         "AWS::IAM::Policy",
         "AWS::IAM::ManagedPolicy"
        ]
       },
       {
        "path": [
         "properties",
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "ec2:CreateNetworkInterface"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)(:security-group/[^*]|ec2:securitygroup)"
       }
      ]
     },
     "to": "role",
     "bidirectional": true
    }
   ],
   "justify": "a policy scoped to the specific subnets and one scoped to the specific security groups, each granting ENI actions to the role; a subnet/* or security-group/* wildcard is not scoped to specific resources"
  },
  {
   "id": "subnet_sg_conditional",
   "tier": "detail",
   "quote": "conditionally create additional policies",
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
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ]
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "properties",
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "ec2:CreateNetworkInterface"
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)(:subnet/[^*]|ec2:subnet|:security-group/[^*]|ec2:securitygroup)"
     }
    ]
   }
  },
  {
   "id": "tag_key",
   "tier": "detail",
   "quote": "all resources must be tagged with a key indicating they are SageMaker HyperPod prerequisites",
   "kind": "attr",
   "select": "role",
   "cond": {
    "path": [
     "Tags",
     "*",
     "Key"
    ],
    "op": "regex",
    "value": "(?i)hyperpod.*prerequisite|prerequisite.*hyperpod"
   }
  },
  {
   "id": "tag_val",
   "tier": "detail",
   "quote": "with a value equal to the role name",
   "kind": "attr",
   "select": "role",
   "cond": {
    "path": [
     "Tags",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "Key"
      ],
      "op": "regex",
      "value": "(?i)hyperpod.*prerequisite|prerequisite.*hyperpod"
     },
     {
      "path": [
       "Value"
      ],
      "op": "regex",
      "value": "ExecRole$"
     }
    ]
   }
  },
  {
   "id": "out_name",
   "tier": "detail",
   "quote": "expose the role name",
   "kind": "any_of",
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
         "ref"
        ],
        "op": "present"
       },
       {
        "path": [
         "value",
         "attr"
        ],
        "op": "absent"
       }
      ]
     },
     "to": "role"
    },
    {
     "kind": "attr",
     "select": "out",
     "cond": {
      "path": [
       "value"
      ],
      "op": "regex",
      "value": "ExecRole$"
     }
    }
   ]
  },
  {
   "id": "out_arn",
   "tier": "detail",
   "quote": "the role name and ARN as outputs",
   "kind": "any_of",
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
     "kind": "attr",
     "select": "out",
     "cond": {
      "path": [
       "value"
      ],
      "op": "regex",
      "value": "(?i)^arn:aws[a-z-]*:iam::[^:]*:role/"
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
