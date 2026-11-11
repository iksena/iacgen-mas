package intent.cfn.row_226

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "table": {
   "types": [
    "AWS::DynamoDB::Table"
   ],
   "where": []
  },
  "vpc": {
   "types": [
    "AWS::EC2::VPC"
   ],
   "where": []
  },
  "sub": {
   "types": [
    "AWS::EC2::Subnet"
   ],
   "where": []
  },
  "sg": {
   "types": [
    "AWS::EC2::SecurityGroup"
   ],
   "where": []
  },
  "subs2": {
   "types": [
    "AWS::EC2::Subnet"
   ],
   "where": [
    {
     "path": [
      "CidrBlock"
     ],
     "op": "in",
     "value": [
      "10.50.10.0/24",
      "10.50.11.0/24"
     ]
    }
   ]
  },
  "d_sg": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::DAX::SubnetGroup"
    }
   ]
  },
  "d_cl": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::DAX::Cluster"
    }
   ]
  },
  "d_role": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::IAM::Role"
    },
    {
     "path": [
      "properties",
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Principal",
      "Service",
      "*"
     ],
     "op": "eq",
     "value": "dax.amazonaws.com"
    }
   ]
  },
  "p_ProjectName": {
   "types": [
    "__parameter__"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "ProjectName"
    }
   ]
  },
  "p_EnableDax": {
   "types": [
    "__parameter__"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "EnableDax"
    }
   ]
  },
  "p_DaxReplicationFactor": {
   "types": [
    "__parameter__"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "DaxReplicationFactor"
    }
   ]
  },
  "d_secgrp": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::EC2::SecurityGroup"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "p_project",
   "kind": "attr",
   "tier": "core",
   "select": "p_ProjectName",
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": "saa-lab-05"
   },
   "quote": "ProjectName defaulting to \"saa-lab-05\""
  },
  {
   "id": "p_enable",
   "kind": "attr",
   "tier": "core",
   "select": "p_EnableDax",
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": "false"
   },
   "quote": "EnableDax defaulting to \"false\""
  },
  {
   "id": "p_enable_true",
   "tier": "detail",
   "quote": "(allowing \"true\" or \"false\")",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": "p_EnableDax",
     "cond": {
      "path": [
       "allowed_values",
       "*"
      ],
      "op": "eq",
      "value": "true"
     }
    },
    {
     "kind": "attr",
     "select": "p_EnableDax",
     "cond": {
      "path": [
       "allowed_values",
       "*"
      ],
      "op": "in",
      "value": [
       "true",
       "false"
      ],
      "every": true
     }
    }
   ]
  },
  {
   "id": "p_enable_false",
   "kind": "attr",
   "tier": "detail",
   "select": "p_EnableDax",
   "cond": {
    "path": [
     "allowed_values",
     "*"
    ],
    "op": "eq",
    "value": "false"
   },
   "quote": "(allowing \"true\" or \"false\")"
  },
  {
   "id": "p_rf",
   "kind": "attr",
   "tier": "core",
   "select": "p_DaxReplicationFactor",
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": 1
   },
   "quote": "DaxReplicationFactor defaulting to 1"
  },
  {
   "id": "p_rf_3",
   "tier": "detail",
   "quote": "(allowing 1 or 3)",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": "p_DaxReplicationFactor",
     "cond": {
      "path": [
       "allowed_values",
       "*"
      ],
      "op": "eq",
      "value": 3
     }
    },
    {
     "kind": "attr",
     "select": "p_DaxReplicationFactor",
     "cond": {
      "path": [
       "allowed_values",
       "*"
      ],
      "op": "in",
      "value": [
       1,
       3
      ],
      "every": true
     }
    }
   ]
  },
  {
   "id": "table",
   "kind": "exists",
   "tier": "core",
   "select": "table",
   "quote": "an on-demand DynamoDB table"
  },
  {
   "id": "billing",
   "kind": "attr",
   "tier": "core",
   "select": "table",
   "cond": {
    "path": [
     "BillingMode"
    ],
    "op": "eq",
    "value": "PAY_PER_REQUEST"
   },
   "quote": "on-demand DynamoDB table",
   "justify": "on-demand billing is PAY_PER_REQUEST"
  },
  {
   "id": "tname",
   "kind": "attr",
   "tier": "core",
   "select": "table",
   "cond": {
    "path": [
     "TableName"
    ],
    "op": "eq",
    "value": "saa-lab-05-orders"
   },
   "quote": "named \"{ProjectName}-orders\"",
   "justify": "default ProjectName saa-lab-05"
  },
  {
   "id": "hash",
   "kind": "attr",
   "tier": "core",
   "select": "table",
   "cond": {
    "path": [
     "KeySchema",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "AttributeName"
      ],
      "op": "eq",
      "value": "customerId"
     },
     {
      "path": [
       "KeyType"
      ],
      "op": "eq",
      "value": "HASH"
     }
    ]
   },
   "quote": "a string partition key \"customerId\"",
   "justify": "partition key means KeyType HASH"
  },
  {
   "id": "range",
   "kind": "attr",
   "tier": "core",
   "select": "table",
   "cond": {
    "path": [
     "KeySchema",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "AttributeName"
      ],
      "op": "eq",
      "value": "orderId"
     },
     {
      "path": [
       "KeyType"
      ],
      "op": "eq",
      "value": "RANGE"
     }
    ]
   },
   "quote": "a string sort key \"orderId\"",
   "justify": "sort key means KeyType RANGE"
  },
  {
   "id": "hash_type",
   "kind": "attr",
   "tier": "core",
   "select": "table",
   "cond": {
    "path": [
     "AttributeDefinitions",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "AttributeName"
      ],
      "op": "eq",
      "value": "customerId"
     },
     {
      "path": [
       "AttributeType"
      ],
      "op": "eq",
      "value": "S"
     }
    ]
   },
   "quote": "a string partition key \"customerId\""
  },
  {
   "id": "range_type",
   "kind": "attr",
   "tier": "core",
   "select": "table",
   "cond": {
    "path": [
     "AttributeDefinitions",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "AttributeName"
      ],
      "op": "eq",
      "value": "orderId"
     },
     {
      "path": [
       "AttributeType"
      ],
      "op": "eq",
      "value": "S"
     }
    ]
   },
   "quote": "a string sort key \"orderId\""
  },
  {
   "id": "sse",
   "kind": "attr",
   "tier": "core",
   "select": "table",
   "cond": {
    "path": [
     "SSESpecification",
     "SSEEnabled"
    ],
    "op": "eq",
    "value": true
   },
   "quote": "server-side encryption enabled"
  },
  {
   "id": "pitr_off",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "table",
     "cond": {
      "path": [
       "PointInTimeRecoverySpecification",
       "PointInTimeRecoveryEnabled"
      ],
      "op": "eq",
      "value": false
     }
    },
    {
     "kind": "attr",
     "select": "table",
     "cond": {
      "path": [
       "PointInTimeRecoverySpecification"
      ],
      "op": "absent"
     }
    }
   ],
   "quote": "point-in-time recovery disabled"
  },
  {
   "id": "del",
   "kind": "attr",
   "tier": "core",
   "select": "table",
   "cond": {
    "path": [
     "__resource__",
     "DeletionPolicy"
    ],
    "op": "eq",
    "value": "Delete"
   },
   "quote": "deletion and update-replace policies set to delete the table when removed"
  },
  {
   "id": "upd",
   "kind": "attr",
   "tier": "core",
   "select": "table",
   "cond": {
    "path": [
     "__resource__",
     "UpdateReplacePolicy"
    ],
    "op": "eq",
    "value": "Delete"
   },
   "quote": "deletion and update-replace policies set to delete the table when removed"
  },
  {
   "id": "vpc",
   "kind": "exists",
   "tier": "core",
   "select": "vpc",
   "quote": "a VPC with CIDR \"10.50.0.0/16\""
  },
  {
   "id": "vpc_cidr",
   "kind": "attr",
   "tier": "core",
   "select": "vpc",
   "cond": {
    "path": [
     "CidrBlock"
    ],
    "op": "eq",
    "value": "10.50.0.0/16"
   },
   "quote": "a VPC with CIDR \"10.50.0.0/16\""
  },
  {
   "id": "dns_support",
   "tier": "detail",
   "quote": "with DNS support and hostnames enabled",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "vpc",
     "cond": {
      "path": [
       "EnableDnsSupport"
      ],
      "op": "eq",
      "value": true
     }
    },
    {
     "kind": "attr",
     "select": "vpc",
     "cond": {
      "path": [
       "EnableDnsSupport"
      ],
      "op": "absent"
     }
    }
   ],
   "justify": "DNS support is on by default when the setting is omitted"
  },
  {
   "id": "dns_hosts",
   "kind": "attr",
   "tier": "detail",
   "select": "vpc",
   "cond": {
    "path": [
     "EnableDnsHostnames"
    ],
    "op": "eq",
    "value": true
   },
   "quote": "with DNS support and hostnames enabled"
  },
  {
   "id": "sub_a",
   "kind": "attr",
   "tier": "core",
   "select": "sub",
   "cond": {
    "path": [
     "CidrBlock"
    ],
    "op": "eq",
    "value": "10.50.10.0/24"
   },
   "quote": "\"10.50.10.0/24\" in the first available availability zone"
  },
  {
   "id": "sub_b",
   "kind": "attr",
   "tier": "core",
   "select": "sub",
   "cond": {
    "path": [
     "CidrBlock"
    ],
    "op": "eq",
    "value": "10.50.11.0/24"
   },
   "quote": "\"10.50.11.0/24\" in the second available availability zone"
  },
  {
   "id": "sub_az",
   "kind": "exists",
   "tier": "detail",
   "select": "subs2",
   "min": 2,
   "distinct_path": [
    "AvailabilityZone"
   ],
   "quote": "in the first available availability zone and \"10.50.11.0/24\" in the second available availability zone",
   "justify": "first and second availability zones are different zones"
  },
  {
   "id": "sgs",
   "kind": "exists",
   "tier": "core",
   "select": "sg",
   "min": 2,
   "quote": "a client security group, and a DAX security group",
   "justify": "a client and a DAX security group are two groups"
  },
  {
   "id": "dax_ingress",
   "tier": "core",
   "quote": "allows inbound TCP traffic on port 8111 exclusively from the client security group",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::EC2::SecurityGroup"
      ],
      "where": [
       {
        "path": [
         "SecurityGroupIngress",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "FromPort"
          ],
          "op": "eq",
          "value": 8111
         },
         {
          "path": [
           "ToPort"
          ],
          "op": "eq",
          "value": 8111
         },
         {
          "path": [
           "IpProtocol"
          ],
          "op": "eq",
          "value": "tcp"
         },
         {
          "path": [
           "SourceSecurityGroupId"
          ],
          "op": "present"
         }
        ]
       },
       {
        "path": [
         "SecurityGroupIngress",
         "*",
         "CidrIp"
        ],
        "op": "absent"
       },
       {
        "path": [
         "SecurityGroupIngress",
         "*",
         "CidrIpv6"
        ],
        "op": "absent"
       },
       {
        "path": [
         "SecurityGroupIngress",
         "*",
         "SourcePrefixListId"
        ],
        "op": "absent"
       }
      ]
     },
     "to": "sg"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::EC2::SecurityGroupIngress"
      ],
      "where": [
       {
        "path": [
         "FromPort"
        ],
        "op": "eq",
        "value": 8111
       },
       {
        "path": [
         "ToPort"
        ],
        "op": "eq",
        "value": 8111
       },
       {
        "path": [
         "IpProtocol"
        ],
        "op": "eq",
        "value": "tcp"
       },
       {
        "path": [
         "SourceSecurityGroupId"
        ],
        "op": "present"
       },
       {
        "path": [
         "CidrIp"
        ],
        "op": "absent"
       },
       {
        "path": [
         "CidrIpv6"
        ],
        "op": "absent"
       },
       {
        "path": [
         "SourcePrefixListId"
        ],
        "op": "absent"
       }
      ]
     },
     "to": "sg"
    }
   ]
  },
  {
   "id": "sg_exists",
   "kind": "exists",
   "tier": "core",
   "select": "d_sg",
   "quote": "a DAX subnet group across both subnets"
  },
  {
   "id": "sg_gated",
   "kind": "attr",
   "tier": "core",
   "select": "d_sg",
   "cond": {
    "path": [
     "gated"
    ],
    "op": "truthy"
   },
   "quote": "When EnableDax is set to \"true\", the template must conditionally deploy"
  },
  {
   "id": "sg_name",
   "kind": "attr",
   "tier": "core",
   "select": "d_sg",
   "cond": {
    "path": [
     "properties",
     "SubnetGroupName"
    ],
    "op": "eq",
    "value": "saa-lab-05-dax-subnets"
   },
   "quote": "a DAX subnet group across both subnets named \"{ProjectName}-dax-subnets\"",
   "justify": "default ProjectName saa-lab-05"
  },
  {
   "id": "sg_subnets",
   "kind": "attr",
   "tier": "detail",
   "select": "d_sg",
   "cond": {
    "path": [
     "properties",
     "SubnetIds"
    ],
    "op": "len_gte",
    "value": 2
   },
   "quote": "across both subnets",
   "justify": "both subnets means at least two subnet ids"
  },
  {
   "id": "role",
   "kind": "exists",
   "tier": "core",
   "select": "d_role",
   "quote": "an IAM service role named \"{ProjectName}-dax-role\" allowing \"dax.amazonaws.com\""
  },
  {
   "id": "role_gated",
   "kind": "attr",
   "tier": "core",
   "select": "d_role",
   "cond": {
    "path": [
     "gated"
    ],
    "op": "truthy"
   },
   "quote": "When EnableDax is set to \"true\", the template must conditionally deploy"
  },
  {
   "id": "role_name",
   "kind": "attr",
   "tier": "core",
   "select": "d_role",
   "cond": {
    "path": [
     "properties",
     "RoleName"
    ],
    "op": "eq",
    "value": "saa-lab-05-dax-role"
   },
   "quote": "an IAM service role named \"{ProjectName}-dax-role\"",
   "justify": "default ProjectName saa-lab-05"
  },
  {
   "id": "role_item",
   "tier": "detail",
   "quote": "to perform DynamoDB item and table operations on the orders table and its indexes",
   "justify": "an item operation such as GetItem is implied",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "d_role",
     "cond": {
      "path": [
       "properties",
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "dynamodb:GetItem"
     }
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
        "value": "dynamodb:GetItem"
       }
      ]
     },
     "to": "d_role",
     "bidirectional": true
    }
   ]
  },
  {
   "id": "role_table",
   "tier": "detail",
   "quote": "to perform DynamoDB item and table operations on the orders table and its indexes",
   "justify": "a table operation such as DescribeTable is implied",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "d_role",
     "cond": {
      "path": [
       "properties",
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "dynamodb:DescribeTable"
     }
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
        "value": "dynamodb:DescribeTable"
       }
      ]
     },
     "to": "d_role",
     "bidirectional": true
    }
   ]
  },
  {
   "id": "role_index",
   "tier": "detail",
   "quote": "on the orders table and its indexes",
   "justify": "indexes are addressed as table/index/*",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "d_role",
     "cond": {
      "path": [
       "properties",
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*",
       "Resource",
       "*"
      ],
      "op": "regex",
      "value": "/index/"
     }
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
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "/index/"
       }
      ]
     },
     "to": "d_role",
     "bidirectional": true
    }
   ]
  },
  {
   "id": "role_on_table",
   "kind": "any_of",
   "tier": "detail",
   "quote": "on the orders table",
   "justify": "the grant names the stated table by reference or by its stated name",
   "checks": [
    {
     "kind": "ref",
     "from": "d_role",
     "to": "table"
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
       }
      ]
     },
     "to": "table"
    },
    {
     "kind": "attr",
     "select": "d_role",
     "cond": {
      "path": [
       "properties",
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*",
       "Resource",
       "*"
      ],
      "op": "regex",
      "value": "table/saa-lab-05-orders"
     }
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
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "table/saa-lab-05-orders"
       }
      ]
     },
     "to": "d_role",
     "bidirectional": true
    }
   ]
  },
  {
   "id": "cluster",
   "kind": "exists",
   "tier": "core",
   "select": "d_cl",
   "quote": "a DAX cluster named \"{ProjectName}-dax\""
  },
  {
   "id": "cl_gated",
   "kind": "attr",
   "tier": "core",
   "select": "d_cl",
   "cond": {
    "path": [
     "gated"
    ],
    "op": "truthy"
   },
   "quote": "When EnableDax is set to \"true\", the template must conditionally deploy"
  },
  {
   "id": "cl_name",
   "kind": "attr",
   "tier": "core",
   "select": "d_cl",
   "cond": {
    "path": [
     "properties",
     "ClusterName"
    ],
    "op": "eq",
    "value": "saa-lab-05-dax"
   },
   "quote": "a DAX cluster named \"{ProjectName}-dax\"",
   "justify": "default ProjectName saa-lab-05"
  },
  {
   "id": "cl_node",
   "kind": "attr",
   "tier": "core",
   "select": "d_cl",
   "cond": {
    "path": [
     "properties",
     "NodeType"
    ],
    "op": "eq",
    "value": "dax.t3.small"
   },
   "quote": "using node type \"dax.t3.small\""
  },
  {
   "id": "cl_sse",
   "kind": "attr",
   "tier": "core",
   "select": "d_cl",
   "cond": {
    "path": [
     "properties",
     "SSESpecification",
     "SSEEnabled"
    ],
    "op": "eq",
    "value": true
   },
   "quote": "server-side encryption enabled, and the configured replication factor"
  },
  {
   "id": "cl_rf",
   "kind": "attr",
   "tier": "detail",
   "select": "d_cl",
   "cond": {
    "path": [
     "properties",
     "ReplicationFactor"
    ],
    "op": "eq",
    "value": 1
   },
   "quote": "and the configured replication factor",
   "justify": "DaxReplicationFactor defaults to 1"
  },
  {
   "id": "out_table",
   "tier": "detail",
   "quote": "export the table name",
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
        "op": "absent"
       }
      ]
     },
     "to": "table"
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
        "value": "saa-lab-05-orders"
       }
      ]
     }
    }
   ],
   "justify": "the table name is its stated name, written literally or by reference"
  },
  {
   "id": "out_arn",
   "tier": "detail",
   "quote": "table ARN",
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
     "to": "table"
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
         "value"
        ],
        "op": "regex",
        "value": "\\.Arn\\}"
       }
      ]
     },
     "to": "table"
    }
   ]
  },
  {
   "id": "out_status",
   "kind": "any_of",
   "tier": "detail",
   "quote": "DAX status",
   "justify": "with EnableDax at its default false the status reads false or disabled, alongside the endpoint's disabled",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "__output__"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "value"
      ],
      "op": "eq",
      "value": "false"
     }
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
        "value": "disabled"
       }
      ]
     },
     "min": 2
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__output__"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)dax.?(status|enabled)"
     }
    }
   ]
  },
  {
   "id": "out_sg",
   "tier": "detail",
   "quote": "client security group ID",
   "kind": "ref",
   "from": {
    "types": [
     "__output__"
    ],
    "where": []
   },
   "to": {
    "types": [
     "AWS::EC2::SecurityGroup"
    ],
    "where": [
     {
      "path": [
       "SecurityGroupIngress",
       "*",
       "FromPort"
      ],
      "op": "none_eq",
      "value": 8111
     }
    ]
   }
  },
  {
   "id": "out_disabled",
   "kind": "attr",
   "tier": "detail",
   "select": {
    "types": [
     "__output__"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "value"
    ],
    "op": "eq",
    "value": "disabled"
   },
   "quote": "either the DAX cluster discovery endpoint or \"disabled\""
  },
  {
   "id": "out_count",
   "kind": "exists",
   "tier": "detail",
   "select": {
    "types": [
     "__output__"
    ],
    "where": []
   },
   "min": 5,
   "quote": "export the table name, table ARN, DAX status, client security group ID, and either the DAX cluster discovery endpoint or \"disabled\" in the outputs",
   "justify": "five exported values are listed"
  },
  {
   "id": "x_sub_vpc",
   "kind": "ref",
   "tier": "extra",
   "from": "sub",
   "to": "vpc"
  },
  {
   "id": "x_sg_vpc",
   "kind": "ref",
   "tier": "extra",
   "from": "sg",
   "to": "vpc"
  },
  {
   "id": "x_cl_sg",
   "kind": "ref",
   "tier": "extra",
   "from": "d_cl",
   "to": "d_sg"
  },
  {
   "id": "x_cl_role",
   "kind": "ref",
   "tier": "extra",
   "from": "d_cl",
   "to": "d_role"
  },
  {
   "id": "x_cl_dsg",
   "kind": "ref",
   "tier": "extra",
   "from": "d_cl",
   "to": "d_secgrp"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
