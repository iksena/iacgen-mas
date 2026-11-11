package intent.cfn.row_218

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
  "role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "pol": {
   "types": [
    "AWS::IAM::Policy",
    "AWS::IAM::RolePolicy"
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
     "value": "doc-example-apigateway-dynamodb-profiles"
    }
   ]
  },
  "named_role_strict": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "RoleName"
     ],
     "op": "eq",
     "value": "doc-example-apigateway-dynamodb-profiles"
    },
    {
     "path": [
      "Policies",
      "*",
      "PolicyDocument",
      "Statement",
      "*",
      "Resource",
      "*"
     ],
     "op": "none_eq",
     "value": "*"
    }
   ]
  },
  "pol_strict": {
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
     "op": "none_eq",
     "value": "*"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "table",
   "kind": "exists",
   "tier": "core",
   "select": "table",
   "quote": "a DynamoDB table"
  },
  {
   "id": "table_name",
   "kind": "attr",
   "tier": "core",
   "select": "table",
   "cond": {
    "path": [
     "TableName"
    ],
    "op": "eq",
    "value": "doc-example-profiles"
   },
   "quote": "a DynamoDB table named \"doc-example-profiles\""
  },
  {
   "id": "pk_name",
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
      "value": "username"
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
   "quote": "a string partition key \"username\"",
   "justify": "partition key means KeyType HASH"
  },
  {
   "id": "pk_type",
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
      "value": "username"
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
   "quote": "a string partition key \"username\""
  },
  {
   "id": "rcu",
   "kind": "attr",
   "tier": "core",
   "select": "table",
   "cond": {
    "path": [
     "ProvisionedThroughput",
     "ReadCapacityUnits"
    ],
    "op": "eq",
    "value": 5
   },
   "quote": "provisioned throughput set to 5 read capacity units and 5 write capacity units"
  },
  {
   "id": "wcu",
   "kind": "attr",
   "tier": "core",
   "select": "table",
   "cond": {
    "path": [
     "ProvisionedThroughput",
     "WriteCapacityUnits"
    ],
    "op": "eq",
    "value": 5
   },
   "quote": "provisioned throughput set to 5 read capacity units and 5 write capacity units"
  },
  {
   "id": "del_policy",
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
   "quote": "deletion/update-replace policies set to delete the table when removed"
  },
  {
   "id": "upd_policy",
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
   "quote": "deletion/update-replace policies set to delete the table when removed"
  },
  {
   "id": "role",
   "kind": "exists",
   "tier": "core",
   "select": "role",
   "quote": "an IAM role named \"doc-example-apigateway-dynamodb-profiles\""
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
    "value": "doc-example-apigateway-dynamodb-profiles"
   },
   "quote": "an IAM role named \"doc-example-apigateway-dynamodb-profiles\""
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
      "value": "apigateway.amazonaws.com"
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
   "quote": "can be assumed by \"apigateway.amazonaws.com\"",
   "justify": "being assumed by a service is an Allow of sts:AssumeRole"
  },
  {
   "id": "act_getitem",
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
        "value": "dynamodb:GetItem"
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
          "value": "dynamodb:GetItem"
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
          "value": "dynamodb:GetItem"
         }
        ]
       },
       {
        "path": [
         "Roles",
         "*"
        ],
        "op": "eq",
        "value": "doc-example-apigateway-dynamodb-profiles"
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
          "value": "dynamodb:GetItem"
         }
        ]
       },
       {
        "path": [
         "RoleName"
        ],
        "op": "eq",
        "value": "doc-example-apigateway-dynamodb-profiles"
       }
      ]
     }
    }
   ],
   "quote": "allowing \"dynamodb:GetItem\", \"dynamodb:PutItem\", and \"dynamodb:Scan\" actions",
   "justify": "the three DynamoDB actions are named in the prompt"
  },
  {
   "id": "act_putitem",
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
        "value": "dynamodb:PutItem"
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
          "value": "dynamodb:PutItem"
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
          "value": "dynamodb:PutItem"
         }
        ]
       },
       {
        "path": [
         "Roles",
         "*"
        ],
        "op": "eq",
        "value": "doc-example-apigateway-dynamodb-profiles"
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
          "value": "dynamodb:PutItem"
         }
        ]
       },
       {
        "path": [
         "RoleName"
        ],
        "op": "eq",
        "value": "doc-example-apigateway-dynamodb-profiles"
       }
      ]
     }
    }
   ],
   "quote": "allowing \"dynamodb:GetItem\", \"dynamodb:PutItem\", and \"dynamodb:Scan\" actions",
   "justify": "the three DynamoDB actions are named in the prompt"
  },
  {
   "id": "act_scan",
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
        "value": "dynamodb:Scan"
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
          "value": "dynamodb:Scan"
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
          "value": "dynamodb:Scan"
         }
        ]
       },
       {
        "path": [
         "Roles",
         "*"
        ],
        "op": "eq",
        "value": "doc-example-apigateway-dynamodb-profiles"
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
          "value": "dynamodb:Scan"
         }
        ]
       },
       {
        "path": [
         "RoleName"
        ],
        "op": "eq",
        "value": "doc-example-apigateway-dynamodb-profiles"
       }
      ]
     }
    }
   ],
   "quote": "allowing \"dynamodb:GetItem\", \"dynamodb:PutItem\", and \"dynamodb:Scan\" actions",
   "justify": "the three DynamoDB actions are named in the prompt"
  },
  {
   "id": "targets_table",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "ref",
     "from": "named_role_strict",
     "to": "table"
    },
    {
     "kind": "attr",
     "select": "named_role_strict",
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
      "value": "table/doc-example-profiles"
     }
    },
    {
     "kind": "ref",
     "from": "pol_strict",
     "to": "table"
    },
    {
     "kind": "attr",
     "select": "pol_strict",
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*",
       "Resource",
       "*"
      ],
      "op": "regex",
      "value": "table/doc-example-profiles"
     }
    }
   ],
   "quote": "strictly targeting the created DynamoDB table",
   "justify": "strictly targeting the table rules out a Resource of *"
  },
  {
   "id": "role_policy_attached",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "attr",
     "select": "named_role",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument"
      ],
      "op": "present"
     }
    },
    {
     "kind": "ref",
     "from": "pol",
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
         "Roles",
         "*"
        ],
        "op": "eq",
        "value": "doc-example-apigateway-dynamodb-profiles"
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
         "RoleName"
        ],
        "op": "eq",
        "value": "doc-example-apigateway-dynamodb-profiles"
       }
      ]
     }
    }
   ],
   "quote": "attach an inline policy"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
