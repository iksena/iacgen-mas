package intent.cfn.row_231

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
  "pool": {
   "types": [
    "AWS::Cognito::IdentityPool"
   ],
   "where": []
  },
  "role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Principal",
      "Federated",
      "*"
     ],
     "op": "eq",
     "value": "cognito-identity.amazonaws.com"
    }
   ]
  },
  "attach": {
   "types": [
    "AWS::Cognito::IdentityPoolRoleAttachment"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "table",
   "kind": "exists",
   "select": "table",
   "tier": "core",
   "quote": "a DynamoDB table"
  },
  {
   "id": "pk_id",
   "kind": "attr",
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
      "value": "id"
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
   "tier": "core",
   "quote": "a numeric id as the partition key",
   "justify": "partition key is the HASH key"
  },
  {
   "id": "id_numeric",
   "kind": "attr",
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
      "value": "id"
     },
     {
      "path": [
       "AttributeType"
      ],
      "op": "eq",
      "value": "N"
     }
    ]
   },
   "tier": "core",
   "quote": "a numeric id",
   "justify": "numeric is type N"
  },
  {
   "id": "table_capacity",
   "kind": "attr",
   "select": "table",
   "tier": "core",
   "quote": "provisioned for 10 read and 10 write capacity units",
   "cond": {
    "path": [
     "ProvisionedThroughput"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "ReadCapacityUnits"
      ],
      "op": "eq",
      "value": 10
     },
     {
      "path": [
       "WriteCapacityUnits"
      ],
      "op": "eq",
      "value": 10
     }
    ]
   }
  },
  {
   "id": "gsi_keyed_id",
   "kind": "attr",
   "select": "table",
   "tier": "core",
   "quote": "a global secondary index also keyed on id",
   "justify": "index keyed on id is a HASH key named id",
   "cond": {
    "path": [
     "GlobalSecondaryIndexes",
     "*",
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
      "value": "id"
     },
     {
      "path": [
       "KeyType"
      ],
      "op": "eq",
      "value": "HASH"
     }
    ]
   }
  },
  {
   "id": "gsi_capacity",
   "kind": "attr",
   "select": "table",
   "tier": "core",
   "quote": "with 5 read and 10 write capacity units",
   "cond": {
    "path": [
     "GlobalSecondaryIndexes",
     "*",
     "ProvisionedThroughput"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "ReadCapacityUnits"
      ],
      "op": "eq",
      "value": 5
     },
     {
      "path": [
       "WriteCapacityUnits"
      ],
      "op": "eq",
      "value": 10
     }
    ]
   }
  },
  {
   "id": "identity_pool",
   "kind": "exists",
   "select": "pool",
   "tier": "core",
   "quote": "a Cognito identity pool"
  },
  {
   "id": "guest_access",
   "kind": "attr",
   "select": "pool",
   "cond": {
    "path": [
     "AllowUnauthenticatedIdentities"
    ],
    "op": "eq",
    "value": true
   },
   "tier": "core",
   "quote": "allows unauthenticated guest access"
  },
  {
   "id": "unauth_role",
   "kind": "exists",
   "select": "role",
   "tier": "core",
   "quote": "the IAM role assumed by unauthenticated identities",
   "justify": "Cognito identities assume roles via cognito-identity.amazonaws.com"
  },
  {
   "id": "role_attachment",
   "kind": "ref",
   "from": "attach",
   "to": "pool",
   "tier": "core",
   "quote": "the identity pool role attachment linking the two"
  },
  {
   "id": "attachment_role",
   "kind": "ref",
   "from": {
    "types": [
     "AWS::Cognito::IdentityPoolRoleAttachment"
    ],
    "where": [
     {
      "path": [
       "Roles",
       "unauthenticated"
      ],
      "op": "present"
     }
    ]
   },
   "to": "role",
   "tier": "core",
   "quote": "the identity pool role attachment linking the two"
  },
  {
   "id": "attachment_unauth",
   "kind": "attr",
   "select": "attach",
   "cond": {
    "path": [
     "Roles",
     "unauthenticated"
    ],
    "op": "present"
   },
   "tier": "core",
   "quote": "IAM role assumed by unauthenticated identities"
  },
  {
   "id": "perm_analytics",
   "kind": "any_of",
   "tier": "core",
   "quote": "submit mobile analytics events",
   "justify": "submitting events is mobileanalytics:PutEvents",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
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
      "value": "mobileanalytics:PutEvents"
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
        "value": "mobileanalytics:PutEvents"
       }
      ]
     },
     "to": "role",
     "bidirectional": true
    }
   ]
  },
  {
   "id": "perm_sync",
   "kind": "any_of",
   "tier": "core",
   "quote": "use Cognito Sync",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
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
      "op": "regex",
      "value": "(?i)^cognito-sync:|^\\*$"
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
        "op": "regex",
        "value": "(?i)^cognito-sync:|^\\*$"
       }
      ]
     },
     "to": "role",
     "bidirectional": true
    }
   ]
  },
  {
   "id": "perm_sns",
   "kind": "any_of",
   "tier": "core",
   "quote": "publish to SNS topics",
   "justify": "publishing is sns:Publish",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
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
      "value": "sns:Publish"
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
        "value": "sns:Publish"
       }
      ]
     },
     "to": "role",
     "bidirectional": true
    }
   ]
  },
  {
   "id": "perm_dynamodb",
   "kind": "any_of",
   "tier": "core",
   "quote": "write items into DynamoDB",
   "justify": "writing items is PutItem, UpdateItem or BatchWriteItem",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
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
      "op": "regex",
      "value": "(?i)^(dynamodb:(PutItem|UpdateItem|BatchWriteItem|Put\\*|Batch\\*|\\*)|\\*)$"
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
        "op": "regex",
        "value": "(?i)^(dynamodb:(PutItem|UpdateItem|BatchWriteItem|Put\\*|Batch\\*|\\*)|\\*)$"
       }
      ]
     },
     "to": "role",
     "bidirectional": true
    }
   ]
  },
  {
   "id": "x_gsi_projection",
   "kind": "attr",
   "select": "table",
   "cond": {
    "path": [
     "GlobalSecondaryIndexes",
     "*",
     "Projection",
     "ProjectionType"
    ],
    "op": "eq",
    "value": "ALL"
   },
   "tier": "extra"
  },
  {
   "id": "x_role_federated",
   "kind": "attr",
   "select": "role",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument"
    ],
    "op": "regex",
    "value": "(?i)unauthenticated"
   },
   "tier": "extra"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
