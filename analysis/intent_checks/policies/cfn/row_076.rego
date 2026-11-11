package intent.cfn.row_076

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "stream": {
   "types": [
    "AWS::Kinesis::Stream"
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
  },
  "outs": {
   "types": [
    "__output__"
   ],
   "where": []
  },
  "pols": {
   "types": [
    "AWS::IAM::Policy",
    "AWS::IAM::ManagedPolicy",
    "AWS::IAM::RolePolicy"
   ],
   "where": []
  },
  "put_pols": {
   "types": [
    "AWS::IAM::Policy",
    "AWS::IAM::ManagedPolicy",
    "AWS::IAM::RolePolicy"
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
     "value": "kinesis:PutRecord"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "stream",
   "kind": "exists",
   "tier": "core",
   "quote": "a Kinesis data stream named \"my-stream-kinesis\"",
   "select": "stream"
  },
  {
   "id": "stream_name",
   "kind": "attr",
   "tier": "core",
   "quote": "named \"my-stream-kinesis\"",
   "select": "stream",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "eq",
    "value": "my-stream-kinesis"
   }
  },
  {
   "id": "shard",
   "kind": "attr",
   "tier": "core",
   "quote": "a single shard",
   "justify": "single shard means ShardCount 1",
   "select": "stream",
   "cond": {
    "path": [
     "ShardCount"
    ],
    "op": "eq",
    "value": 1
   }
  },
  {
   "id": "retention",
   "kind": "any_of",
   "tier": "core",
   "quote": "24-hour data retention",
   "justify": "24 hours is the Kinesis default, so leaving it unset also means 24-hour retention",
   "checks": [
    {
     "kind": "attr",
     "select": "stream",
     "cond": {
      "path": [
       "RetentionPeriodHours"
      ],
      "op": "eq",
      "value": 24
     }
    },
    {
     "kind": "attr",
     "select": "stream",
     "cond": {
      "path": [
       "RetentionPeriodHours"
      ],
      "op": "absent"
     }
    }
   ]
  },
  {
   "id": "pool",
   "kind": "exists",
   "tier": "core",
   "quote": "a Cognito identity pool",
   "select": "pool"
  },
  {
   "id": "unauth",
   "kind": "attr",
   "tier": "core",
   "quote": "allows unauthenticated identities",
   "select": "pool",
   "cond": {
    "path": [
     "AllowUnauthenticatedIdentities"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "role",
   "kind": "exists",
   "tier": "core",
   "quote": "the necessary IAM role and policy attachments so that unauthenticated Cognito users",
   "select": "role"
  },
  {
   "id": "role_unauth",
   "kind": "exists",
   "tier": "detail",
   "quote": "unauthenticated Cognito users",
   "select": {
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
     },
     {
      "path": [
       "AssumeRolePolicyDocument",
       "Statement",
       "*",
       "Condition",
       "*",
       "cognito-identity.amazonaws.com:amr"
      ],
      "op": "none_eq",
      "value": "authenticated"
     },
     {
      "path": [
       "AssumeRolePolicyDocument",
       "Statement",
       "*",
       "Condition",
       "*",
       "cognito-identity.amazonaws.com:amr",
       "*"
      ],
      "op": "none_eq",
      "value": "authenticated"
     }
    ]
   }
  },
  {
   "id": "attach_pool",
   "kind": "ref",
   "tier": "core",
   "quote": "a Cognito identity pool that allows unauthenticated identities to publish data to that stream",
   "from": "attach",
   "to": "pool"
  },
  {
   "id": "attach_unauth",
   "kind": "ref",
   "tier": "core",
   "quote": "unauthenticated Cognito users can perform Put operations",
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
   "to": "role"
  },
  {
   "id": "put_ops",
   "kind": "any_of",
   "tier": "core",
   "quote": "perform Put operations on the Kinesis stream",
   "justify": "Put operations include kinesis:PutRecord",
   "checks": [
    {
     "kind": "ref",
     "bidirectional": true,
     "to": "role",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::RolePolicy"
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
        "value": "kinesis:PutRecord"
       }
      ]
     }
    },
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
      "value": "kinesis:PutRecord"
     }
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "AmazonKinesisFullAccess"
     }
    }
   ]
  },
  {
   "id": "policy_stream",
   "kind": "any_of",
   "tier": "detail",
   "quote": "Put operations on the Kinesis stream",
   "checks": [
    {
     "kind": "ref",
     "from": "put_pols",
     "to": "stream"
    },
    {
     "kind": "ref",
     "from": {
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
        "value": "kinesis:PutRecord"
       }
      ]
     },
     "to": "stream"
    },
    {
     "kind": "attr",
     "select": "put_pols",
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*",
       "Resource",
       "*"
      ],
      "op": "contains",
      "value": "my-stream-kinesis"
     }
    },
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
       "Resource",
       "*"
      ],
      "op": "contains",
      "value": "my-stream-kinesis"
     }
    }
   ]
  },
  {
   "id": "out_pool",
   "kind": "ref",
   "tier": "detail",
   "quote": "output the identity pool ID",
   "from": "outs",
   "to": "pool"
  },
  {
   "id": "out_stream_name",
   "kind": "any_of",
   "tier": "detail",
   "quote": "stream name",
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
     "to": "stream"
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
        "value": "my-stream-kinesis"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "out_stream_arn",
   "kind": "any_of",
   "tier": "detail",
   "quote": "and stream ARN",
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
     "to": "stream"
    },
    {
     "kind": "attr",
     "select": "outs",
     "cond": {
      "path": [
       "value"
      ],
      "op": "regex",
      "value": "(?i)arn:.*kinesis"
     }
    }
   ]
  },
  {
   "id": "x_encrypt",
   "kind": "attr",
   "tier": "extra",
   "select": "stream",
   "cond": {
    "path": [
     "StreamEncryption",
     "EncryptionType"
    ],
    "op": "eq",
    "value": "KMS"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
