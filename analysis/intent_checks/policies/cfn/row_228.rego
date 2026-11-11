package intent.cfn.row_228

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "api": {
   "types": [
    "AWS::AppSync::GraphQLApi"
   ],
   "where": []
  },
  "schema": {
   "types": [
    "AWS::AppSync::GraphQLSchema"
   ],
   "where": []
  },
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
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Principal",
      "Service",
      "*"
     ],
     "op": "eq",
     "value": "appsync.amazonaws.com"
    }
   ]
  },
  "iam_pol": {
   "types": [
    "AWS::IAM::Policy",
    "AWS::IAM::ManagedPolicy"
   ],
   "where": []
  },
  "ds": {
   "types": [
    "AWS::AppSync::DataSource"
   ],
   "where": [
    {
     "path": [
      "Type"
     ],
     "op": "eq",
     "value": "AMAZON_DYNAMODB"
    }
   ]
  },
  "pipe": {
   "types": [
    "AWS::AppSync::Resolver"
   ],
   "where": [
    {
     "path": [
      "FieldName"
     ],
     "op": "eq",
     "value": "addSong"
    },
    {
     "path": [
      "Kind"
     ],
     "op": "eq",
     "value": "PIPELINE"
    },
    {
     "path": [
      "TypeName"
     ],
     "op": "eq",
     "value": "Mutation"
    }
   ]
  },
  "fns": {
   "types": [
    "AWS::AppSync::FunctionConfiguration"
   ],
   "where": []
  },
  "fn_validate": {
   "types": [
    "AWS::AppSync::FunctionConfiguration"
   ],
   "where": [
    {
     "path": [],
     "op": "regex",
     "value": "(?is)artist.*(a-z|alpha|letters|p\\{l)|(a-z|alpha|letters|p\\{l).*artist"
    }
   ]
  },
  "fn_put": {
   "types": [
    "AWS::AppSync::FunctionConfiguration"
   ],
   "where": [
    {
     "path": [],
     "op": "regex",
     "value": "(?i)PutItem|UpdateItem|ddb\\.put|ddb\\.update|\\.put\\("
    }
   ]
  },
  "decl_validate": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::AppSync::FunctionConfiguration"
    },
    {
     "path": [
      "properties"
     ],
     "op": "regex",
     "value": "(?is)artist.*(a-z|alpha|letters|p\\{l)|(a-z|alpha|letters|p\\{l).*artist"
    }
   ]
  },
  "decl_put": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::AppSync::FunctionConfiguration"
    },
    {
     "path": [
      "properties"
     ],
     "op": "regex",
     "value": "(?i)PutItem|UpdateItem|ddb\\.put|ddb\\.update|\\.put\\("
    }
   ]
  },
  "getsongs": {
   "types": [
    "AWS::AppSync::Resolver"
   ],
   "where": [
    {
     "path": [
      "FieldName"
     ],
     "op": "eq",
     "value": "getSongs"
    },
    {
     "path": [
      "TypeName"
     ],
     "op": "eq",
     "value": "Query"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "graphql_api",
   "kind": "exists",
   "select": "api",
   "tier": "core",
   "quote": "AWS AppSync GraphQL API"
  },
  {
   "id": "iam_auth",
   "kind": "attr",
   "select": "api",
   "cond": {
    "path": [
     "AuthenticationType"
    ],
    "op": "eq",
    "value": "AWS_IAM"
   },
   "tier": "core",
   "quote": "secured with IAM authorization"
  },
  {
   "id": "xray",
   "kind": "attr",
   "select": "api",
   "cond": {
    "path": [
     "XrayEnabled"
    ],
    "op": "eq",
    "value": true
   },
   "tier": "core",
   "quote": "request tracing enabled",
   "justify": "AppSync request tracing is X-Ray"
  },
  {
   "id": "schema_song",
   "kind": "all_of",
   "tier": "core",
   "quote": "a Song type with id, name, and artist fields",
   "checks": [
    {
     "kind": "attr",
     "select": "schema",
     "cond": {
      "path": [
       "Definition"
      ],
      "op": "regex",
      "value": "(?s)type\\s+Song\\s*\\{[^}]*\\bid\\b"
     }
    },
    {
     "kind": "attr",
     "select": "schema",
     "cond": {
      "path": [
       "Definition"
      ],
      "op": "regex",
      "value": "(?s)type\\s+Song\\s*\\{[^}]*\\bname\\b"
     }
    },
    {
     "kind": "attr",
     "select": "schema",
     "cond": {
      "path": [
       "Definition"
      ],
      "op": "regex",
      "value": "(?s)type\\s+Song\\s*\\{[^}]*\\bartist\\b"
     }
    }
   ]
  },
  {
   "id": "schema_getsongs",
   "kind": "attr",
   "select": "schema",
   "cond": {
    "path": [
     "Definition"
    ],
    "op": "regex",
    "value": "(?s)type\\s+Query\\s*\\{[^}]*\\bgetSongs\\b[^}]*Song"
   },
   "tier": "core",
   "quote": "a getSongs query returning all songs"
  },
  {
   "id": "getsongs_resolver",
   "kind": "exists",
   "select": "getsongs",
   "tier": "detail",
   "quote": "a getSongs query returning all songs"
  },
  {
   "id": "getsongs_scan",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a getSongs query returning all songs",
   "justify": "returning every item in a table is a DynamoDB Scan",
   "checks": [
    {
     "kind": "attr",
     "select": "getsongs",
     "cond": {
      "path": [
       "RequestMappingTemplate"
      ],
      "op": "regex",
      "value": "(?i)\\bscan\\b"
     }
    },
    {
     "kind": "attr",
     "select": "getsongs",
     "cond": {
      "path": [
       "Code"
      ],
      "op": "regex",
      "value": "(?i)\\bscan\\b"
     }
    },
    {
     "kind": "attr",
     "select": "fns",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)\\bscan\\b"
     }
    }
   ]
  },
  {
   "id": "schema_addsong",
   "kind": "attr",
   "select": "schema",
   "cond": {
    "path": [
     "Definition"
    ],
    "op": "regex",
    "value": "(?s)type\\s+Mutation\\s*\\{[^}]*\\baddSong\\b"
   },
   "tier": "core",
   "quote": "an addSong mutation that accepts a name and artist"
  },
  {
   "id": "schema_addsong_args",
   "kind": "attr",
   "select": "schema",
   "cond": {
    "path": [
     "Definition"
    ],
    "op": "regex",
    "value": "(?s)addSong\\s*\\([^)]*\\bname\\b[^)]*\\bartist\\b|addSong\\s*\\([^)]*\\bartist\\b[^)]*\\bname\\b|input\\s+\\w+\\s*\\{[^}]*\\bname\\b[^}]*\\bartist\\b|input\\s+\\w+\\s*\\{[^}]*\\bartist\\b[^}]*\\bname\\b"
   },
   "tier": "core",
   "quote": "an addSong mutation that accepts a name and artist"
  },
  {
   "id": "table",
   "kind": "exists",
   "select": "table",
   "tier": "core",
   "quote": "Song records should be stored in a DynamoDB table"
  },
  {
   "id": "table_pk_id",
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
   "quote": "using id as the partition key",
   "justify": "partition key is the HASH key"
  },
  {
   "id": "table_retain",
   "kind": "all_of",
   "tier": "core",
   "quote": "retained if the stack is ever deleted or replaced",
   "checks": [
    {
     "kind": "attr",
     "select": "table",
     "cond": {
      "path": [
       "__resource__",
       "DeletionPolicy"
      ],
      "op": "eq",
      "value": "Retain"
     }
    },
    {
     "kind": "attr",
     "select": "table",
     "cond": {
      "path": [
       "__resource__",
       "UpdateReplacePolicy"
      ],
      "op": "eq",
      "value": "Retain"
     }
    }
   ]
  },
  {
   "id": "appsync_role",
   "kind": "exists",
   "select": "role",
   "tier": "core",
   "quote": "the IAM service role AppSync needs",
   "justify": "AppSync principal is appsync.amazonaws.com"
  },
  {
   "id": "role_read",
   "kind": "any_of",
   "tier": "core",
   "quote": "to read from and write to that table",
   "justify": "reading a table is GetItem, BatchGetItem, Query or Scan",
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
      "value": "(?i)^(dynamodb:(GetItem|BatchGetItem|Query|Scan|Get\\*|Batch\\*|\\*)|\\*)$"
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
        "value": "(?i)^(dynamodb:(GetItem|BatchGetItem|Query|Scan|Get\\*|Batch\\*|\\*)|\\*)$"
       }
      ]
     },
     "to": "role",
     "bidirectional": true
    }
   ]
  },
  {
   "id": "role_write",
   "kind": "any_of",
   "tier": "core",
   "quote": "to read from and write to that table",
   "justify": "writing an item is PutItem, UpdateItem or BatchWriteItem",
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
      "value": "(?i)^(dynamodb:(PutItem|BatchWriteItem|UpdateItem|Put\\*|Batch\\*|\\*)|\\*)$"
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
        "value": "(?i)^(dynamodb:(PutItem|BatchWriteItem|UpdateItem|Put\\*|Batch\\*|\\*)|\\*)$"
       }
      ]
     },
     "to": "role",
     "bidirectional": true
    }
   ]
  },
  {
   "id": "role_targets_table",
   "kind": "any_of",
   "tier": "detail",
   "quote": "to read from and write to that table",
   "checks": [
    {
     "kind": "ref",
     "from": "role",
     "to": "table"
    },
    {
     "kind": "ref",
     "from": "iam_pol",
     "to": "table"
    }
   ]
  },
  {
   "id": "datasource_table",
   "kind": "any_of",
   "tier": "detail",
   "quote": "Song records should be stored in a DynamoDB table",
   "checks": [
    {
     "kind": "ref",
     "from": "ds",
     "to": "table"
    },
    {
     "kind": "join",
     "from": "ds",
     "from_path": [
      "DynamoDBConfig",
      "TableName"
     ],
     "to": "table",
     "to_path": [
      "TableName"
     ]
    }
   ]
  },
  {
   "id": "datasource_role",
   "kind": "ref",
   "from": "ds",
   "to": "role",
   "tier": "detail",
   "quote": "the IAM service role AppSync needs to read from and write to that table"
  },
  {
   "id": "pipeline_resolver",
   "kind": "exists",
   "select": "pipe",
   "tier": "core",
   "quote": "implemented as a two-step pipeline resolver"
  },
  {
   "id": "two_steps",
   "kind": "attr",
   "select": "pipe",
   "cond": {
    "path": [
     "PipelineConfig",
     "Functions"
    ],
    "op": "len_eq",
    "value": 2
   },
   "tier": "core",
   "quote": "two-step pipeline resolver",
   "justify": "two steps means two pipeline functions"
  },
  {
   "id": "validate_letters",
   "kind": "any_of",
   "tier": "detail",
   "quote": "validates that the submitted artist value contains only letters",
   "checks": [
    {
     "kind": "attr",
     "select": "fns",
     "cond": {
      "path": [
       "RequestMappingTemplate"
      ],
      "op": "regex",
      "value": "(?is)artist.*(a-z|alpha|letters|p\\{l)|(a-z|alpha|letters|p\\{l).*artist"
     }
    },
    {
     "kind": "attr",
     "select": "fns",
     "cond": {
      "path": [
       "ResponseMappingTemplate"
      ],
      "op": "regex",
      "value": "(?is)artist.*(a-z|alpha|letters|p\\{l)|(a-z|alpha|letters|p\\{l).*artist"
     }
    },
    {
     "kind": "attr",
     "select": "fns",
     "cond": {
      "path": [
       "Code"
      ],
      "op": "regex",
      "value": "(?is)artist.*(a-z|alpha|letters|p\\{l)|(a-z|alpha|letters|p\\{l).*artist"
     }
    }
   ]
  },
  {
   "id": "validate_error",
   "kind": "any_of",
   "tier": "detail",
   "quote": "returns a validation error if it is missing or invalid",
   "checks": [
    {
     "kind": "attr",
     "select": "fn_validate",
     "cond": {
      "path": [
       "RequestMappingTemplate"
      ],
      "op": "regex",
      "value": "(?i)error"
     }
    },
    {
     "kind": "attr",
     "select": "fn_validate",
     "cond": {
      "path": [
       "ResponseMappingTemplate"
      ],
      "op": "regex",
      "value": "(?i)error"
     }
    },
    {
     "kind": "attr",
     "select": "fn_validate",
     "cond": {
      "path": [
       "Code"
      ],
      "op": "regex",
      "value": "(?i)error"
     }
    }
   ]
  },
  {
   "id": "validate_is_first",
   "kind": "join",
   "from": "pipe",
   "from_path": [
    "PipelineConfig",
    "Functions",
    0,
    "ref"
   ],
   "to": "decl_validate",
   "to_path": [
    "name"
   ],
   "tier": "detail",
   "quote": "the first step validates that the submitted artist value contains only letters"
  },
  {
   "id": "put_autoid",
   "kind": "any_of",
   "tier": "detail",
   "quote": "with an automatically generated id",
   "checks": [
    {
     "kind": "attr",
     "select": "fn_put",
     "cond": {
      "path": [
       "RequestMappingTemplate"
      ],
      "op": "regex",
      "value": "(?i)autoId|autoUlid|uuid|ulid"
     }
    },
    {
     "kind": "attr",
     "select": "fn_put",
     "cond": {
      "path": [
       "Code"
      ],
      "op": "regex",
      "value": "(?i)autoId|autoUlid|uuid|ulid"
     }
    }
   ],
   "justify": "the id is generated in the function that writes the item"
  },
  {
   "id": "put_item",
   "kind": "any_of",
   "tier": "detail",
   "quote": "writes the new song into DynamoDB",
   "justify": "writing an item is a PutItem or UpdateItem operation",
   "checks": [
    {
     "kind": "attr",
     "select": "fns",
     "cond": {
      "path": [
       "RequestMappingTemplate"
      ],
      "op": "regex",
      "value": "(?i)PutItem|UpdateItem|ddb\\.put|ddb\\.update|\\.put\\("
     }
    },
    {
     "kind": "attr",
     "select": "fns",
     "cond": {
      "path": [
       "Code"
      ],
      "op": "regex",
      "value": "(?i)PutItem|UpdateItem|ddb\\.put|ddb\\.update|\\.put\\("
     }
    }
   ]
  },
  {
   "id": "put_uses_table_source",
   "kind": "any_of",
   "tier": "detail",
   "quote": "writes the new song into DynamoDB",
   "checks": [
    {
     "kind": "ref",
     "from": "fn_put",
     "to": "ds"
    },
    {
     "kind": "join",
     "from": "fn_put",
     "from_path": [
      "DataSourceName"
     ],
     "to": "ds",
     "to_path": [
      "Name"
     ]
    }
   ],
   "justify": "the function that writes the item, a PutItem or UpdateItem operation"
  },
  {
   "id": "put_is_second",
   "kind": "join",
   "from": "pipe",
   "from_path": [
    "PipelineConfig",
    "Functions",
    1,
    "ref"
   ],
   "to": "decl_put",
   "to_path": [
    "name"
   ],
   "tier": "detail",
   "quote": "the second step writes the new song into DynamoDB",
   "justify": "the second step is the function with a PutItem or UpdateItem operation"
  },
  {
   "id": "x_table_billing",
   "kind": "attr",
   "select": "table",
   "cond": {
    "path": [
     "ProvisionedThroughput"
    ],
    "op": "present"
   },
   "tier": "extra"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
