package intent.cfn.row_127

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "report_table",
   "kind": "exists",
   "tier": "core",
   "quote": "a DynamoDB table for classification reports",
   "select": {
    "types": [
     "AWS::DynamoDB::Table"
    ],
    "where": []
   }
  },
  {
   "id": "function_writes_table",
   "kind": "any_of",
   "tier": "detail",
   "quote": "storing the results in a DynamoDB table",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Lambda::Function"
      ],
      "where": []
     },
     "to": {
      "types": [
       "AWS::DynamoDB::Table"
      ],
      "where": []
     }
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "AWS::Lambda::Function"
      ],
      "where": []
     },
     "from_path": [
      "Environment",
      "Variables",
      "*"
     ],
     "to": {
      "types": [
       "AWS::DynamoDB::Table"
      ],
      "where": []
     },
     "to_path": [
      "TableName"
     ]
    }
   ]
  },
  {
   "id": "table_pitr",
   "kind": "attr",
   "tier": "core",
   "quote": "with point-in-time recovery",
   "select": {
    "types": [
     "AWS::DynamoDB::Table"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "PointInTimeRecoverySpecification",
     "PointInTimeRecoveryEnabled"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "table_encryption",
   "kind": "any_of",
   "tier": "core",
   "quote": "and encryption",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::DynamoDB::Table"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "SSESpecification",
       "SSEEnabled"
      ],
      "op": "truthy"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::DynamoDB::Table"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "SSESpecification",
       "KMSMasterKeyId"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "scanner_function",
   "kind": "exists",
   "tier": "core",
   "quote": "a Lambda function",
   "select": {
    "types": [
     "AWS::Lambda::Function"
    ],
    "where": []
   }
  },
  {
   "id": "lambda_outside_vpc_by_default",
   "kind": "attr",
   "tier": "core",
   "quote": "By default the scanner Lambda should run outside any VPC",
   "select": {
    "types": [
     "AWS::Lambda::Function"
    ],
    "where": [
     {
      "path": [
       "MemorySize"
      ],
      "op": "eq",
      "value": 512
     }
    ]
   },
   "cond": {
    "path": [
     "VpcConfig"
    ],
    "op": "absent"
   },
   "quantifier": "all",
   "justify": "512 MB picks out the scanner Lambda the prompt describes"
  },
  {
   "id": "scanner_role",
   "kind": "exists",
   "tier": "core",
   "quote": "an IAM role granting the Lambda permissions",
   "select": {
    "types": [
     "AWS::IAM::Role"
    ],
    "where": []
   }
  },
  {
   "id": "function_uses_role",
   "kind": "ref",
   "tier": "detail",
   "quote": "an IAM role granting the Lambda permissions",
   "from": {
    "types": [
     "AWS::Lambda::Function"
    ],
    "where": []
   },
   "to": {
    "types": [
     "AWS::IAM::Role"
    ],
    "where": []
   }
  },
  {
   "id": "perm_read_access_point",
   "tier": "core",
   "quote": "to read from the access point",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Lambda::Function"
      ],
      "where": []
     },
     "to": {
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
     }
    },
    {
     "kind": "ref",
     "bidirectional": true,
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
     "to": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Lambda::Function"
      ],
      "where": []
     },
     "to": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": [
       {
        "path": [
         "ManagedPolicyArns",
         "*"
        ],
        "op": "regex",
        "value": "(?i)AmazonS3(ReadOnly|Full)Access"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "perm_comprehend",
   "tier": "core",
   "quote": "call Comprehend",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Lambda::Function"
      ],
      "where": []
     },
     "to": {
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
          "value": "comprehend:DetectPiiEntities"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "ref",
     "bidirectional": true,
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
          "value": "comprehend:DetectPiiEntities"
         }
        ]
       }
      ]
     },
     "to": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Lambda::Function"
      ],
      "where": []
     },
     "to": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": [
       {
        "path": [
         "ManagedPolicyArns",
         "*"
        ],
        "op": "regex",
        "value": "(?i)Comprehend(ReadOnly|Full)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "perm_dynamodb_write",
   "tier": "core",
   "quote": "write to DynamoDB",
   "justify": "writing to DynamoDB can use PutItem, BatchWriteItem or UpdateItem",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Lambda::Function"
      ],
      "where": []
     },
     "to": {
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
     }
    },
    {
     "kind": "ref",
     "bidirectional": true,
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
     "to": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Lambda::Function"
      ],
      "where": []
     },
     "to": {
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
          "value": "dynamodb:BatchWriteItem"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "ref",
     "bidirectional": true,
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
          "value": "dynamodb:BatchWriteItem"
         }
        ]
       }
      ]
     },
     "to": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Lambda::Function"
      ],
      "where": []
     },
     "to": {
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
          "value": "dynamodb:UpdateItem"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "ref",
     "bidirectional": true,
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
          "value": "dynamodb:UpdateItem"
         }
        ]
       }
      ]
     },
     "to": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Lambda::Function"
      ],
      "where": []
     },
     "to": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": [
       {
        "path": [
         "ManagedPolicyArns",
         "*"
        ],
        "op": "regex",
        "value": "(?i)AmazonDynamoDBFullAccess"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "perm_sns_publish",
   "tier": "core",
   "quote": "publish to SNS",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Lambda::Function"
      ],
      "where": []
     },
     "to": {
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
          "value": "sns:Publish"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "ref",
     "bidirectional": true,
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
          "value": "sns:Publish"
         }
        ]
       }
      ]
     },
     "to": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Lambda::Function"
      ],
      "where": []
     },
     "to": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": [
       {
        "path": [
         "ManagedPolicyArns",
         "*"
        ],
        "op": "regex",
        "value": "(?i)AmazonSNSFullAccess"
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
         "AWS::IAM::Policy",
         "AWS::IAM::ManagedPolicy"
        ]
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
          "value": "sns:Publish"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Lambda::Function"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Code",
         "ZipFile"
        ],
        "op": "regex",
        "value": "(?i)(sns[^\\n]{0,40}publish|\\.publish\\()"
       },
       {
        "path": [
         "Environment",
         "Variables"
        ],
        "op": "regex",
        "value": "(?i)(sns|topic)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "perm_logs",
   "tier": "detail",
   "quote": "and create logs",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Lambda::Function"
      ],
      "where": []
     },
     "to": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": [
       {
        "path": [
         "ManagedPolicyArns",
         "*"
        ],
        "op": "regex",
        "value": "(?i)(AWSLambdaBasicExecutionRole|AWSLambdaVPCAccessExecutionRole)"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Lambda::Function"
      ],
      "where": []
     },
     "to": {
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
          "value": "logs:PutLogEvents"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "ref",
     "bidirectional": true,
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
          "value": "logs:PutLogEvents"
         }
        ]
       }
      ]
     },
     "to": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": []
     }
    }
   ]
  },
  {
   "id": "memory_512",
   "kind": "attr",
   "tier": "core",
   "quote": "configurable memory (defaulting to 512 MB)",
   "select": {
    "types": [
     "AWS::Lambda::Function"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "MemorySize"
    ],
    "op": "eq",
    "value": 512
   }
  },
  {
   "id": "timeout_600",
   "kind": "attr",
   "tier": "core",
   "quote": "timeout (defaulting to 600 seconds)",
   "select": {
    "types": [
     "AWS::Lambda::Function"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "Timeout"
    ],
    "op": "eq",
    "value": 600
   }
  },
  {
   "id": "memory_param",
   "kind": "exists",
   "tier": "detail",
   "quote": "configurable memory (defaulting to 512 MB)",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": 512
     }
    ]
   }
  },
  {
   "id": "timeout_param",
   "kind": "exists",
   "tier": "detail",
   "quote": "timeout (defaulting to 600 seconds)",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": 600
     }
    ]
   }
  },
  {
   "id": "language_default_en",
   "kind": "any_of",
   "tier": "core",
   "quote": "a default Comprehend language code (defaulting to English)",
   "justify": "English is language code en",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": [
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": "en"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Lambda::Function"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Environment",
       "Variables",
       "*"
      ],
      "op": "eq",
      "value": "en"
     }
    }
   ]
  },
  {
   "id": "max_files_500",
   "kind": "any_of",
   "tier": "core",
   "quote": "a default maximum number of files to scan per invocation (defaulting to 500, as a cost and runtime control)",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": [
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": 500
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Lambda::Function"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Environment",
       "Variables",
       "*"
      ],
      "op": "eq",
      "value": 500
     }
    }
   ]
  },
  {
   "id": "create_endpoints_flag",
   "kind": "exists",
   "tier": "core",
   "quote": "controlled by a create-endpoints flag that defaults to true",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)endpoint"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "true"
     }
    ]
   }
  },
  {
   "id": "endpoint_s3",
   "kind": "exists",
   "tier": "core",
   "quote": "the VPC endpoints needed for the Lambda to reach S3, DynamoDB, Comprehend, and SNS",
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
      "value": "AWS::EC2::VPCEndpoint"
     },
     {
      "path": [
       "properties",
       "ServiceName"
      ],
      "op": "regex",
      "value": "(?i)[.]s3"
     }
    ]
   }
  },
  {
   "id": "endpoint_dynamodb",
   "kind": "exists",
   "tier": "core",
   "quote": "the VPC endpoints needed for the Lambda to reach S3, DynamoDB, Comprehend, and SNS",
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
      "value": "AWS::EC2::VPCEndpoint"
     },
     {
      "path": [
       "properties",
       "ServiceName"
      ],
      "op": "regex",
      "value": "(?i)dynamodb"
     }
    ]
   }
  },
  {
   "id": "endpoint_comprehend",
   "kind": "exists",
   "tier": "core",
   "quote": "the VPC endpoints needed for the Lambda to reach S3, DynamoDB, Comprehend, and SNS",
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
      "value": "AWS::EC2::VPCEndpoint"
     },
     {
      "path": [
       "properties",
       "ServiceName"
      ],
      "op": "regex",
      "value": "(?i)comprehend"
     }
    ]
   }
  },
  {
   "id": "endpoint_sns",
   "kind": "exists",
   "tier": "core",
   "quote": "the VPC endpoints needed for the Lambda to reach S3, DynamoDB, Comprehend, and SNS",
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
      "value": "AWS::EC2::VPCEndpoint"
     },
     {
      "path": [
       "properties",
       "ServiceName"
      ],
      "op": "regex",
      "value": "(?i)[.]sns"
     }
    ]
   }
  },
  {
   "id": "endpoints_gated",
   "kind": "attr",
   "tier": "detail",
   "quote": "the template should optionally create the VPC endpoints",
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
      "value": "AWS::EC2::VPCEndpoint"
     }
    ]
   },
   "cond": {
    "path": [
     "gated"
    ],
    "op": "truthy"
   },
   "quantifier": "all"
  },
  {
   "id": "s3_gateway_endpoint",
   "kind": "exists",
   "tier": "detail",
   "quote": "a second S3 Gateway endpoint bound to the same route tables",
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
      "value": "AWS::EC2::VPCEndpoint"
     },
     {
      "path": [
       "properties",
       "ServiceName"
      ],
      "op": "regex",
      "value": "(?i)[.]s3$"
     },
     {
      "path": [
       "properties",
       "VpcEndpointType"
      ],
      "op": "none_eq",
      "value": "Interface"
     }
    ]
   }
  },
  {
   "id": "param_vpc_id_empty",
   "kind": "any_of",
   "tier": "detail",
   "quote": "the VPC ID",
   "justify": "the prompt says these all default to empty",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)vpc.?id"
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": ""
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)vpc.?id"
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "regex",
      "value": "^\\[(\"\")?\\]$"
     }
    }
   ]
  },
  {
   "id": "param_subnet_ids_empty",
   "kind": "any_of",
   "tier": "detail",
   "quote": "subnet IDs",
   "justify": "the prompt says these all default to empty",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)subnet"
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": ""
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)subnet"
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "regex",
      "value": "^\\[(\"\")?\\]$"
     }
    }
   ]
  },
  {
   "id": "param_security_group_id_empty",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a security group ID",
   "justify": "the prompt says these all default to empty",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)security.?group"
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": ""
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)security.?group"
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "regex",
      "value": "^\\[(\"\")?\\]$"
     }
    }
   ]
  },
  {
   "id": "param_route_table_ids_empty",
   "kind": "any_of",
   "tier": "detail",
   "quote": "route table IDs",
   "justify": "the prompt says these all default to empty",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)route.?table"
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": ""
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)route.?table"
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "regex",
      "value": "^\\[(\"\")?\\]$"
     }
    }
   ]
  },
  {
   "id": "sns_notifications",
   "kind": "any_of",
   "tier": "detail",
   "quote": "with optional SNS notifications",
   "checks": [
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
        "op": "eq",
        "value": "AWS::SNS::Topic"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)(sns|topic|notif)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "code_handles",
   "kind": "all_of",
   "tier": "detail",
   "quote": "The Lambda code should handle chunking of large files, sampling, and pagination through the access point's objects",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Lambda::Function"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Code",
       "ZipFile"
      ],
      "op": "regex",
      "value": "(?i)chunk"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Lambda::Function"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Code",
       "ZipFile"
      ],
      "op": "regex",
      "value": "(?i)sampl"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Lambda::Function"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Code",
       "ZipFile"
      ],
      "op": "regex",
      "value": "(?i)(paginat|continuationtoken)"
     }
    }
   ]
  },
  {
   "id": "out_function_arn",
   "tier": "detail",
   "quote": "The stack should output the scanner function ARN",
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
      "value": "Arn"
     }
    ]
   },
   "to": {
    "types": [
     "AWS::Lambda::Function"
    ],
    "where": []
   }
  },
  {
   "id": "out_table_name",
   "tier": "detail",
   "quote": "the report table name",
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
   "to": {
    "types": [
     "AWS::DynamoDB::Table"
    ],
    "where": []
   }
  },
  {
   "id": "out_cli_example",
   "kind": "exists",
   "tier": "detail",
   "quote": "an example CLI invocation command",
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
      "value": "(?i)aws lambda invoke"
     }
    ]
   }
  },
  {
   "id": "x_billing",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::DynamoDB::Table"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "BillingMode"
    ],
    "op": "eq",
    "value": "PAY_PER_REQUEST"
   }
  },
  {
   "id": "x_runtime",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::Lambda::Function"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "Runtime"
    ],
    "op": "regex",
    "value": "^python3"
   }
  },
  {
   "id": "x_role_vpc_access",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::IAM::Role"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "ManagedPolicyArns",
     "*"
    ],
    "op": "contains",
    "value": "AWSLambdaVPCAccessExecutionRole"
   }
  },
  {
   "id": "x_endpoint_private_dns",
   "kind": "attr",
   "tier": "extra",
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
      "value": "AWS::EC2::VPCEndpoint"
     },
     {
      "path": [
       "properties",
       "VpcEndpointType"
      ],
      "op": "eq",
      "value": "Interface"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "PrivateDnsEnabled"
    ],
    "op": "truthy"
   },
   "quantifier": "all"
  },
  {
   "id": "extra_type_aws_logs_loggroup",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::Logs::LogGroup"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_ec2_securitygroup",
   "kind": "exists",
   "tier": "extra",
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
      "value": "AWS::EC2::SecurityGroup"
     }
    ]
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
