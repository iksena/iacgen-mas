package intent.tf.row_035

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "slr",
   "tier": "core",
   "quote": "an IAM service-linked role for Amazon OpenSearch/Elasticsearch service (\"es.amazonaws.com\")",
   "kind": "exists",
   "select": {
    "types": [
     "aws_iam_service_linked_role"
    ],
    "where": [
     {
      "path": [
       "aws_service_name"
      ],
      "op": "eq",
      "value": "es.amazonaws.com"
     }
    ]
   }
  },
  {
   "id": "log_policy",
   "tier": "core",
   "quote": "a CloudWatch log resource policy named \"elasticsearch-log-publishing-policy\"",
   "kind": "exists",
   "select": {
    "types": [
     "aws_cloudwatch_log_resource_policy"
    ],
    "where": [
     {
      "path": [
       "policy_name"
      ],
      "op": "eq",
      "value": "elasticsearch-log-publishing-policy"
     }
    ]
   }
  },
  {
   "id": "principal",
   "tier": "core",
   "quote": "grant the Elasticsearch service principal",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_cloudwatch_log_resource_policy"
      ],
      "where": [
       {
        "path": [
         "policy_name"
        ],
        "op": "eq",
        "value": "elasticsearch-log-publishing-policy"
       }
      ]
     },
     "cond": {
      "path": [
       "policy_document"
      ],
      "op": "regex",
      "value": "es\\.amazonaws\\.com"
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
        "op": "eq",
        "value": "aws_cloudwatch_log_resource_policy"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy_document"
      ],
      "op": "regex",
      "value": "es\\.amazonaws\\.com"
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
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "es\\.amazonaws\\.com"
     }
    }
   ]
  },
  {
   "id": "act_create_stream",
   "tier": "core",
   "quote": "\"logs:CreateLogStream\"",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_cloudwatch_log_resource_policy"
      ],
      "where": [
       {
        "path": [
         "policy_name"
        ],
        "op": "eq",
        "value": "elasticsearch-log-publishing-policy"
       }
      ]
     },
     "cond": {
      "path": [
       "policy_document"
      ],
      "op": "regex",
      "value": "(?i)(logs:CreateLogStream([^A-Za-z]|$)|logs:\\*)"
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
        "op": "eq",
        "value": "aws_cloudwatch_log_resource_policy"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy_document"
      ],
      "op": "regex",
      "value": "(?i)(logs:CreateLogStream([^A-Za-z]|$)|logs:\\*)"
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
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)(logs:CreateLogStream([^A-Za-z]|$)|logs:\\*)"
     }
    }
   ]
  },
  {
   "id": "act_put_events",
   "tier": "core",
   "quote": "\"logs:PutLogEvents\"",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_cloudwatch_log_resource_policy"
      ],
      "where": [
       {
        "path": [
         "policy_name"
        ],
        "op": "eq",
        "value": "elasticsearch-log-publishing-policy"
       }
      ]
     },
     "cond": {
      "path": [
       "policy_document"
      ],
      "op": "regex",
      "value": "(?i)(logs:PutLogEvents([^A-Za-z]|$)|logs:\\*)"
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
        "op": "eq",
        "value": "aws_cloudwatch_log_resource_policy"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy_document"
      ],
      "op": "regex",
      "value": "(?i)(logs:PutLogEvents([^A-Za-z]|$)|logs:\\*)"
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
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)(logs:PutLogEvents([^A-Za-z]|$)|logs:\\*)"
     }
    }
   ]
  },
  {
   "id": "act_put_batch",
   "tier": "core",
   "quote": "\"logs:PutLogEventsBatch\"",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_cloudwatch_log_resource_policy"
      ],
      "where": [
       {
        "path": [
         "policy_name"
        ],
        "op": "eq",
        "value": "elasticsearch-log-publishing-policy"
       }
      ]
     },
     "cond": {
      "path": [
       "policy_document"
      ],
      "op": "regex",
      "value": "(?i)(logs:PutLogEventsBatch([^A-Za-z]|$)|logs:\\*)"
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
        "op": "eq",
        "value": "aws_cloudwatch_log_resource_policy"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy_document"
      ],
      "op": "regex",
      "value": "(?i)(logs:PutLogEventsBatch([^A-Za-z]|$)|logs:\\*)"
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
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)(logs:PutLogEventsBatch([^A-Za-z]|$)|logs:\\*)"
     }
    }
   ]
  },
  {
   "id": "resources_logs",
   "tier": "detail",
   "quote": "across CloudWatch log resources",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_cloudwatch_log_resource_policy"
      ],
      "where": [
       {
        "path": [
         "policy_name"
        ],
        "op": "eq",
        "value": "elasticsearch-log-publishing-policy"
       }
      ]
     },
     "cond": {
      "path": [
       "policy_document"
      ],
      "op": "regex",
      "value": "(?i)(resources?[\"']?\\s*[:=]\\s*\\[?\\s*[\"']?[^\"'\\]]*\\*|resources:\\[[^\\]]*\\*)"
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
        "op": "eq",
        "value": "aws_cloudwatch_log_resource_policy"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy_document"
      ],
      "op": "regex",
      "value": "(?i)(resources?[\"']?\\s*[:=]\\s*\\[?\\s*[\"']?[^\"'\\]]*\\*|resources:\\[[^\\]]*\\*)"
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
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)(resources?[\"']?\\s*[:=]\\s*\\[?\\s*[\"']?[^\"'\\]]*\\*|resources:\\[[^\\]]*\\*)"
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
