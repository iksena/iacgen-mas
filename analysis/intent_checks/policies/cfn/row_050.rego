package intent.cfn.row_050

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "stk": {
   "types": [
    "AWS::CloudFormation::Stack"
   ],
   "where": []
  },
  "out": {
   "types": [
    "__output__"
   ],
   "where": []
  },
  "param": {
   "types": [
    "__parameter__"
   ],
   "where": []
  },
  "enduser": {
   "types": [
    "AWS::CloudFormation::Stack"
   ],
   "where": [
    {
     "path": [
      "TemplateURL"
     ],
     "op": "regex",
     "value": "(?i)[^:/]/[^/]*(enduser|end-user|end_user)[^/]*(/[^/]+)?$"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "nested_stacks",
   "kind": "exists",
   "tier": "core",
   "quote": "using nested stacks",
   "justify": "'nested stacks' is plural; the per-product checks below require each stack",
   "select": "stk",
   "min": 2
  },
  {
   "id": "enduser_stack",
   "kind": "exists",
   "tier": "core",
   "quote": "an end-user IAM stack",
   "select": "enduser",
   "justify": "the nested template is identified by its URL's last two path segments, excluding the host"
  },
  {
   "id": "ec2vpc_stack",
   "kind": "exists",
   "tier": "core",
   "quote": "launch constraint roles for EC2-VPC",
   "select": {
    "types": [
     "AWS::CloudFormation::Stack"
    ],
    "where": [
     {
      "path": [
       "TemplateURL"
      ],
      "op": "regex",
      "value": "(?i)[^:/]/[^/]*(ec2|vpc)[^/]*(/[^/]+)?$"
     }
    ]
   },
   "justify": "the nested template for this product is identified by its URL's last two path segments, excluding the host"
  },
  {
   "id": "emr_stack",
   "kind": "exists",
   "tier": "core",
   "quote": "EMR",
   "select": {
    "types": [
     "AWS::CloudFormation::Stack"
    ],
    "where": [
     {
      "path": [
       "TemplateURL"
      ],
      "op": "regex",
      "value": "(?i)[^:/]/[^/]*(emr)[^/]*(/[^/]+)?$"
     }
    ]
   },
   "justify": "the nested template for this product is identified by its URL's last two path segments, excluding the host"
  },
  {
   "id": "rds_stack",
   "kind": "exists",
   "tier": "core",
   "quote": "RDS",
   "select": {
    "types": [
     "AWS::CloudFormation::Stack"
    ],
    "where": [
     {
      "path": [
       "TemplateURL"
      ],
      "op": "regex",
      "value": "(?i)[^:/]/[^/]*(rds)[^/]*(/[^/]+)?$"
     }
    ]
   },
   "justify": "the nested template for this product is identified by its URL's last two path segments, excluding the host"
  },
  {
   "id": "s3_stack",
   "kind": "exists",
   "tier": "core",
   "quote": "and S3 product templates",
   "select": {
    "types": [
     "AWS::CloudFormation::Stack"
    ],
    "where": [
     {
      "path": [
       "TemplateURL"
      ],
      "op": "regex",
      "value": "(?i)[^:/]/[^/]*(s3)[^/]*(/[^/]+)?$"
     }
    ]
   },
   "justify": "the nested template for this product is identified by its URL's last two path segments, excluding the host"
  },
  {
   "id": "repo_param",
   "kind": "attr",
   "tier": "core",
   "quote": "a repository root URL parameter, with a default value pointing to the standard AWS Service Catalog reference architectures S3 location",
   "justify": "the default points at the standard reference architectures S3 location",
   "select": "param",
   "cond": {
    "path": [
     "default"
    ],
    "op": "regex",
    "value": "(?i)aws-service-catalog-reference-architectures"
   }
  },
  {
   "id": "stacks_use_repo",
   "kind": "attr",
   "tier": "detail",
   "quote": "pull the IAM templates from a repository root URL parameter",
   "justify": "URL resolves from the parameter default",
   "select": "stk",
   "quantifier": "all",
   "cond": {
    "path": [
     "TemplateURL"
    ],
    "op": "regex",
    "value": "(?i)aws-service-catalog-reference-architectures"
   }
  },
  {
   "id": "output_group",
   "kind": "any_of",
   "tier": "detail",
   "quote": "expose the generated group and launch role references as outputs",
   "justify": "a group output either reads the nested stack's output, or references the IAM group directly",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "__output__"
      ],
      "where": [
       {
        "path": [
         "value",
         "attr"
        ],
        "op": "regex",
        "value": "(?i)^Outputs\\..*group"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "out",
     "to": {
      "types": [
       "AWS::IAM::Group"
      ],
      "where": []
     }
    }
   ]
  },
  {
   "id": "output_roles",
   "kind": "any_of",
   "tier": "detail",
   "quote": "expose the generated group and launch role references as outputs",
   "justify": "four launch roles are named: EC2-VPC, EMR, RDS and S3",
   "checks": [
    {
     "kind": "exists",
     "min": 4,
     "select": {
      "types": [
       "__output__"
      ],
      "where": [
       {
        "path": [
         "value",
         "attr"
        ],
        "op": "regex",
        "value": "(?i)^Outputs\\..*role"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "min": 4,
     "select": {
      "types": [
       "__output__"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)role"
       },
       {
        "path": [
         "value",
         "ref"
        ],
        "op": "present"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "x_timeout",
   "kind": "attr",
   "tier": "extra",
   "select": "stk",
   "quantifier": "all",
   "cond": {
    "path": [
     "TimeoutInMinutes"
    ],
    "op": "present"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
