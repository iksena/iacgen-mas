package intent.tf.row_209

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "roles": {
   "types": [
    "aws_iam_role"
   ],
   "where": []
  },
  "emr": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "assume_role_policy"
     ],
     "op": "regex",
     "value": "(?i)elasticmapreduce\\.amazonaws\\.com"
    }
   ]
  },
  "ec2": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "assume_role_policy"
     ],
     "op": "regex",
     "value": "(?i)ec2\\.amazonaws\\.com"
    }
   ]
  },
  "asg": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "assume_role_policy"
     ],
     "op": "regex",
     "value": "(?i)application-autoscaling\\.amazonaws\\.com"
    }
   ]
  },
  "profile": {
   "types": [
    "aws_iam_instance_profile"
   ],
   "where": []
  },
  "outputs": {
   "types": [
    "__output__"
   ],
   "where": []
  },
  "attach": {
   "types": [
    "aws_iam_role_policy_attachment"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "roles_count",
   "kind": "exists",
   "tier": "core",
   "select": "roles",
   "min": 3,
   "quote": "an EMR service role, an EC2 instance profile role with attached policies for CloudWatch and SSM, an autoscaling role for EMR",
   "justify": "three roles: service, EC2 and autoscaling"
  },
  {
   "id": "emr_role",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
     "select": "emr"
    }
   ],
   "quote": "an EMR service role",
   "justify": "an EMR service role is assumed by elasticmapreduce.amazonaws.com"
  },
  {
   "id": "ec2_role",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
     "select": "ec2"
    }
   ],
   "quote": "an EC2 instance profile role"
  },
  {
   "id": "asg_role",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
     "select": "asg"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment",
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "(?i)autoscaling"
       }
      ]
     },
     "to": "roles"
    }
   ],
   "quote": "an autoscaling role for EMR"
  },
  {
   "id": "ec2_cloudwatch",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment",
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "(?i)cloudwatch"
       }
      ]
     },
     "to": "ec2"
    },
    {
     "kind": "attr",
     "select": "ec2",
     "cond": {
      "path": [
       "managed_policy_arns",
       "*"
      ],
      "op": "regex",
      "value": "(?i)cloudwatch"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)\"(cloudwatch|logs):"
       }
      ]
     },
     "to": "ec2"
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
        "op": "eq",
        "value": "aws_iam_role_policy"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "(?i)['\"](cloudwatch|logs):"
       }
      ]
     },
     "to": "ec2"
    }
   ],
   "quote": "attached policies for CloudWatch and SSM"
  },
  {
   "id": "ec2_ssm",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment",
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "(?i)ssm"
       }
      ]
     },
     "to": "ec2"
    },
    {
     "kind": "attr",
     "select": "ec2",
     "cond": {
      "path": [
       "managed_policy_arns",
       "*"
      ],
      "op": "regex",
      "value": "(?i)ssm"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)\"(ssm|ssmmessages|ec2messages):"
       }
      ]
     },
     "to": "ec2"
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
        "op": "eq",
        "value": "aws_iam_role_policy"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "(?i)['\"](ssm|ssmmessages|ec2messages):"
       }
      ]
     },
     "to": "ec2"
    }
   ],
   "quote": "attached policies for CloudWatch and SSM"
  },
  {
   "id": "instance_profile",
   "kind": "exists",
   "tier": "core",
   "select": "profile",
   "quote": "and an EC2 instance profile"
  },
  {
   "id": "profile_role",
   "kind": "ref",
   "tier": "detail",
   "from": "profile",
   "to": "ec2",
   "quote": "an EC2 instance profile"
  },
  {
   "id": "prefix_default",
   "kind": "any_of",
   "tier": "core",
   "quote": "all parameterized with a name prefix defaulting to \"imputation-example\"",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role",
       "aws_iam_instance_profile"
      ],
      "where": []
     },
     "quantifier": "all",
     "cond": {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "^imputation-example"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role",
       "aws_iam_instance_profile"
      ],
      "where": []
     },
     "quantifier": "all",
     "cond": {
      "path": [
       "name_prefix"
      ],
      "op": "regex",
      "value": "^imputation-example"
     }
    }
   ]
  },
  {
   "id": "prefix_var",
   "kind": "exists",
   "tier": "detail",
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
      "value": "imputation-example"
     }
    ]
   },
   "quote": "a name prefix defaulting to \"imputation-example\""
  },
  {
   "id": "tags_var",
   "kind": "exists",
   "tier": "detail",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "tags"
     }
    ]
   },
   "quote": "a tags variable for consistent tagging"
  },
  {
   "id": "outputs_count",
   "kind": "exists",
   "tier": "detail",
   "select": "outputs",
   "min": 9,
   "quote": "output the ARN, name, and unique ID for each role as well as the instance profile ID, ARN, and name",
   "justify": "ARN, name and unique ID for each of three roles gives at least 9 outputs"
  },
  {
   "id": "outputs_emr",
   "kind": "ref",
   "tier": "detail",
   "from": "outputs",
   "to": "emr",
   "quote": "output the ARN, name, and unique ID for each role",
   "justify": "the EMR service role is the one assumed by elasticmapreduce.amazonaws.com"
  },
  {
   "id": "outputs_ec2",
   "kind": "ref",
   "tier": "detail",
   "from": "outputs",
   "to": "ec2",
   "quote": "output the ARN, name, and unique ID for each role"
  },
  {
   "id": "outputs_asg",
   "kind": "ref",
   "tier": "detail",
   "from": "outputs",
   "to": "asg",
   "quote": "output the ARN, name, and unique ID for each role"
  },
  {
   "id": "outputs_profile",
   "kind": "ref",
   "tier": "detail",
   "from": "outputs",
   "to": "profile",
   "quote": "the instance profile ID, ARN, and name"
  },
  {
   "id": "x_emr_policy",
   "kind": "ref",
   "tier": "extra",
   "from": {
    "types": [
     "aws_iam_role_policy_attachment",
     "aws_iam_policy_attachment"
    ],
    "where": [
     {
      "path": [
       "policy_arn"
      ],
      "op": "regex",
      "value": "AmazonEMRServicePolicy"
     }
    ]
   },
   "to": "emr"
  },
  {
   "id": "x_ec2_policy",
   "kind": "ref",
   "tier": "extra",
   "from": {
    "types": [
     "aws_iam_role_policy_attachment",
     "aws_iam_policy_attachment"
    ],
    "where": [
     {
      "path": [
       "policy_arn"
      ],
      "op": "regex",
      "value": "AmazonElasticMapReduceforEC2Role"
     }
    ]
   },
   "to": "ec2"
  },
  {
   "id": "x_asg_policy",
   "kind": "ref",
   "tier": "extra",
   "from": {
    "types": [
     "aws_iam_role_policy_attachment",
     "aws_iam_policy_attachment"
    ],
    "where": [
     {
      "path": [
       "policy_arn"
      ],
      "op": "regex",
      "value": "AmazonElasticMapReduceforAutoScalingRole"
     }
    ]
   },
   "to": "asg"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
