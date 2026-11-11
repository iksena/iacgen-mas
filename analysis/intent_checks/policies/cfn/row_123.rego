package intent.cfn.row_123

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "comp": {
   "types": [
    "AWS::ImageBuilder::Component"
   ],
   "where": []
  },
  "recipe": {
   "types": [
    "AWS::ImageBuilder::ImageRecipe"
   ],
   "where": []
  },
  "infra": {
   "types": [
    "AWS::ImageBuilder::InfrastructureConfiguration"
   ],
   "where": []
  },
  "dist": {
   "types": [
    "AWS::ImageBuilder::DistributionConfiguration"
   ],
   "where": []
  },
  "pipe": {
   "types": [
    "AWS::ImageBuilder::ImagePipeline"
   ],
   "where": []
  },
  "life": {
   "types": [
    "AWS::ImageBuilder::LifecyclePolicy"
   ],
   "where": []
  },
  "wf": {
   "types": [
    "AWS::ImageBuilder::Workflow"
   ],
   "where": []
  },
  "role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "ip": {
   "types": [
    "AWS::IAM::InstanceProfile"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "component_chef",
   "kind": "any_of",
   "tier": "core",
   "quote": "a custom component that downloads and executes a Chef recipe from an S3 bucket",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::ImageBuilder::Component"
      ],
      "where": [
       {
        "path": [
         "Data"
        ],
        "op": "regex",
        "value": "(?i)chef"
       }
      ]
     },
     "cond": {
      "path": [
       "Data"
      ],
      "op": "regex",
      "value": "(?i)s3"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::ImageBuilder::Component"
      ],
      "where": [
       {
        "path": [
         "Uri"
        ],
        "op": "regex",
        "value": "^s3://"
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)chef"
     }
    }
   ]
  },
  {
   "id": "recipe_parent_ecs_al2",
   "kind": "attr",
   "tier": "core",
   "quote": "an image recipe using the latest Amazon Linux 2 ECS optimized AMI as the parent image",
   "select": "recipe",
   "cond": {
    "path": [
     "ParentImage"
    ],
    "op": "regex",
    "value": "(?i)ecs.{0,80}(amazon-linux-2([^0-9]|$)|amzn2)|(amazon-linux-2([^0-9]|$)|amzn2).{0,80}ecs"
   }
  },
  {
   "id": "recipe_parent_latest",
   "kind": "attr",
   "tier": "detail",
   "quote": "using the latest Amazon Linux 2 ECS optimized AMI",
   "select": "recipe",
   "cond": {
    "path": [
     "ParentImage"
    ],
    "op": "regex",
    "value": "(?i)/x\\.x\\.x|/recommended|latest"
   },
   "justify": "latest -> a version wildcard or the recommended SSM alias, not a pinned image"
  },
  {
   "id": "recipe_uses_component",
   "kind": "any_of",
   "tier": "detail",
   "quote": "an image recipe",
   "checks": [
    {
     "kind": "ref",
     "from": "recipe",
     "to": "comp"
    },
    {
     "kind": "attr",
     "select": "recipe",
     "cond": {
      "path": [
       "Components",
       "*",
       "ComponentArn"
      ],
      "op": "regex",
      "value": "(?i):component/[^/]*chef"
     }
    }
   ]
  },
  {
   "id": "recipe_root_volume",
   "kind": "attr",
   "tier": "detail",
   "quote": "with a root volume of appropriate size and type",
   "select": "recipe",
   "cond": {
    "path": [
     "BlockDeviceMappings",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "Ebs",
       "VolumeSize"
      ],
      "op": "present"
     },
     {
      "path": [
       "Ebs",
       "VolumeType"
      ],
      "op": "present"
     }
    ]
   }
  },
  {
   "id": "infra_config",
   "kind": "exists",
   "tier": "core",
   "quote": "an infrastructure configuration",
   "select": "infra"
  },
  {
   "id": "infra_terminate",
   "kind": "attr",
   "tier": "core",
   "quote": "an infrastructure configuration that terminates instances on failure",
   "select": "infra",
   "cond": {
    "path": [
     "TerminateInstanceOnFailure"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "iam_role",
   "kind": "exists",
   "tier": "core",
   "quote": "all required IAM roles and instance profiles must be created as part of the stack",
   "select": "role"
  },
  {
   "id": "instance_profile",
   "kind": "exists",
   "tier": "core",
   "quote": "all required IAM roles and instance profiles must be created as part of the stack",
   "select": "ip"
  },
  {
   "id": "infra_profile",
   "kind": "ref",
   "tier": "detail",
   "quote": "all required IAM roles and instance profiles must be created as part of the stack",
   "from": "infra",
   "to": "ip"
  },
  {
   "id": "profile_role",
   "kind": "ref",
   "tier": "detail",
   "quote": "all required IAM roles and instance profiles must be created as part of the stack",
   "from": "ip",
   "to": "role"
  },
  {
   "id": "dist_config",
   "kind": "exists",
   "tier": "core",
   "quote": "a distribution configuration",
   "select": "dist"
  },
  {
   "id": "dist_shares_account",
   "kind": "any_of",
   "tier": "core",
   "quote": "shares the resulting AMI with the current account",
   "checks": [
    {
     "kind": "attr",
     "select": "dist",
     "cond": {
      "path": [
       "Distributions",
       "*",
       "AmiDistributionConfiguration",
       "LaunchPermissionConfiguration",
       "UserIds",
       "*"
      ],
      "op": "regex",
      "value": "^(123456789012|\\$\\{AWS::AccountId\\})$"
     }
    },
    {
     "kind": "attr",
     "select": "dist",
     "cond": {
      "path": [
       "Distributions",
       "*",
       "AmiDistributionConfiguration",
       "TargetAccountIds",
       "*"
      ],
      "op": "regex",
      "value": "^(123456789012|\\$\\{AWS::AccountId\\})$"
     }
    }
   ],
   "justify": "current account resolves to pseudo-parameter 123456789012; sharing via launch permissions or target accounts"
  },
  {
   "id": "dist_region",
   "kind": "attr",
   "tier": "detail",
   "quote": "in a target region",
   "select": "dist",
   "cond": {
    "path": [
     "Distributions",
     "*",
     "Region"
    ],
    "op": "present"
   }
  },
  {
   "id": "pipeline",
   "kind": "exists",
   "tier": "core",
   "quote": "an image pipeline",
   "select": "pipe"
  },
  {
   "id": "pipeline_daily",
   "kind": "attr",
   "tier": "core",
   "quote": "an image pipeline scheduled to run daily",
   "select": "pipe",
   "cond": {
    "path": [
     "Schedule",
     "ScheduleExpression"
    ],
    "op": "regex",
    "value": "(?i)^cron\\(\\s*\\S+\\s+\\d+\\s+[*?]\\s+\\*\\s+[?*](\\s+\\*)?\\s*\\)$|^rate\\(\\s*1\\s+days?\\s*\\)$"
   },
   "justify": "daily = a fixed hour with day-of-month and month wildcards in the cron"
  },
  {
   "id": "pipeline_scanning",
   "kind": "attr",
   "tier": "core",
   "quote": "image scanning and tests enabled",
   "select": "pipe",
   "cond": {
    "path": [
     "ImageScanningConfiguration",
     "ImageScanningEnabled"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "pipeline_tests",
   "kind": "any_of",
   "tier": "core",
   "quote": "tests enabled",
   "checks": [
    {
     "kind": "attr",
     "select": "pipe",
     "cond": {
      "path": [
       "ImageTestsConfiguration",
       "ImageTestsEnabled"
      ],
      "op": "truthy"
     }
    },
    {
     "kind": "attr",
     "select": "pipe",
     "cond": {
      "path": [
       "ImageTestsConfiguration",
       "ImageTestsEnabled"
      ],
      "op": "absent"
     }
    }
   ],
   "justify": "Image Builder runs image tests unless they are turned off"
  },
  {
   "id": "pipeline_wiring",
   "kind": "all_of",
   "tier": "detail",
   "quote": "an image pipeline",
   "checks": [
    {
     "kind": "ref",
     "from": "pipe",
     "to": "recipe"
    },
    {
     "kind": "ref",
     "from": "pipe",
     "to": "infra"
    },
    {
     "kind": "ref",
     "from": "pipe",
     "to": "dist"
    }
   ],
   "justify": "the pipeline combines the recipe, infrastructure and distribution configurations"
  },
  {
   "id": "lifecycle",
   "kind": "exists",
   "tier": "core",
   "quote": "a lifecycle policy",
   "select": "life"
  },
  {
   "id": "lifecycle_deprecate",
   "kind": "attr",
   "tier": "core",
   "quote": "a lifecycle policy that deprecates AMIs",
   "select": "life",
   "cond": {
    "path": [
     "PolicyDetails",
     "*",
     "Action",
     "Type"
    ],
    "op": "eq",
    "value": "DEPRECATE"
   }
  },
  {
   "id": "lifecycle_role",
   "kind": "ref",
   "tier": "detail",
   "quote": "all required IAM roles and instance profiles must be created as part of the stack",
   "from": "life",
   "to": "role"
  },
  {
   "id": "lifecycle_age",
   "kind": "attr",
   "tier": "core",
   "quote": "deprecates AMIs based on age",
   "select": "life",
   "cond": {
    "path": [
     "PolicyDetails",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "Action",
       "Type"
      ],
      "op": "eq",
      "value": "DEPRECATE"
     },
     {
      "path": [
       "Filter",
       "Type"
      ],
      "op": "eq",
      "value": "AGE"
     }
    ]
   }
  },
  {
   "id": "lifecycle_tag",
   "kind": "attr",
   "tier": "core",
   "quote": "tag selection",
   "select": "life",
   "cond": {
    "path": [
     "ResourceSelection",
     "TagMap"
    ],
    "op": "present"
   }
  },
  {
   "id": "workflow",
   "kind": "exists",
   "tier": "core",
   "quote": "a custom build workflow",
   "select": "wf"
  },
  {
   "id": "workflow_build",
   "kind": "attr",
   "tier": "detail",
   "quote": "a custom build workflow",
   "select": "wf",
   "cond": {
    "path": [
     "Type"
    ],
    "op": "eq",
    "value": "BUILD"
   }
  },
  {
   "id": "workflow_ssm_agent",
   "kind": "any_of",
   "tier": "core",
   "quote": "updates the SSM agent",
   "checks": [
    {
     "kind": "attr",
     "select": "wf",
     "cond": {
      "path": [
       "Data"
      ],
      "op": "regex",
      "value": "(?i)update.{0,3}ssm.{0,3}agent|(yum|dnf|apt)[^\\n]{0,40}(update|install)[^\\n]{0,80}ssm-agent"
     }
    },
    {
     "kind": "attr",
     "select": "comp",
     "cond": {
      "path": [
       "Data"
      ],
      "op": "regex",
      "value": "(?i)update.{0,3}ssm.{0,3}agent|(yum|dnf|apt)[^\\n]{0,40}(update|install)[^\\n]{0,80}ssm-agent"
     }
    }
   ]
  },
  {
   "id": "workflow_metadata",
   "kind": "any_of",
   "tier": "core",
   "quote": "collects metadata",
   "checks": [
    {
     "kind": "attr",
     "select": "wf",
     "cond": {
      "path": [
       "Data"
      ],
      "op": "regex",
      "value": "(?is)collect\\w*.{0,40}metadata|metadata.{0,40}collect"
     }
    },
    {
     "kind": "attr",
     "select": "comp",
     "cond": {
      "path": [
       "Data"
      ],
      "op": "regex",
      "value": "(?is)collect\\w*.{0,40}metadata|metadata.{0,40}collect"
     }
    }
   ]
  },
  {
   "id": "workflow_create_ami",
   "kind": "attr",
   "tier": "detail",
   "quote": "collects metadata before creating the AMI",
   "select": "wf",
   "cond": {
    "path": [
     "Data"
    ],
    "op": "regex",
    "value": "(?is)collect\\w*.{0,40}metadata.*CreateImage"
   }
  },
  {
   "id": "x_component_linux",
   "kind": "attr",
   "tier": "extra",
   "select": "comp",
   "cond": {
    "path": [
     "Platform"
    ],
    "op": "eq",
    "value": "Linux"
   }
  },
  {
   "id": "x_lifecycle_enabled",
   "kind": "attr",
   "tier": "extra",
   "select": "life",
   "cond": {
    "path": [
     "Status"
    ],
    "op": "eq",
    "value": "ENABLED"
   }
  },
  {
   "id": "x_lifecycle_type",
   "kind": "attr",
   "tier": "extra",
   "select": "life",
   "cond": {
    "path": [
     "ResourceType"
    ],
    "op": "eq",
    "value": "AMI_IMAGE"
   }
  },
  {
   "id": "x_pipeline_enabled",
   "kind": "attr",
   "tier": "extra",
   "select": "pipe",
   "cond": {
    "path": [
     "Status"
    ],
    "op": "eq",
    "value": "ENABLED"
   }
  },
  {
   "id": "x_ec2_trust",
   "kind": "attr",
   "tier": "extra",
   "select": "role",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument",
     "Statement",
     "*",
     "Principal",
     "Service",
     "*"
    ],
    "op": "eq",
    "value": "ec2.amazonaws.com"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
