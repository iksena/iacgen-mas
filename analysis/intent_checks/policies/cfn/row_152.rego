package intent.cfn.row_152

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
  "wf": {
   "types": [
    "AWS::ImageBuilder::Workflow"
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
  "role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "role_ec2": {
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
     "value": "ec2.amazonaws.com"
    }
   ]
  },
  "role_ib": {
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
     "value": "imagebuilder.amazonaws.com"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "component",
   "tier": "core",
   "kind": "exists",
   "select": "comp",
   "quote": "a custom component named 'sample-component'"
  },
  {
   "id": "component_name",
   "tier": "core",
   "kind": "attr",
   "select": "comp",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "eq",
    "value": "sample-component"
   },
   "quote": "a custom component named 'sample-component'"
  },
  {
   "id": "component_version",
   "tier": "detail",
   "kind": "attr",
   "select": "comp",
   "cond": {
    "path": [
     "Version"
    ],
    "op": "eq",
    "value": "1.0.0"
   },
   "quote": "(version 1.0.0)"
  },
  {
   "id": "component_linux",
   "tier": "core",
   "kind": "attr",
   "select": "comp",
   "cond": {
    "path": [
     "Platform"
    ],
    "op": "eq",
    "value": "Linux"
   },
   "quote": "installs and runs Chef Client on Linux"
  },
  {
   "id": "component_webdownload",
   "tier": "core",
   "kind": "attr",
   "select": "comp",
   "cond": {
    "path": [
     "Data"
    ],
    "op": "regex",
    "value": "(?i)webdownload"
   },
   "quote": "using a WebDownload action"
  },
  {
   "id": "component_chef",
   "tier": "detail",
   "kind": "attr",
   "select": "comp",
   "cond": {
    "path": [
     "Data"
    ],
    "op": "regex",
    "value": "(?i)chef"
   },
   "quote": "installs and runs Chef Client on Linux"
  },
  {
   "id": "workflow",
   "tier": "core",
   "kind": "exists",
   "select": "wf",
   "quote": "a custom build workflow named 'sample-workflow'"
  },
  {
   "id": "workflow_name",
   "tier": "core",
   "kind": "attr",
   "select": "wf",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "eq",
    "value": "sample-workflow"
   },
   "quote": "a custom build workflow named 'sample-workflow'"
  },
  {
   "id": "workflow_build",
   "tier": "detail",
   "kind": "attr",
   "select": "wf",
   "cond": {
    "path": [
     "Type"
    ],
    "op": "eq",
    "value": "BUILD"
   },
   "quote": "a custom build workflow"
  },
  {
   "id": "workflow_ssm",
   "tier": "detail",
   "kind": "attr",
   "select": "wf",
   "cond": {
    "path": [
     "Data"
    ],
    "op": "regex",
    "value": "(?i)update[^\\n]{0,40}ssm|ssm[^\\n]{0,40}update"
   },
   "quote": "updates the SSM agent"
  },
  {
   "id": "workflow_ami",
   "tier": "detail",
   "kind": "attr",
   "select": "wf",
   "cond": {
    "path": [
     "Data"
    ],
    "op": "regex",
    "value": "(?i)createimage"
   },
   "quote": "builds an AMI",
   "justify": "the Image Builder CreateImage step builds the AMI"
  },
  {
   "id": "recipe",
   "tier": "core",
   "kind": "exists",
   "select": "recipe",
   "quote": "Create an image recipe named 'sample-recipe'"
  },
  {
   "id": "recipe_name",
   "tier": "core",
   "kind": "attr",
   "select": "recipe",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "eq",
    "value": "sample-recipe"
   },
   "quote": "Create an image recipe named 'sample-recipe'"
  },
  {
   "id": "recipe_custom_comp",
   "tier": "core",
   "kind": "any_of",
   "quote": "combines the custom component",
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
      "value": "sample-component"
     }
    }
   ]
  },
  {
   "id": "recipe_chrony",
   "tier": "core",
   "kind": "attr",
   "select": "recipe",
   "cond": {
    "path": [
     "Components",
     "*",
     "ComponentArn"
    ],
    "op": "regex",
    "value": "chrony-time-configuration-test"
   },
   "quote": "the AWS-managed 'chrony-time-configuration-test' component"
  },
  {
   "id": "recipe_parent",
   "tier": "core",
   "kind": "attr",
   "select": "recipe",
   "cond": {
    "path": [
     "ParentImage"
    ],
    "op": "regex",
    "value": "amazon-linux-2-ecs-optimized-x86"
   },
   "quote": "utilizing the AWS-managed 'amazon-linux-2-ecs-optimized-x86' image as the parent image"
  },
  {
   "id": "root_size",
   "tier": "core",
   "kind": "attr",
   "select": "recipe",
   "cond": {
    "path": [
     "BlockDeviceMappings",
     "*",
     "Ebs",
     "VolumeSize"
    ],
    "op": "eq",
    "value": 30
   },
   "quote": "a 30GB gp2 root volume"
  },
  {
   "id": "root_type",
   "tier": "core",
   "kind": "attr",
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
      "op": "eq",
      "value": 30
     },
     {
      "path": [
       "Ebs",
       "VolumeType"
      ],
      "op": "eq",
      "value": "gp2"
     }
    ]
   },
   "quote": "a 30GB gp2 root volume"
  },
  {
   "id": "infra",
   "tier": "core",
   "kind": "exists",
   "select": "infra",
   "quote": "Configure the infrastructure to terminate instances on failure"
  },
  {
   "id": "terminate_on_failure",
   "tier": "core",
   "kind": "attr",
   "select": "infra",
   "cond": {
    "path": [
     "TerminateInstanceOnFailure"
    ],
    "op": "eq",
    "value": true
   },
   "quote": "Configure the infrastructure to terminate instances on failure"
  },
  {
   "id": "dist",
   "tier": "core",
   "kind": "exists",
   "select": "dist",
   "quote": "distribute the resulting AMI"
  },
  {
   "id": "dist_launch_perm",
   "tier": "core",
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
    "op": "eq",
    "value": "123456789012"
   },
   "quote": "launch permissions granted to the current account",
   "justify": "the current account resolves to the pseudo account id"
  },
  {
   "id": "pipeline",
   "tier": "core",
   "kind": "exists",
   "select": "pipe",
   "quote": "The image pipeline, named 'sample-image-pipeline'"
  },
  {
   "id": "pipeline_name",
   "tier": "core",
   "kind": "attr",
   "select": "pipe",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "eq",
    "value": "sample-image-pipeline"
   },
   "quote": "The image pipeline, named 'sample-image-pipeline'"
  },
  {
   "id": "pipeline_schedule",
   "tier": "core",
   "kind": "attr",
   "select": "pipe",
   "cond": {
    "path": [
     "Schedule",
     "ScheduleExpression"
    ],
    "op": "regex",
    "value": "^cron\\(0 0?9 (\\*|\\?|1/1) \\* (\\*|\\?)( \\*)?\\)$"
   },
   "quote": "should run daily at 9 AM UTC",
   "justify": "daily at 9 AM is minute 0 hour 9 every day"
  },
  {
   "id": "pipeline_start_condition",
   "tier": "core",
   "kind": "attr",
   "select": "pipe",
   "cond": {
    "path": [
     "Schedule",
     "PipelineExecutionStartCondition"
    ],
    "op": "eq",
    "value": "EXPRESSION_MATCH_AND_DEPENDENCY_UPDATES_AVAILABLE"
   },
   "quote": "triggering only on expression match and dependency updates",
   "justify": "the Image Builder start condition for expression match plus dependency updates"
  },
  {
   "id": "pipeline_scan",
   "tier": "core",
   "kind": "attr",
   "select": "pipe",
   "cond": {
    "path": [
     "ImageScanningConfiguration",
     "ImageScanningEnabled"
    ],
    "op": "eq",
    "value": true
   },
   "quote": "with image scanning and tests enabled"
  },
  {
   "id": "pipeline_tests",
   "tier": "core",
   "kind": "attr",
   "select": "pipe",
   "cond": {
    "path": [
     "ImageTestsConfiguration",
     "ImageTestsEnabled"
    ],
    "op": "none_eq",
    "value": false
   },
   "quote": "with image scanning and tests enabled",
   "justify": "Image Builder runs image tests unless they are turned off, so an omitted setting already means enabled"
  },
  {
   "id": "pipeline_recipe",
   "tier": "core",
   "kind": "ref",
   "from": "pipe",
   "to": "recipe",
   "quote": "creates a complete EC2 Image Builder pipeline"
  },
  {
   "id": "pipeline_infra",
   "tier": "core",
   "kind": "ref",
   "from": "pipe",
   "to": "infra",
   "quote": "Configure the infrastructure"
  },
  {
   "id": "pipeline_dist",
   "tier": "core",
   "kind": "ref",
   "from": "pipe",
   "to": "dist",
   "quote": "distribute the resulting AMI"
  },
  {
   "id": "lifecycle",
   "tier": "core",
   "kind": "exists",
   "select": "life",
   "quote": "provision a lifecycle policy named 'sample-lifecycle-policy'"
  },
  {
   "id": "lifecycle_name",
   "tier": "core",
   "kind": "attr",
   "select": "life",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "eq",
    "value": "sample-lifecycle-policy"
   },
   "quote": "provision a lifecycle policy named 'sample-lifecycle-policy'"
  },
  {
   "id": "lifecycle_deprecate",
   "tier": "core",
   "kind": "attr",
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
   },
   "quote": "deprecates AMIs"
  },
  {
   "id": "lifecycle_age",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
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
       },
       {
        "path": [
         "Filter",
         "Unit"
        ],
        "op": "eq",
        "value": "MONTHS"
       },
       {
        "path": [
         "Filter",
         "Value"
        ],
        "op": "eq",
        "value": 6
       }
      ]
     }
    },
    {
     "kind": "attr",
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
       },
       {
        "path": [
         "Filter",
         "Unit"
        ],
        "op": "eq",
        "value": "DAYS"
       },
       {
        "path": [
         "Filter",
         "Value"
        ],
        "op": "regex",
        "value": "^18[0-9]$"
       }
      ]
     }
    },
    {
     "kind": "attr",
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
       },
       {
        "path": [
         "Filter",
         "Unit"
        ],
        "op": "eq",
        "value": "WEEKS"
       },
       {
        "path": [
         "Filter",
         "Value"
        ],
        "op": "regex",
        "value": "^2[67]$"
       }
      ]
     }
    }
   ],
   "quote": "older than 6 months",
   "justify": "6 months, or the equivalent in days or weeks"
  },
  {
   "id": "lifecycle_tag",
   "tier": "core",
   "kind": "attr",
   "select": "life",
   "cond": {
    "path": [
     "ResourceSelection",
     "TagMap",
     "Environment"
    ],
    "op": "eq",
    "value": "Dev"
   },
   "quote": "for resources tagged with Environment=Dev"
  },
  {
   "id": "lifecycle_ami",
   "tier": "detail",
   "kind": "attr",
   "select": "life",
   "cond": {
    "path": [
     "ResourceType"
    ],
    "op": "regex",
    "value": "(?i)^ami"
   },
   "quote": "deprecates AMIs"
  },
  {
   "id": "lifecycle_role",
   "tier": "detail",
   "kind": "ref",
   "from": "life",
   "to": "role",
   "quote": "the necessary IAM roles with AdministratorAccess for the build infrastructure and lifecycle execution"
  },
  {
   "id": "build_role_admin",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "role_ec2",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "policy/AdministratorAccess$"
     }
    },
    {
     "kind": "attr",
     "select": "role_ec2",
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
        "op": "eq",
        "value": "*"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "eq",
        "value": "*"
       }
      ]
     }
    }
   ],
   "quote": "the necessary IAM roles with AdministratorAccess for the build infrastructure",
   "justify": "build instance role trusted by EC2"
  },
  {
   "id": "build_role_wired",
   "tier": "detail",
   "kind": "all_of",
   "checks": [
    {
     "kind": "ref",
     "from": "infra",
     "to": {
      "types": [
       "AWS::IAM::InstanceProfile"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::InstanceProfile"
      ],
      "where": []
     },
     "to": "role_ec2"
    }
   ],
   "quote": "the necessary IAM roles with AdministratorAccess for the build infrastructure",
   "justify": "the infrastructure configuration reaches its role through an instance profile"
  },
  {
   "id": "lifecycle_role_admin",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "life",
     "to": {
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
        "value": "imagebuilder.amazonaws.com"
       },
       {
        "path": [
         "ManagedPolicyArns",
         "*"
        ],
        "op": "regex",
        "value": "policy/AdministratorAccess$"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "life",
     "to": {
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
        "value": "imagebuilder.amazonaws.com"
       },
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
          "op": "eq",
          "value": "*"
         },
         {
          "path": [
           "Resource",
           "*"
          ],
          "op": "eq",
          "value": "*"
         }
        ]
       }
      ]
     }
    }
   ],
   "quote": "the necessary IAM roles with AdministratorAccess for the build infrastructure and lifecycle execution",
   "justify": "lifecycle execution role trusted by Image Builder"
  },
  {
   "id": "x_delete_on_termination",
   "tier": "extra",
   "kind": "attr",
   "select": "recipe",
   "cond": {
    "path": [
     "BlockDeviceMappings",
     "*",
     "Ebs",
     "DeleteOnTermination"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "x_workflow_abort",
   "tier": "extra",
   "kind": "attr",
   "select": "wf",
   "cond": {
    "path": [
     "Data"
    ],
    "op": "regex",
    "value": "(?i)onFailure:\\s*Abort"
   }
  },
  {
   "id": "x_lifecycle_status",
   "tier": "extra",
   "kind": "attr",
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
   "id": "extra_type_aws_iam_instanceprofile",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::IAM::InstanceProfile"
    ],
    "where": []
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
