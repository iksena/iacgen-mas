package intent.cfn.row_142

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "recipe": {
   "types": [
    "AWS::ImageBuilder::ImageRecipe"
   ],
   "where": []
  },
  "component": {
   "types": [
    "AWS::ImageBuilder::Component"
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
  "builder": {
   "types": [
    "AWS::ImageBuilder::Image",
    "AWS::ImageBuilder::ImagePipeline"
   ],
   "where": []
  },
  "param": {
   "types": [
    "__parameter__"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "image_builder_pipeline",
   "kind": "exists",
   "select": "builder",
   "tier": "core",
   "quote": "creates an EC2 Image Builder pipeline to build custom Amazon Linux 2023 AMIs"
  },
  {
   "id": "two_recipes",
   "kind": "exists",
   "select": "recipe",
   "min": 2,
   "tier": "core",
   "quote": "define two image recipes"
  },
  {
   "id": "recipe_al2023_x86",
   "kind": "attr",
   "select": "recipe",
   "cond": {
    "path": [
     "ParentImage"
    ],
    "op": "regex",
    "value": "(?i)(amazon-linux-2023|al2023).*(x86|amd64)"
   },
   "tier": "core",
   "quote": "Amazon Linux 2023 AMIs for both x86 and arm64 architectures"
  },
  {
   "id": "recipe_al2023_arm64",
   "kind": "attr",
   "select": "recipe",
   "cond": {
    "path": [
     "ParentImage"
    ],
    "op": "regex",
    "value": "(?i)(amazon-linux-2023|al2023).*(arm64|aarch64)"
   },
   "tier": "core",
   "quote": "Amazon Linux 2023 AMIs for both x86 and arm64 architectures"
  },
  {
   "id": "install_component",
   "kind": "attr",
   "select": "component",
   "cond": {
    "path": [
     "Data"
    ],
    "op": "regex",
    "value": "(?i)docker[- ]?compose"
   },
   "tier": "core",
   "quote": "installing Docker, Docker Compose"
  },
  {
   "id": "component_python_packages",
   "kind": "all_of",
   "tier": "detail",
   "quote": "Python packages (synapseclient, pandas, pysftp)",
   "checks": [
    {
     "kind": "attr",
     "select": "component",
     "cond": {
      "path": [
       "Data"
      ],
      "op": "contains",
      "value": "synapseclient"
     }
    },
    {
     "kind": "attr",
     "select": "component",
     "cond": {
      "path": [
       "Data"
      ],
      "op": "contains",
      "value": "pandas"
     }
    },
    {
     "kind": "attr",
     "select": "component",
     "cond": {
      "path": [
       "Data"
      ],
      "op": "contains",
      "value": "pysftp"
     }
    }
   ]
  },
  {
   "id": "component_ssm_sudo",
   "kind": "attr",
   "select": "component",
   "cond": {
    "path": [
     "Data"
    ],
    "op": "regex",
    "value": "(?i)ssm-user.*(nopasswd|sudo|all=)"
   },
   "tier": "detail",
   "quote": "enabling SSM user sudo access"
  },
  {
   "id": "component_test_phase",
   "kind": "all_of",
   "tier": "detail",
   "quote": "a test phase verifying Docker Compose and Python imports",
   "checks": [
    {
     "kind": "attr",
     "select": "component",
     "cond": {
      "path": [
       "Data"
      ],
      "op": "regex",
      "value": "(?is)name:\\s*test.*compose"
     }
    },
    {
     "kind": "attr",
     "select": "component",
     "cond": {
      "path": [
       "Data"
      ],
      "op": "regex",
      "value": "(?is)name:\\s*test.*import"
     }
    }
   ]
  },
  {
   "id": "recipes_use_component",
   "kind": "ref",
   "from": "recipe",
   "to": "component",
   "tier": "core",
   "quote": "the pipeline should include a component for software installation"
  },
  {
   "id": "single_infra_config",
   "kind": "exists",
   "select": "infra",
   "max": 1,
   "tier": "core",
   "quote": "a shared infrastructure configuration",
   "justify": "\"a shared infrastructure configuration\" = one config used by both builds"
  },
  {
   "id": "infra_shared",
   "kind": "exists",
   "min": 2,
   "tier": "detail",
   "select": {
    "types": [
     "AWS::ImageBuilder::Image",
     "AWS::ImageBuilder::ImagePipeline"
    ],
    "where": [
     {
      "path": [
       "InfrastructureConfigurationArn"
      ],
      "op": "present"
     }
    ]
   },
   "quote": "a shared infrastructure configuration",
   "justify": "two image recipes (x86 + arm64) need two image builds that share the infrastructure configuration"
  },
  {
   "id": "single_distribution_config",
   "kind": "exists",
   "select": "dist",
   "max": 1,
   "tier": "core",
   "quote": "a single distribution configuration",
   "justify": "prompt states \"a single distribution configuration\""
  },
  {
   "id": "distribution_public",
   "kind": "attr",
   "select": "dist",
   "cond": {
    "path": [
     "Distributions",
     "*",
     "AmiDistributionConfiguration",
     "LaunchPermissionConfiguration",
     "UserGroups",
     "*"
    ],
    "op": "eq",
    "value": "all"
   },
   "tier": "core",
   "quote": "distributing the images publicly"
  },
  {
   "id": "distribution_org_share",
   "kind": "attr",
   "select": "dist",
   "cond": {
    "path": [
     "Distributions",
     "*",
     "AmiDistributionConfiguration",
     "LaunchPermissionConfiguration",
     "OrganizationArns",
     "*"
    ],
    "op": "present"
   },
   "tier": "core",
   "quote": "sharing them with a specified AWS Organization ID"
  },
  {
   "id": "org_id_parameter",
   "kind": "attr",
   "select": "param",
   "cond": {
    "path": [
     "default"
    ],
    "op": "regex",
    "value": "^o-"
   },
   "tier": "detail",
   "quote": "(with a configurable default)"
  },
  {
   "id": "root_volume_32",
   "kind": "attr",
   "select": "recipe",
   "quantifier": "all",
   "cond": {
    "path": [
     "BlockDeviceMappings",
     "*",
     "Ebs",
     "VolumeSize"
    ],
    "op": "eq",
    "value": 32
   },
   "tier": "core",
   "quote": "root volume size (default 32 GB)"
  },
  {
   "id": "configurable_version_and_volume",
   "kind": "all_of",
   "tier": "detail",
   "quote": "allow the user to set the image version and root volume size",
   "checks": [
    {
     "kind": "attr",
     "select": "param",
     "cond": {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": 32
     }
    },
    {
     "kind": "exists",
     "select": "param",
     "min": 3
    }
   ],
   "justify": "prompt makes three values user-settable: organization ID (configurable default), image version and root volume size (default 32)"
  },
  {
   "id": "ami_tagged_stack_name",
   "kind": "attr",
   "select": "dist",
   "cond": {
    "path": [
     "Distributions",
     "*",
     "AmiDistributionConfiguration",
     "AmiTags",
     "*"
    ],
    "op": "eq",
    "value": "stack"
   },
   "tier": "detail",
   "quote": "The resulting AMIs must be tagged with the stack name"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
