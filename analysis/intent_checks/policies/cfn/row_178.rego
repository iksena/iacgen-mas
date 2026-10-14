# GENERATED from specs/cfn/row_178.json by intent_checks/build.py -- do not edit.
package intent.cfn.row_178

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
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
      "Service"
     ],
     "op": "contains",
     "value": "sagemaker.amazonaws.com"
    }
   ]
  },
  "iam_policy": {
   "types": [
    "AWS::IAM::Policy",
    "AWS::IAM::ManagedPolicy"
   ],
   "where": []
  },
  "profile": {
   "types": [
    "AWS::SageMaker::UserProfile"
   ],
   "where": []
  },
  "domain": {
   "types": [
    "AWS::SageMaker::Domain"
   ],
   "where": []
  },
  "vpc": {
   "types": [
    "AWS::EC2::VPC"
   ],
   "where": []
  },
  "subnet": {
   "types": [
    "AWS::EC2::Subnet"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "user_profile",
   "kind": "exists",
   "select": "profile",
   "tier": "core",
   "quote": "provisions a SageMaker Studio user profile for an MLOps engineer persona"
  },
  {
   "id": "execution_role_sagemaker_trust",
   "kind": "exists",
   "select": "role",
   "tier": "core",
   "quote": "The execution role should be assumable by the SageMaker service"
  },
  {
   "id": "profile_uses_execution_role",
   "kind": "any_of",
   "tier": "core",
   "quote": "a SageMaker Studio user profile for an MLOps engineer persona along with an IAM execution role",
   "checks": [
    {
     "kind": "ref",
     "from": "profile",
     "to": "role"
    },
    {
     "kind": "ref",
     "from": "domain",
     "to": "role"
    }
   ]
  },
  {
   "id": "policies_attached_to_role",
   "kind": "any_of",
   "tier": "detail",
   "quote": "should include policies allowing it to",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy"
      ],
      "where": []
     },
     "to": "role"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::ManagedPolicy"
      ],
      "where": []
     },
     "to": "role"
    },
    {
     "kind": "ref",
     "from": "role",
     "to": {
      "types": [
       "AWS::IAM::ManagedPolicy"
      ],
      "where": []
     }
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "pass_role",
   "kind": "any_of",
   "tier": "core",
   "quote": "pass a per-user SageMaker execution role",
   "checks": [
    {
     "kind": "exists",
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
         "Service"
        ],
        "op": "contains",
        "value": "sagemaker.amazonaws.com"
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
        "value": "iam:PassRole"
       }
      ]
     }
    },
    {
     "kind": "exists",
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
         "Service"
        ],
        "op": "contains",
        "value": "sagemaker.amazonaws.com"
       },
       {
        "path": [
         "Policies",
         "*",
         "PolicyDocument",
         "Statement",
         "*",
         "Action"
        ],
        "op": "glob_covers",
        "value": "iam:PassRole"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
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
        "value": "iam:PassRole"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
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
         "Action"
        ],
        "op": "glob_covers",
        "value": "iam:PassRole"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "pipeline_management",
   "kind": "any_of",
   "tier": "core",
   "quote": "manage SageMaker pipelines (create, start, stop, retry, and update pipeline executions, plus list and describe operations)",
   "checks": [
    {
     "kind": "exists",
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
         "Service"
        ],
        "op": "contains",
        "value": "sagemaker.amazonaws.com"
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
        "value": "sagemaker:CreatePipeline"
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
        "value": "sagemaker:StartPipelineExecution"
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
        "value": "sagemaker:StopPipelineExecution"
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
        "value": "sagemaker:RetryPipelineExecution"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
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
        "value": "sagemaker:CreatePipeline"
       },
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "sagemaker:StartPipelineExecution"
       },
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "sagemaker:StopPipelineExecution"
       },
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "sagemaker:RetryPipelineExecution"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "pipeline_update_list_describe",
   "kind": "any_of",
   "tier": "detail",
   "quote": "update pipeline executions, plus list and describe operations",
   "checks": [
    {
     "kind": "exists",
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
         "Service"
        ],
        "op": "contains",
        "value": "sagemaker.amazonaws.com"
       },
       {
        "path": [
         "Policies"
        ],
        "op": "regex",
        "value": "(?i)sagemaker:(Update|\\*)"
       },
       {
        "path": [
         "Policies"
        ],
        "op": "regex",
        "value": "(?i)sagemaker:(List|Describe|\\*)"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument"
        ],
        "op": "regex",
        "value": "(?i)sagemaker:(Update|\\*)"
       },
       {
        "path": [
         "PolicyDocument"
        ],
        "op": "regex",
        "value": "(?i)sagemaker:(List|Describe|\\*)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "model_monitoring",
   "kind": "any_of",
   "tier": "detail",
   "quote": "manage model monitoring schedules and their underlying processing jobs",
   "checks": [
    {
     "kind": "exists",
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
         "Service"
        ],
        "op": "contains",
        "value": "sagemaker.amazonaws.com"
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
        "value": "sagemaker:CreateMonitoringSchedule"
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
        "value": "sagemaker:CreateProcessingJob"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
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
        "value": "sagemaker:CreateMonitoringSchedule"
       },
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "sagemaker:CreateProcessingJob"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "model_management",
   "kind": "any_of",
   "tier": "detail",
   "quote": "manage models and model package groups",
   "checks": [
    {
     "kind": "exists",
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
         "Service"
        ],
        "op": "contains",
        "value": "sagemaker.amazonaws.com"
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
        "value": "sagemaker:CreateModel"
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
        "value": "sagemaker:CreateModelPackageGroup"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
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
        "value": "sagemaker:CreateModel"
       },
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "sagemaker:CreateModelPackageGroup"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "experiments_lineage_view",
   "kind": "any_of",
   "tier": "detail",
   "quote": "view experiments, trials, and lineage information",
   "checks": [
    {
     "kind": "exists",
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
         "Service"
        ],
        "op": "contains",
        "value": "sagemaker.amazonaws.com"
       },
       {
        "path": [
         "Policies"
        ],
        "op": "regex",
        "value": "(?i)sagemaker:([A-Za-z*]*Experiment|\\*)"
       },
       {
        "path": [
         "Policies"
        ],
        "op": "regex",
        "value": "(?i)sagemaker:([A-Za-z*]*Trial|\\*)"
       },
       {
        "path": [
         "Policies"
        ],
        "op": "regex",
        "value": "(?i)sagemaker:([A-Za-z*]*Lineage|[A-Za-z*]*Association|\\*)"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument"
        ],
        "op": "regex",
        "value": "(?i)sagemaker:([A-Za-z*]*Experiment|\\*)"
       },
       {
        "path": [
         "PolicyDocument"
        ],
        "op": "regex",
        "value": "(?i)sagemaker:([A-Za-z*]*Trial|\\*)"
       },
       {
        "path": [
         "PolicyDocument"
        ],
        "op": "regex",
        "value": "(?i)sagemaker:([A-Za-z*]*Lineage|[A-Za-z*]*Association|\\*)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "training_transform_processing_tuning_jobs",
   "kind": "any_of",
   "tier": "core",
   "quote": "run training, transform, processing, and hyperparameter tuning jobs",
   "checks": [
    {
     "kind": "exists",
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
         "Service"
        ],
        "op": "contains",
        "value": "sagemaker.amazonaws.com"
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
        "value": "sagemaker:CreateTrainingJob"
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
        "value": "sagemaker:CreateTransformJob"
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
        "value": "sagemaker:CreateProcessingJob"
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
        "value": "sagemaker:CreateHyperParameterTuningJob"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
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
        "value": "sagemaker:CreateTrainingJob"
       },
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "sagemaker:CreateTransformJob"
       },
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "sagemaker:CreateProcessingJob"
       },
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "sagemaker:CreateHyperParameterTuningJob"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "endpoint_management",
   "kind": "any_of",
   "tier": "detail",
   "quote": "manage SageMaker endpoints",
   "checks": [
    {
     "kind": "exists",
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
         "Service"
        ],
        "op": "contains",
        "value": "sagemaker.amazonaws.com"
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
        "value": "sagemaker:CreateEndpoint"
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
        "value": "sagemaker:UpdateEndpoint"
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
        "value": "sagemaker:DeleteEndpoint"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
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
        "value": "sagemaker:CreateEndpoint"
       },
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "sagemaker:UpdateEndpoint"
       },
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "sagemaker:DeleteEndpoint"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "studio_apps_spaces_owner_restricted",
   "kind": "any_of",
   "tier": "core",
   "quote": "use SageMaker Studio applications and shared or private spaces with an ownership restriction so a user can only manage apps and spaces they own",
   "checks": [
    {
     "kind": "exists",
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
         "Service"
        ],
        "op": "contains",
        "value": "sagemaker.amazonaws.com"
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
        "value": "sagemaker:CreateApp"
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
        "value": "sagemaker:CreateSpace"
       },
       {
        "path": [
         "Policies"
        ],
        "op": "regex",
        "value": "(?i)OwnerUserProfileArn|UserProfileName|SpaceName|ResourceTag/|PrincipalTag/"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
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
        "value": "sagemaker:CreateApp"
       },
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "sagemaker:CreateSpace"
       },
       {
        "path": [
         "PolicyDocument"
        ],
        "op": "regex",
        "value": "(?i)OwnerUserProfileArn|UserProfileName|SpaceName|ResourceTag/|PrincipalTag/"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "optional_existing_domain_params",
   "kind": "exists",
   "min": 3,
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "default"
      ],
      "op": "in",
      "value": [
       "",
       "[\"\"]"
      ]
     }
    ]
   },
   "tier": "detail",
   "quote": "Accept optional parameters for an existing SageMaker Studio domain ID together with its associated security group IDs and subnet IDs",
   "justify": "three optional parameters stated: domain ID, security group IDs, subnet IDs"
  },
  {
   "id": "self_contained_vpc_subnet",
   "kind": "ref",
   "from": "subnet",
   "to": "vpc",
   "tier": "detail",
   "quote": "create its own self-contained VPC, subnet"
  },
  {
   "id": "domain_in_created_network",
   "kind": "all_of",
   "tier": "core",
   "quote": "create its own self-contained VPC, subnet, and public-internet-access SageMaker Studio domain",
   "checks": [
    {
     "kind": "ref",
     "from": "domain",
     "to": "vpc"
    },
    {
     "kind": "ref",
     "from": "domain",
     "to": "subnet"
    }
   ]
  },
  {
   "id": "domain_public_internet",
   "kind": "attr",
   "select": "domain",
   "cond": {
    "path": [
     "AppNetworkAccessType"
    ],
    "op": "eq",
    "value": "PublicInternetOnly"
   },
   "tier": "core",
   "quote": "public-internet-access SageMaker Studio domain"
  },
  {
   "id": "domain_default_role",
   "kind": "ref",
   "from": "domain",
   "to": "role",
   "tier": "detail",
   "quote": "using the created execution role for its default user settings"
  },
  {
   "id": "profile_attached_to_domain",
   "kind": "ref",
   "from": "profile",
   "to": "domain",
   "tier": "core",
   "quote": "attach the new user profile to that domain instead"
  },
  {
   "id": "output_profile_arn",
   "kind": "any_of",
   "tier": "detail",
   "quote": "Output the ARN of the created user profile",
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
        "value": "UserProfileArn"
       }
      ]
     },
     "to": "profile"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "__output__"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)arn"
       }
      ]
     },
     "to": "profile"
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
