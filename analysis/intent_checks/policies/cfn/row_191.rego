package intent.cfn.row_191

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "domain": {
   "types": [
    "AWS::SageMaker::Domain"
   ],
   "where": []
  },
  "profile": {
   "types": [
    "AWS::SageMaker::UserProfile"
   ],
   "where": []
  },
  "role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "pol": {
   "types": [
    "AWS::IAM::Policy",
    "AWS::IAM::ManagedPolicy",
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "out": {
   "types": [
    "__output__"
   ],
   "where": []
  },
  "out_url": {
   "types": [
    "__output__"
   ],
   "where": [
    {
     "path": [
      "value"
     ],
     "op": "regex",
     "value": "(?i)https?://"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "domain",
   "kind": "exists",
   "select": "domain",
   "tier": "core",
   "quote": "a self-contained SageMaker Domain"
  },
  {
   "id": "domain_vpc_only",
   "kind": "attr",
   "select": "domain",
   "cond": {
    "path": [
     "AppNetworkAccessType"
    ],
    "op": "eq",
    "value": "VpcOnly"
   },
   "tier": "core",
   "quote": "configured in VPC Only mode"
  },
  {
   "id": "domain_has_vpc_and_subnets",
   "tier": "detail",
   "quote": "the VPC ID, a comma-separated list of subnet IDs",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": "domain",
     "cond": {
      "path": [
       "VpcId"
      ],
      "op": "present"
     }
    },
    {
     "kind": "attr",
     "select": "domain",
     "cond": {
      "path": [
       "SubnetIds"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "domain_security_groups",
   "tier": "detail",
   "quote": "a comma-separated list of security group IDs",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "domain",
     "cond": {
      "path": [
       "DefaultUserSettings",
       "SecurityGroups"
      ],
      "op": "present"
     }
    },
    {
     "kind": "attr",
     "select": "domain",
     "cond": {
      "path": [
       "DomainSettings",
       "SecurityGroupIds"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "user_profile",
   "kind": "exists",
   "select": "profile",
   "min": 1,
   "max": 1,
   "tier": "core",
   "quote": "a single test user profile",
   "justify": "single means exactly one"
  },
  {
   "id": "profile_in_domain",
   "kind": "ref",
   "from": "profile",
   "to": "domain",
   "tier": "detail",
   "quote": "with a single test user profile"
  },
  {
   "id": "iam_role",
   "kind": "exists",
   "select": "role",
   "tier": "core",
   "quote": "a dedicated IAM role"
  },
  {
   "id": "sagemaker_permissions_on_role",
   "tier": "core",
   "quote": "a dedicated IAM role that grants the user full permissions to manage SageMaker",
   "kind": "any_of",
   "checks": [
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
         "PolicyDocument"
        ],
        "op": "regex",
        "value": "(?i)(^|[^:])sagemaker:"
       }
      ]
     },
     "to": "role"
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)AmazonSageMakerFullAccess|(^|[^:])sagemaker:"
     }
    }
   ]
  },
  {
   "id": "role_trusts_sagemaker",
   "kind": "attr",
   "select": "role",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument"
    ],
    "op": "regex",
    "value": "sagemaker\\.amazonaws\\.com"
   },
   "tier": "detail",
   "quote": "a dedicated IAM role that grants the user full permissions to manage SageMaker",
   "justify": "a SageMaker execution role is assumed by the SageMaker service"
  },
  {
   "id": "role_used_by_domain_or_profile",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "domain",
     "to": "role"
    },
    {
     "kind": "ref",
     "from": "profile",
     "to": "role"
    }
   ],
   "tier": "core",
   "quote": "a dedicated IAM role that grants the user full permissions"
  },
  {
   "id": "jobs_create",
   "tier": "core",
   "quote": "create, stop, describe, and list training, transform, processing, AutoML, and hyperparameter tuning jobs",
   "kind": "all_of",
   "justify": "create is the stated job action",
   "checks": [
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)AmazonSageMakerFullAccess|(^|[^:])sagemaker:(\\*|Create\\*|CreateTraining\\*|CreateTrainingJob\\*?)([^A-Za-z0-9_]|$)"
     }
    },
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)AmazonSageMakerFullAccess|(^|[^:])sagemaker:(\\*|Create\\*|CreateTransform\\*|CreateTransformJob\\*?)([^A-Za-z0-9_]|$)"
     }
    },
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)AmazonSageMakerFullAccess|(^|[^:])sagemaker:(\\*|Create\\*|CreateProcessing\\*|CreateProcessingJob\\*?)([^A-Za-z0-9_]|$)"
     }
    },
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)AmazonSageMakerFullAccess|(^|[^:])sagemaker:(\\*|Create\\*|CreateAuto\\*|CreateAutoML\\*|CreateAutoMLJob\\*?)([^A-Za-z0-9_]|$)"
     }
    },
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)AmazonSageMakerFullAccess|(^|[^:])sagemaker:(\\*|Create\\*|CreateHyper\\*|CreateHyperParameter\\*|CreateHyperParameterTuning\\*|CreateHyperParameterTuningJob\\*?)([^A-Za-z0-9_]|$)"
     }
    }
   ]
  },
  {
   "id": "jobs_stop",
   "tier": "core",
   "quote": "create, stop, describe, and list training, transform, processing, AutoML, and hyperparameter tuning jobs",
   "kind": "all_of",
   "justify": "stop is the stated job action",
   "checks": [
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)AmazonSageMakerFullAccess|(^|[^:])sagemaker:(\\*|Stop\\*|StopTraining\\*|StopTrainingJob\\*?)([^A-Za-z0-9_]|$)"
     }
    },
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)AmazonSageMakerFullAccess|(^|[^:])sagemaker:(\\*|Stop\\*|StopTransform\\*|StopTransformJob\\*?)([^A-Za-z0-9_]|$)"
     }
    },
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)AmazonSageMakerFullAccess|(^|[^:])sagemaker:(\\*|Stop\\*|StopProcessing\\*|StopProcessingJob\\*?)([^A-Za-z0-9_]|$)"
     }
    },
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)AmazonSageMakerFullAccess|(^|[^:])sagemaker:(\\*|Stop\\*|StopAuto\\*|StopAutoML\\*|StopAutoMLJob\\*?)([^A-Za-z0-9_]|$)"
     }
    },
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)AmazonSageMakerFullAccess|(^|[^:])sagemaker:(\\*|Stop\\*|StopHyper\\*|StopHyperParameter\\*|StopHyperParameterTuning\\*|StopHyperParameterTuningJob\\*?)([^A-Za-z0-9_]|$)"
     }
    }
   ]
  },
  {
   "id": "jobs_describe",
   "tier": "core",
   "quote": "create, stop, describe, and list training, transform, processing, AutoML, and hyperparameter tuning jobs",
   "kind": "all_of",
   "justify": "describe is the stated job action",
   "checks": [
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)AmazonSageMakerFullAccess|(^|[^:])sagemaker:(\\*|Describe\\*|DescribeTraining\\*|DescribeTrainingJob\\*?)([^A-Za-z0-9_]|$)"
     }
    },
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)AmazonSageMakerFullAccess|(^|[^:])sagemaker:(\\*|Describe\\*|DescribeTransform\\*|DescribeTransformJob\\*?)([^A-Za-z0-9_]|$)"
     }
    },
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)AmazonSageMakerFullAccess|(^|[^:])sagemaker:(\\*|Describe\\*|DescribeProcessing\\*|DescribeProcessingJob\\*?)([^A-Za-z0-9_]|$)"
     }
    },
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)AmazonSageMakerFullAccess|(^|[^:])sagemaker:(\\*|Describe\\*|DescribeAuto\\*|DescribeAutoML\\*|DescribeAutoMLJob\\*?)([^A-Za-z0-9_]|$)"
     }
    },
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)AmazonSageMakerFullAccess|(^|[^:])sagemaker:(\\*|Describe\\*|DescribeHyper\\*|DescribeHyperParameter\\*|DescribeHyperParameterTuning\\*|DescribeHyperParameterTuningJob\\*?)([^A-Za-z0-9_]|$)"
     }
    }
   ]
  },
  {
   "id": "jobs_list",
   "tier": "core",
   "quote": "create, stop, describe, and list training, transform, processing, AutoML, and hyperparameter tuning jobs",
   "kind": "all_of",
   "justify": "list is the stated job action",
   "checks": [
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)AmazonSageMakerFullAccess|(^|[^:])sagemaker:(\\*|List\\*|ListTraining\\*|ListTrainingJobs\\*?)([^A-Za-z0-9_]|$)"
     }
    },
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)AmazonSageMakerFullAccess|(^|[^:])sagemaker:(\\*|List\\*|ListTransform\\*|ListTransformJobs\\*?)([^A-Za-z0-9_]|$)"
     }
    },
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)AmazonSageMakerFullAccess|(^|[^:])sagemaker:(\\*|List\\*|ListProcessing\\*|ListProcessingJobs\\*?)([^A-Za-z0-9_]|$)"
     }
    },
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)AmazonSageMakerFullAccess|(^|[^:])sagemaker:(\\*|List\\*|ListAuto\\*|ListAutoML\\*|ListAutoMLJobs\\*?)([^A-Za-z0-9_]|$)"
     }
    },
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)AmazonSageMakerFullAccess|(^|[^:])sagemaker:(\\*|List\\*|ListHyper\\*|ListHyperParameter\\*|ListHyperParameterTuning\\*|ListHyperParameterTuningJobs\\*?)([^A-Za-z0-9_]|$)"
     }
    }
   ]
  },
  {
   "id": "experiments_lineage_artifacts",
   "tier": "core",
   "quote": "manage experiment lineage and artifacts",
   "kind": "all_of",
   "justify": "experiments, artifacts and a lineage action (a lineage query or association)",
   "checks": [
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)AmazonSageMakerFullAccess|(^|[^:])sagemaker:(\\*|Create\\*|CreateExperiment\\*?)([^A-Za-z0-9_]|$)"
     }
    },
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)AmazonSageMakerFullAccess|(^|[^:])sagemaker:(\\*|Create\\*|CreateArtifact\\*?)([^A-Za-z0-9_]|$)"
     }
    },
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)AmazonSageMakerFullAccess|(^|[^:])sagemaker:(\\*|Query\\*|QueryLineage|Add\\*|AddAssociation|List\\*|ListAssociations|ListLineageGroups|Describe\\*|DescribeLineageGroup|Delete\\*|DeleteAssociation)([^A-Za-z0-9_]|$)"
     }
    }
   ]
  },
  {
   "id": "model_packages_groups",
   "tier": "core",
   "quote": "create and manage model packages and groups",
   "kind": "all_of",
   "justify": "model packages and model package groups",
   "checks": [
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)AmazonSageMakerFullAccess|(^|[^:])sagemaker:(\\*|Create\\*|CreateModel\\*|CreateModelPackage\\*?)([^A-Za-z0-9_]|$)"
     }
    },
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)AmazonSageMakerFullAccess|(^|[^:])sagemaker:(\\*|Create\\*|CreateModel\\*|CreateModelPackage\\*|CreateModelPackageGroup\\*?)([^A-Za-z0-9_]|$)"
     }
    }
   ]
  },
  {
   "id": "studio_apps_spaces_urls",
   "tier": "core",
   "quote": "handle Studio apps, spaces, and presigned domain URLs",
   "kind": "all_of",
   "justify": "apps, spaces and presigned domain URLs",
   "checks": [
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)AmazonSageMakerFullAccess|(^|[^:])sagemaker:(\\*|Create\\*|CreateApp\\*?)([^A-Za-z0-9_]|$)"
     }
    },
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)AmazonSageMakerFullAccess|(^|[^:])sagemaker:(\\*|Create\\*|CreateSpace\\*?)([^A-Za-z0-9_]|$)"
     }
    },
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)AmazonSageMakerFullAccess|(^|[^:])sagemaker:(\\*|Create\\*|CreatePresigned\\*|CreatePresignedDomain\\*|CreatePresignedDomainUrl\\*?)([^A-Za-z0-9_]|$)"
     }
    }
   ]
  },
  {
   "id": "s3_read_write",
   "tier": "core",
   "quote": "read-write access to a specific default S3 bucket for the domain",
   "kind": "any_of",
   "justify": "read-write means reading (GetObject) and writing (PutObject) objects",
   "checks": [
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
         "PolicyDocument"
        ],
        "op": "regex",
        "value": "(?i)(^|[^:])s3:(\\*|Get\\*|GetObject\\*?)([^A-Za-z0-9_]|$)"
       },
       {
        "path": [
         "PolicyDocument"
        ],
        "op": "regex",
        "value": "(?i)(^|[^:])s3:(\\*|Put\\*|PutObject\\*?)([^A-Za-z0-9_]|$)"
       }
      ]
     },
     "to": "role"
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
         "Policies"
        ],
        "op": "regex",
        "value": "(?i)(^|[^:])s3:(\\*|Get\\*|GetObject\\*?)([^A-Za-z0-9_]|$)"
       },
       {
        "path": [
         "Policies"
        ],
        "op": "regex",
        "value": "(?i)(^|[^:])s3:(\\*|Put\\*|PutObject\\*?)([^A-Za-z0-9_]|$)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "s3_scoped_to_bucket",
   "tier": "detail",
   "quote": "a specific default S3 bucket",
   "justify": "a specific bucket means the write statement names a bucket, not an all-buckets wildcard such as * or arn:aws:s3:::*/*",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "s3:PutObject"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "(?i)s3:::[a-z0-9$]|ref|Fn::|\\$\\{",
        "every": true
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
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "s3:PutObject"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "(?i)s3:::[a-z0-9$]|ref|Fn::|\\$\\{",
        "every": true
       }
      ]
     }
    }
   ]
  },
  {
   "id": "pass_role",
   "tier": "core",
   "quote": "the ability to pass itself to SageMaker services",
   "kind": "any_of",
   "checks": [
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
         "PolicyDocument"
        ],
        "op": "regex",
        "value": "(?i)(^|[^:])iam:(\\*|Pass\\*|PassRole)([^A-Za-z0-9_]|$)"
       }
      ]
     },
     "to": "role"
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": [
       {
        "path": [],
        "op": "regex",
        "value": "(?i)AmazonSageMakerFullAccess|(^|[^:])iam:(\\*|Pass\\*|PassRole)([^A-Za-z0-9_]|$)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "param_domain_name",
   "tier": "detail",
   "quote": "accept parameters for the domain name",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)domain.?name|^domain"
     }
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "__parameter__"
      ],
      "where": []
     },
     "from_path": [
      "default"
     ],
     "to": "domain",
     "to_path": [
      "DomainName"
     ]
    }
   ]
  },
  {
   "id": "param_user_name",
   "tier": "detail",
   "quote": "the test user name",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)user"
     }
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "__parameter__"
      ],
      "where": []
     },
     "from_path": [
      "default"
     ],
     "to": "profile",
     "to_path": [
      "UserProfileName"
     ]
    }
   ]
  },
  {
   "id": "param_bucket_arn",
   "tier": "detail",
   "quote": "the ARN of the default S3 bucket",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)bucket|s3"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "regex",
      "value": "(?i)^arn:[^:]*:s3:::"
     }
    }
   ]
  },
  {
   "id": "output_domain_id",
   "tier": "core",
   "quote": "it must output the domain ID",
   "kind": "any_of",
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
         "ref"
        ],
        "op": "present"
       },
       {
        "path": [
         "value",
         "attr"
        ],
        "op": "absent"
       }
      ]
     },
     "to": "domain"
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
         "value",
         "attr"
        ],
        "op": "eq",
        "value": "DomainId"
       }
      ]
     },
     "to": "domain"
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
         "value"
        ],
        "op": "regex",
        "value": "\\.DomainId\\}"
       }
      ]
     },
     "to": "domain"
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
        "value": "(?i)domain.?id"
       }
      ]
     },
     "to": "domain"
    }
   ],
   "justify": "Ref on a SageMaker domain returns its ID; GetAtt DomainId is the same value, while DomainArn is not the ID"
  },
  {
   "id": "output_role_name",
   "tier": "core",
   "quote": "the execution role name",
   "kind": "any_of",
   "justify": "Ref on an IAM role returns its name; GetAtt Arn returns the ARN, not the name",
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
         "ref"
        ],
        "op": "present"
       },
       {
        "path": [
         "value",
         "attr"
        ],
        "op": "absent"
       }
      ]
     },
     "to": "role"
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
        "value": "(?i)role.?name"
       }
      ]
     },
     "to": "role"
    }
   ]
  },
  {
   "id": "output_studio_url",
   "tier": "core",
   "quote": "a direct URL to the SageMaker Studio console for the new domain",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "out_url",
     "to": "domain"
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
         "value",
         "attr"
        ],
        "op": "eq",
        "value": "Url"
       }
      ]
     },
     "to": "domain"
    }
   ],
   "justify": "a direct URL is an http(s) address, or the domain's Url attribute"
  },
  {
   "id": "x_auth_mode_iam",
   "kind": "attr",
   "select": "domain",
   "cond": {
    "path": [
     "AuthMode"
    ],
    "op": "eq",
    "value": "IAM"
   },
   "tier": "extra"
  },
  {
   "id": "x_passrole_to_sagemaker",
   "kind": "attr",
   "select": "pol",
   "cond": {
    "path": [],
    "op": "regex",
    "value": "iam:PassedToService[^a-z]*sagemaker\\.amazonaws\\.com"
   },
   "tier": "extra"
  },
  {
   "id": "x_domain_execution_role",
   "kind": "attr",
   "select": "domain",
   "cond": {
    "path": [
     "DefaultUserSettings",
     "ExecutionRole"
    ],
    "op": "present"
   },
   "tier": "extra"
  },
  {
   "id": "x_s3_list_bucket",
   "kind": "attr",
   "select": "pol",
   "cond": {
    "path": [],
    "op": "regex",
    "value": "s3:(\\*|List\\*|ListBucket)([^A-Za-z0-9_]|$)"
   },
   "tier": "extra"
  },
  {
   "id": "extra_type_aws_ec2_eip",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::EC2::EIP"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_ec2_internetgateway",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::EC2::InternetGateway"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_ec2_natgateway",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::EC2::NatGateway"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_ec2_route",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::EC2::Route"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_ec2_routetable",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::EC2::RouteTable"
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
     "AWS::EC2::SecurityGroup"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_ec2_subnet",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::EC2::Subnet"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_ec2_subnetroutetableassociation",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::EC2::SubnetRouteTableAssociation"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_ec2_vpc",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::EC2::VPC"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_ec2_vpcgatewayattachment",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::EC2::VPCGatewayAttachment"
    ],
    "where": []
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
