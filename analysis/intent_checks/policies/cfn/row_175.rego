package intent.cfn.row_175

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "portfolio": {
   "types": [
    "AWS::ServiceCatalog::Portfolio"
   ],
   "where": []
  },
  "product": {
   "types": [
    "AWS::ServiceCatalog::CloudFormationProduct"
   ],
   "where": []
  },
  "assoc": {
   "types": [
    "AWS::ServiceCatalog::PortfolioProductAssociation"
   ],
   "where": []
  },
  "constraint": {
   "types": [
    "AWS::ServiceCatalog::LaunchRoleConstraint"
   ],
   "where": []
  },
  "launch_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "contains",
     "value": "servicecatalog.amazonaws.com"
    }
   ]
  },
  "user_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "regex",
     "value": "\"AWS\"\\s*:"
    }
   ]
  },
  "principal_assoc": {
   "types": [
    "AWS::ServiceCatalog::PortfolioPrincipalAssociation"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "two_portfolios",
   "kind": "exists",
   "select": "portfolio",
   "min": 2,
   "tier": "core",
   "quote": "including two portfolios, one for an admin team and one for end users"
  },
  {
   "id": "products",
   "kind": "exists",
   "select": "product",
   "min": 7,
   "tier": "core",
   "quote": "with a set of products",
   "justify": "the prompt enumerates seven products (VPC, IAM/KMS/S3, Data Exchange, infrastructure, application, SageMaker notebook, ML model)"
  },
  {
   "id": "product_vpc",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a VPC with private subnets and endpoints",
   "checks": [
    {
     "kind": "attr",
     "select": "product",
     "cond": {
      "path": [
       "Name"
      ],
      "op": "regex",
      "value": "(?i)vpc"
     }
    },
    {
     "kind": "attr",
     "select": "product",
     "cond": {
      "path": [
       "Description"
      ],
      "op": "regex",
      "value": "(?i)vpc"
     }
    }
   ]
  },
  {
   "id": "product_iam_kms_s3",
   "kind": "any_of",
   "tier": "detail",
   "quote": "IAM roles with KMS keys and S3 buckets",
   "checks": [
    {
     "kind": "attr",
     "select": "product",
     "cond": {
      "path": [
       "Name"
      ],
      "op": "regex",
      "value": "(?i)kms"
     }
    },
    {
     "kind": "attr",
     "select": "product",
     "cond": {
      "path": [
       "Description"
      ],
      "op": "regex",
      "value": "(?i)kms"
     }
    }
   ]
  },
  {
   "id": "product_data_exchange",
   "kind": "any_of",
   "tier": "core",
   "quote": "an AWS Data Exchange product",
   "checks": [
    {
     "kind": "attr",
     "select": "product",
     "cond": {
      "path": [
       "Name"
      ],
      "op": "regex",
      "value": "(?i)data.?exchange|dataset"
     }
    },
    {
     "kind": "attr",
     "select": "product",
     "cond": {
      "path": [
       "Description"
      ],
      "op": "regex",
      "value": "(?i)data.?exchange|dataset"
     }
    }
   ]
  },
  {
   "id": "product_infrastructure",
   "kind": "any_of",
   "tier": "detail",
   "quote": "an infrastructure product",
   "checks": [
    {
     "kind": "attr",
     "select": "product",
     "cond": {
      "path": [
       "Name"
      ],
      "op": "regex",
      "value": "(?i)infrastructure"
     }
    },
    {
     "kind": "attr",
     "select": "product",
     "cond": {
      "path": [
       "Description"
      ],
      "op": "regex",
      "value": "(?i)infrastructure"
     }
    }
   ]
  },
  {
   "id": "product_application",
   "kind": "any_of",
   "tier": "detail",
   "quote": "an application product",
   "checks": [
    {
     "kind": "attr",
     "select": "product",
     "cond": {
      "path": [
       "Name"
      ],
      "op": "regex",
      "value": "(?i)application"
     }
    },
    {
     "kind": "attr",
     "select": "product",
     "cond": {
      "path": [
       "Description"
      ],
      "op": "regex",
      "value": "(?i)application"
     }
    }
   ]
  },
  {
   "id": "product_sagemaker_notebook",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a SageMaker notebook instance",
   "checks": [
    {
     "kind": "attr",
     "select": "product",
     "cond": {
      "path": [
       "Name"
      ],
      "op": "regex",
      "value": "(?i)notebook"
     }
    },
    {
     "kind": "attr",
     "select": "product",
     "cond": {
      "path": [
       "Description"
      ],
      "op": "regex",
      "value": "(?i)notebook"
     }
    }
   ]
  },
  {
   "id": "product_ml_model",
   "kind": "any_of",
   "tier": "core",
   "quote": "a third-party ML model",
   "checks": [
    {
     "kind": "attr",
     "select": "product",
     "cond": {
      "path": [
       "Name"
      ],
      "op": "regex",
      "value": "(?i)model"
     }
    },
    {
     "kind": "attr",
     "select": "product",
     "cond": {
      "path": [
       "Description"
      ],
      "op": "regex",
      "value": "(?i)model"
     }
    }
   ]
  },
  {
   "id": "products_from_root_url",
   "kind": "attr",
   "select": "product",
   "quantifier": "all",
   "cond": {
    "path": [
     "ProvisioningArtifactParameters",
     "*",
     "Info",
     "LoadTemplateFromURL"
    ],
    "op": "regex",
    "value": "^https://aws-service-catalog-reference-architectures\\.s3\\.amazonaws\\.com/blog_content/securing-third-party-data-and-ml-apps/"
   },
   "tier": "detail",
   "quote": "the root S3 URL pointing to the location of the nested CloudFormation templates"
  },
  {
   "id": "product_portfolio_association",
   "kind": "all_of",
   "tier": "core",
   "quote": "each associated with its respective portfolio",
   "checks": [
    {
     "kind": "ref",
     "from": "assoc",
     "to": "product"
    },
    {
     "kind": "ref",
     "from": "assoc",
     "to": "portfolio"
    }
   ]
  },
  {
   "id": "product_associations_count",
   "kind": "exists",
   "select": "assoc",
   "min": 7,
   "tier": "detail",
   "quote": "each associated with its respective portfolio",
   "justify": "each of the seven enumerated products is associated with its portfolio"
  },
  {
   "id": "launch_role_constraint",
   "kind": "all_of",
   "tier": "core",
   "quote": "constrained by a dedicated launch role that grants the necessary permissions for provisioning",
   "checks": [
    {
     "kind": "ref",
     "from": "constraint",
     "to": "launch_role"
    },
    {
     "kind": "ref",
     "from": "constraint",
     "to": "product"
    }
   ]
  },
  {
   "id": "user_roles",
   "kind": "exists",
   "select": "user_role",
   "min": 2,
   "tier": "core",
   "quote": "create the corresponding IAM roles for the Service Catalog admin lead end user and the standard end user",
   "justify": "two roles stated: admin lead end user and standard end user"
  },
  {
   "id": "user_roles_read_describe",
   "kind": "any_of",
   "tier": "detail",
   "quote": "granting them appropriate read and describe permissions",
   "checks": [
    {
     "kind": "attr",
     "select": "user_role",
     "cond": {
      "path": [
       "*"
      ],
      "op": "regex",
      "value": "(?i)(servicecatalog|cloudformation):(Describe|List|Get)"
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
         "PolicyDocument"
        ],
        "op": "regex",
        "value": "(?i)(servicecatalog|cloudformation):(Describe|List|Get)"
       }
      ]
     },
     "to": "user_role"
    }
   ]
  },
  {
   "id": "user_roles_ssm_mlworkshop",
   "kind": "any_of",
   "tier": "core",
   "quote": "access to specific SSM parameters under the MLWorkshop path",
   "checks": [
    {
     "kind": "attr",
     "select": "user_role",
     "cond": {
      "path": [
       "*"
      ],
      "op": "regex",
      "value": "(?i)parameter/MLWorkshop"
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
         "PolicyDocument"
        ],
        "op": "regex",
        "value": "(?i)parameter/MLWorkshop"
       }
      ]
     },
     "to": "user_role"
    }
   ]
  },
  {
   "id": "user_roles_s3_tagged_objects",
   "kind": "any_of",
   "tier": "detail",
   "quote": "S3 objects tagged for provisioning",
   "checks": [
    {
     "kind": "attr",
     "select": "user_role",
     "cond": {
      "path": [
       "*"
      ],
      "op": "regex",
      "value": "(?i)ExistingObjectTag|ResourceTag|RequestObjectTag"
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
         "PolicyDocument"
        ],
        "op": "regex",
        "value": "(?i)ExistingObjectTag|ResourceTag|RequestObjectTag"
       }
      ]
     },
     "to": "user_role"
    }
   ]
  },
  {
   "id": "principal_associations",
   "kind": "exists",
   "select": "principal_assoc",
   "min": 2,
   "tier": "core",
   "quote": "associate these roles as principals to the correct portfolios",
   "justify": "both stated user roles are associated as principals"
  },
  {
   "id": "principal_association_links",
   "kind": "all_of",
   "tier": "detail",
   "quote": "associate these roles as principals to the correct portfolios",
   "checks": [
    {
     "kind": "ref",
     "from": "principal_assoc",
     "to": "user_role"
    },
    {
     "kind": "ref",
     "from": "principal_assoc",
     "to": "portfolio"
    }
   ]
  },
  {
   "id": "s3_root_url_parameter",
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
    "op": "eq",
    "value": "https://aws-service-catalog-reference-architectures.s3.amazonaws.com/blog_content/securing-third-party-data-and-ml-apps"
   },
   "tier": "core",
   "quote": "with a default value of https://aws-service-catalog-reference-architectures.s3.amazonaws.com/blog_content/securing-third-party-data-and-ml-apps"
  },
  {
   "id": "environment_prefix_parameter",
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
    "op": "eq",
    "value": "user-1"
   },
   "tier": "core",
   "quote": "an environment prefix that defaults to user-1"
  },
  {
   "id": "switch_role_outputs",
   "kind": "exists",
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
      "value": "(?i)signin\\.aws\\.amazon\\.com/switchrole"
     }
    ]
   },
   "min": 2,
   "tier": "detail",
   "quote": "output the switch role URLs for both the lead end user and the developer end user"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
