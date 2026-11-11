package intent.cfn.row_174

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "app": {
   "types": [
    "AWS::ElasticBeanstalk::Application"
   ],
   "where": []
  },
  "env": {
   "types": [
    "AWS::ElasticBeanstalk::Environment"
   ],
   "where": []
  },
  "appver": {
   "types": [
    "AWS::ElasticBeanstalk::ApplicationVersion"
   ],
   "where": []
  },
  "d_env": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::ElasticBeanstalk::Environment"
    }
   ]
  },
  "d_app": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::ElasticBeanstalk::Application"
    }
   ]
  },
  "vpc": {
   "types": [
    "AWS::EC2::VPC"
   ],
   "where": []
  },
  "route": {
   "types": [
    "AWS::EC2::Route"
   ],
   "where": [
    {
     "path": [
      "DestinationCidrBlock"
     ],
     "op": "eq",
     "value": "0.0.0.0/0"
    }
   ]
  },
  "ec2_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "contains",
     "value": "ec2.amazonaws.com"
    }
   ]
  },
  "eb_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "contains",
     "value": "elasticbeanstalk.amazonaws.com"
    }
   ]
  },
  "d_appver": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::ElasticBeanstalk::ApplicationVersion"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "beanstalk_application",
   "kind": "exists",
   "select": "d_app",
   "tier": "core",
   "quote": "create a new application and environment"
  },
  {
   "id": "beanstalk_environment",
   "kind": "exists",
   "select": "d_env",
   "tier": "core",
   "quote": "creates an Elastic Beanstalk environment"
  },
  {
   "id": "env_in_application",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "d_env",
     "to": "d_app"
    },
    {
     "kind": "join",
     "from": "d_env",
     "from_path": [
      "properties",
      "ApplicationName"
     ],
     "to": "d_app",
     "to_path": [
      "properties",
      "ApplicationName"
     ]
    }
   ],
   "tier": "core",
   "quote": "create a new application and environment"
  },
  {
   "id": "create_new_or_reference_env",
   "kind": "attr",
   "select": "d_env",
   "cond": {
    "path": [
     "gated"
    ],
    "op": "truthy"
   },
   "tier": "core",
   "quote": "allowing the user to either create a new application and environment or reference existing ones",
   "quantifier": "all"
  },
  {
   "id": "create_new_or_reference_app",
   "kind": "attr",
   "select": "d_app",
   "cond": {
    "path": [
     "gated"
    ],
    "op": "truthy"
   },
   "tier": "core",
   "quote": "allowing the user to either create a new application and environment or reference existing ones",
   "quantifier": "all"
  },
  {
   "id": "default_application_name",
   "kind": "attr",
   "select": "d_app",
   "cond": {
    "path": [
     "properties",
     "ApplicationName"
    ],
    "op": "present"
   },
   "tier": "detail",
   "quote": "use a default application name and environment name"
  },
  {
   "id": "default_environment_name",
   "kind": "attr",
   "select": "d_env",
   "cond": {
    "path": [
     "properties",
     "EnvironmentName"
    ],
    "op": "present"
   },
   "tier": "detail",
   "quote": "use a default application name and environment name"
  },
  {
   "id": "modern_solution_stack",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "d_env",
     "cond": {
      "path": [
       "properties",
       "SolutionStackName"
      ],
      "op": "regex",
      "value": "(?i)(amazon linux 2023|windows server (core )?20(19|22|25))"
     }
    },
    {
     "kind": "attr",
     "select": "d_env",
     "cond": {
      "path": [
       "properties",
       "PlatformArn"
      ],
      "op": "regex",
      "value": "(?i)(amazon linux 2023|windows server (core )?20(19|22|25))"
     }
    },
    {
     "kind": "attr",
     "select": "d_env",
     "cond": {
      "path": [
       "properties",
       "PlatformArn",
       "ref"
      ],
      "op": "present"
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
        "value": "AWS::ElasticBeanstalk::ConfigurationTemplate"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "SolutionStackName"
      ],
      "op": "regex",
      "value": "(?i)(amazon linux 2023|windows server (core )?20(19|22|25))"
     }
    }
   ],
   "tier": "core",
   "quote": "launch with a modern supported solution stack appropriate for the application",
   "justify": "modern supported means a current platform generation (Amazon Linux 2023 or Windows Server 2019+); Amazon Linux 2 reached end of support in June 2026"
  },
  {
   "id": "sample_application_version",
   "kind": "exists",
   "select": "d_appver",
   "tier": "core",
   "quote": "deploy a sample application from a default S3 bucket"
  },
  {
   "id": "sample_bundle_bucket",
   "kind": "attr",
   "select": "d_appver",
   "cond": {
    "path": [
     "properties",
     "SourceBundle",
     "S3Bucket"
    ],
    "op": "present"
   },
   "tier": "core",
   "quote": "deploy a sample application from a default S3 bucket"
  },
  {
   "id": "sample_bundle_key",
   "kind": "attr",
   "select": "d_appver",
   "cond": {
    "path": [
     "properties",
     "SourceBundle",
     "S3Key"
    ],
    "op": "present"
   },
   "tier": "detail",
   "quote": "deploy a sample application from a default S3 bucket"
  },
  {
   "id": "bucket_with_region",
   "kind": "attr",
   "select": "d_appver",
   "cond": {
    "path": [
     "properties",
     "SourceBundle",
     "S3Bucket"
    ],
    "op": "contains",
    "value": "us-east-1"
   },
   "tier": "core",
   "quote": "appending the current region to the bucket name only when using that default bucket",
   "justify": "current region appended to the default bucket name (us-east-1 here)"
  },
  {
   "id": "bucket_override_parameter",
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
      "value": "(?i)bucket"
     }
    ]
   },
   "tier": "detail",
   "quote": "only when using that default bucket"
  },
  {
   "id": "env_uses_version",
   "kind": "ref",
   "from": "d_env",
   "to": "d_appver",
   "tier": "detail",
   "quote": "deploy a sample application from a default S3 bucket"
  },
  {
   "id": "green_environment_capability",
   "kind": "any_of",
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
         "name"
        ],
        "op": "regex",
        "value": "(?i)green"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "d_env",
     "cond": {
      "path": [
       "properties",
       "EnvironmentName"
      ],
      "op": "regex",
      "value": "(?i)green"
     }
    }
   ],
   "tier": "detail",
   "quote": "generate a temporary green environment for traffic routing during updates"
  },
  {
   "id": "x_env_vpc_options",
   "kind": "attr",
   "select": "d_env",
   "cond": {
    "path": [
     "properties",
     "OptionSettings",
     "*",
     "Namespace"
    ],
    "op": "eq",
    "value": "aws:ec2:vpc"
   },
   "tier": "extra"
  },
  {
   "id": "x_env_instance_profile",
   "kind": "attr",
   "select": "d_env",
   "cond": {
    "path": [
     "properties",
     "OptionSettings",
     "*",
     "OptionName"
    ],
    "op": "eq",
    "value": "IamInstanceProfile"
   },
   "tier": "extra"
  },
  {
   "id": "x_env_service_role",
   "kind": "attr",
   "select": "d_env",
   "cond": {
    "path": [
     "properties",
     "OptionSettings",
     "*",
     "OptionName"
    ],
    "op": "eq",
    "value": "ServiceRole"
   },
   "tier": "extra"
  },
  {
   "id": "x_vpc_dns",
   "kind": "attr",
   "select": "vpc",
   "cond": {
    "path": [
     "EnableDnsHostnames"
    ],
    "op": "eq",
    "value": "true"
   },
   "tier": "extra"
  },
  {
   "id": "x_default_route",
   "kind": "exists",
   "select": "route",
   "tier": "extra",
   "min": 1
  },
  {
   "id": "x_ec2_role",
   "kind": "exists",
   "select": "ec2_role",
   "tier": "extra",
   "min": 1
  },
  {
   "id": "x_eb_service_role",
   "kind": "exists",
   "select": "eb_role",
   "tier": "extra",
   "min": 1
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
   "id": "extra_type_aws_ec2_vpcgatewayattachment",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::EC2::VPCGatewayAttachment"
    ],
    "where": []
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
