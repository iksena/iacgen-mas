# GENERATED from specs/cfn/row_049.json by intent_checks/build.py -- do not edit.
package intent.cfn.row_049

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "fn": {
   "types": [
    "AWS::Lambda::Function"
   ],
   "where": []
  },
  "fn_env": {
   "types": [
    "AWS::Lambda::Function"
   ],
   "where": [
    {
     "path": [
      "Environment",
      "Variables"
     ],
     "op": "present"
    }
   ]
  },
  "version": {
   "types": [
    "AWS::Lambda::Version"
   ],
   "where": []
  },
  "alias": {
   "types": [
    "AWS::Lambda::Alias"
   ],
   "where": []
  },
  "lambda_role": {
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
     "value": "lambda.amazonaws.com"
    }
   ]
  },
  "cd_role": {
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
     "op": "regex",
     "value": "^codedeploy\\.([a-z0-9-]+\\.)?amazonaws\\.com$"
    }
   ]
  },
  "app": {
   "types": [
    "AWS::CodeDeploy::Application"
   ],
   "where": []
  },
  "dg": {
   "types": [
    "AWS::CodeDeploy::DeploymentGroup"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "main_function_env_var",
   "kind": "exists",
   "select": "fn_env",
   "tier": "core",
   "quote": "a main Lambda function with an environment variable"
  },
  {
   "id": "lambda_functions_three",
   "kind": "exists",
   "select": "fn",
   "min": 3,
   "tier": "core",
   "quote": "two validation hook Lambda functions",
   "justify": "a main function plus two hook functions = at least 3 Lambda functions"
  },
  {
   "id": "version_of_function",
   "kind": "ref",
   "from": "version",
   "to": "fn",
   "tier": "core",
   "quote": "its version and alias"
  },
  {
   "id": "alias_of_function",
   "kind": "any_of",
   "tier": "core",
   "quote": "its version and alias",
   "checks": [
    {
     "kind": "ref",
     "from": "alias",
     "to": "fn"
    },
    {
     "kind": "ref",
     "from": "alias",
     "to": "version"
    }
   ]
  },
  {
   "id": "hook_report_status_permission",
   "kind": "any_of",
   "tier": "core",
   "quote": "with permissions to report deployment status",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": []
     },
     "cond": {
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
      "value": "codedeploy:PutLifecycleEventHookExecutionStatus"
     }
    },
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
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "codedeploy:PutLifecycleEventHookExecutionStatus"
     }
    }
   ]
  },
  {
   "id": "lambda_execution_role",
   "kind": "exists",
   "select": "lambda_role",
   "tier": "detail",
   "quote": "IAM roles for Lambda execution"
  },
  {
   "id": "codedeploy_service_role",
   "kind": "exists",
   "select": "cd_role",
   "tier": "core",
   "quote": "CodeDeploy service"
  },
  {
   "id": "codedeploy_app_lambda",
   "kind": "attr",
   "select": "app",
   "cond": {
    "path": [
     "ComputePlatform"
    ],
    "op": "eq",
    "value": "Lambda"
   },
   "tier": "detail",
   "quote": "a CodeDeploy application",
   "justify": "a CodeDeploy application for a Lambda-based deployment uses the Lambda compute platform"
  },
  {
   "id": "deployment_group_of_app",
   "kind": "any_of",
   "tier": "core",
   "quote": "a CodeDeploy application with a deployment group",
   "checks": [
    {
     "kind": "ref",
     "from": "dg",
     "to": "app"
    },
    {
     "kind": "join",
     "from": "dg",
     "from_path": [
      "ApplicationName"
     ],
     "to": "app",
     "to_path": [
      "ApplicationName"
     ]
    }
   ]
  },
  {
   "id": "deployment_group_canary",
   "kind": "any_of",
   "tier": "core",
   "quote": "configured for canary traffic shifting",
   "checks": [
    {
     "kind": "attr",
     "select": "dg",
     "cond": {
      "path": [
       "DeploymentConfigName"
      ],
      "op": "regex",
      "value": "(?i)canary"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::CodeDeploy::DeploymentConfig"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "TrafficRoutingConfig",
       "Type"
      ],
      "op": "eq",
      "value": "TimeBasedCanary"
     }
    }
   ]
  },
  {
   "id": "deployment_group_service_role",
   "kind": "ref",
   "from": "dg",
   "to": "cd_role",
   "tier": "detail",
   "quote": "IAM roles for Lambda execution and CodeDeploy service"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
