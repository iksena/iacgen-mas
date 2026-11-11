package intent.cfn.row_040

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
  "cr": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "regex",
     "value": "^(AWS::CloudFormation::CustomResource|Custom::.+)$"
    },
    {
     "path": [
      "gated"
     ],
     "op": "eq",
     "value": false
    }
   ]
  },
  "role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "iotpol": {
   "types": [
    "AWS::IoT::Policy"
   ],
   "where": []
  },
  "out": {
   "types": [
    "__output__"
   ],
   "where": []
  },
  "out_name": {
   "types": [
    "__output__"
   ],
   "where": [
    {
     "path": [
      "value",
      "attr"
     ],
     "op": "none_eq",
     "value": "Arn"
    },
    {
     "path": [
      "value",
      "attr"
     ],
     "op": "none_eq",
     "value": "PolicyArn"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "lambda",
   "tier": "core",
   "quote": "a Lambda-backed custom resource",
   "kind": "exists",
   "select": "fn"
  },
  {
   "id": "runtime",
   "tier": "core",
   "quote": "running Node.js 24.x",
   "kind": "attr",
   "select": "fn",
   "cond": {
    "path": [
     "Runtime"
    ],
    "op": "eq",
    "value": "nodejs24.x"
   }
  },
  {
   "id": "custom_resource",
   "tier": "core",
   "quote": "a Lambda-backed custom resource",
   "kind": "exists",
   "select": "cr"
  },
  {
   "id": "custom_uses_fn",
   "tier": "core",
   "quote": "a Lambda-backed custom resource",
   "kind": "ref",
   "from": "cr",
   "to": "fn"
  },
  {
   "id": "connect",
   "tier": "core",
   "quote": "allows devices to connect",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "iotpol",
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "iot:Connect"
     }
    },
    {
     "kind": "attr",
     "select": "fn",
     "cond": {
      "path": [
       "Code",
       "ZipFile"
      ],
      "op": "regex",
      "value": "(?i)iot:(Connect|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": "cr",
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)iot:(Connect|\\*)"
     }
    }
   ]
  },
  {
   "id": "publish",
   "tier": "core",
   "quote": "publish",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "iotpol",
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "iot:Publish"
     }
    },
    {
     "kind": "attr",
     "select": "fn",
     "cond": {
      "path": [
       "Code",
       "ZipFile"
      ],
      "op": "regex",
      "value": "(?i)iot:(Publish|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": "cr",
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)iot:(Publish|\\*)"
     }
    }
   ]
  },
  {
   "id": "subscribe",
   "tier": "core",
   "quote": "subscribe to topics",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "iotpol",
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "iot:Subscribe"
     }
    },
    {
     "kind": "attr",
     "select": "fn",
     "cond": {
      "path": [
       "Code",
       "ZipFile"
      ],
      "op": "regex",
      "value": "(?i)iot:(Subscribe|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": "cr",
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)iot:(Subscribe|\\*)"
     }
    }
   ]
  },
  {
   "id": "thing_scoped",
   "tier": "core",
   "quote": "scoped to their own thing name",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "iotpol",
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "contains",
      "value": "ThingName"
     }
    },
    {
     "kind": "attr",
     "select": "fn",
     "cond": {
      "path": [
       "Code",
       "ZipFile"
      ],
      "op": "contains",
      "value": "ThingName"
     }
    },
    {
     "kind": "attr",
     "select": "cr",
     "cond": {
      "path": [
       "properties"
      ],
      "op": "contains",
      "value": "ThingName"
     }
    }
   ]
  },
  {
   "id": "output",
   "tier": "detail",
   "quote": "the template should output the generated policy name",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "out_name",
     "to": "cr"
    },
    {
     "kind": "ref",
     "from": "out_name",
     "to": "iotpol"
    }
   ]
  },
  {
   "id": "fn_role_create_policy",
   "tier": "extra",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
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
      "value": "iot:CreatePolicy"
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
      "value": "iot:CreatePolicy"
     }
    }
   ]
  },
  {
   "id": "role_trust_lambda",
   "tier": "extra",
   "kind": "attr",
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
    "value": "lambda.amazonaws.com"
   }
  },
  {
   "id": "basic_exec",
   "tier": "extra",
   "kind": "attr",
   "select": "role",
   "cond": {
    "path": [
     "ManagedPolicyArns",
     "*"
    ],
    "op": "regex",
    "value": "service-role/AWSLambdaBasicExecutionRole$"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
