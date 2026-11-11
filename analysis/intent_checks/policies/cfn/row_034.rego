package intent.cfn.row_034

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "svc": {
   "types": [
    "AWS::AppRunner::Service"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "service",
   "kind": "exists",
   "select": "svc",
   "tier": "core",
   "quote": "creates an AWS App Runner service"
  },
  {
   "id": "image_hello_app",
   "kind": "attr",
   "select": "svc",
   "cond": {
    "path": [
     "SourceConfiguration",
     "ImageRepository",
     "ImageIdentifier"
    ],
    "op": "regex",
    "value": "hello-app-runner"
   },
   "tier": "core",
   "quote": "the hello-app-runner sample application"
  },
  {
   "id": "image_public_ecr",
   "kind": "attr",
   "select": "svc",
   "cond": {
    "path": [
     "SourceConfiguration",
     "ImageRepository",
     "ImageRepositoryType"
    ],
    "op": "eq",
    "value": "ECR_PUBLIC"
   },
   "tier": "core",
   "quote": "latest public ECR image"
  },
  {
   "id": "image_latest",
   "kind": "attr",
   "select": "svc",
   "cond": {
    "path": [
     "SourceConfiguration",
     "ImageRepository",
     "ImageIdentifier"
    ],
    "op": "regex",
    "value": "(:latest$|hello-app-runner$)"
   },
   "tier": "detail",
   "quote": "latest public ECR image",
   "justify": "'latest' means the :latest tag or an untagged reference that resolves to it"
  },
  {
   "id": "port_8000",
   "kind": "attr",
   "select": "svc",
   "cond": {
    "path": [
     "SourceConfiguration",
     "ImageRepository",
     "ImageConfiguration",
     "Port"
    ],
    "op": "eq",
    "value": 8000
   },
   "tier": "core",
   "quote": "exposing it on port 8000"
  },
  {
   "id": "service_name",
   "kind": "attr",
   "select": "svc",
   "cond": {
    "path": [
     "ServiceName"
    ],
    "op": "eq",
    "value": "hello-app-runner"
   },
   "tier": "core",
   "quote": "the service named \"hello-app-runner\" by default"
  },
  {
   "id": "auto_deploy_off",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "svc",
     "cond": {
      "path": [
       "SourceConfiguration",
       "AutoDeploymentsEnabled"
      ],
      "op": "eq",
      "value": false
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::AppRunner::Service"
      ],
      "where": [
       {
        "path": [
         "SourceConfiguration",
         "ImageRepository",
         "ImageRepositoryType"
        ],
        "op": "eq",
        "value": "ECR_PUBLIC"
       }
      ]
     },
     "cond": {
      "path": [
       "SourceConfiguration",
       "AutoDeploymentsEnabled"
      ],
      "op": "absent"
     }
    }
   ],
   "quote": "disabling auto-deployments for this test service",
   "justify": "App Runner leaves automatic deployments off by default for an ECR Public image"
  },
  {
   "id": "endpoint_output",
   "kind": "ref",
   "from": {
    "types": [
     "__output__"
    ],
    "where": []
   },
   "to": "svc",
   "tier": "detail",
   "quote": "we need the endpoint URL as an output"
  },
  {
   "id": "endpoint_is_url",
   "kind": "attr",
   "select": {
    "types": [
     "__output__"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "value"
    ],
    "op": "regex",
    "value": "(?i)ServiceUrl"
   },
   "tier": "detail",
   "quote": "the endpoint URL as an output",
   "justify": "the endpoint URL is the service's ServiceUrl attribute, returned directly or inside a https:// string"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
