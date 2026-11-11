package intent.cfn.row_068

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "app": {
   "types": [
    "AWS::AppConfig::Application"
   ],
   "where": [
    {
     "path": [
      "Name"
     ],
     "op": "eq",
     "value": "ConfigSourceDemo"
    }
   ]
  },
  "env": {
   "types": [
    "AWS::AppConfig::Environment"
   ],
   "where": [
    {
     "path": [
      "Name"
     ],
     "op": "eq",
     "value": "Sandbox"
    }
   ]
  },
  "prof": {
   "types": [
    "AWS::AppConfig::ConfigurationProfile"
   ],
   "where": [
    {
     "path": [
      "Name"
     ],
     "op": "eq",
     "value": "json-profile"
    }
   ]
  },
  "ver": {
   "types": [
    "AWS::AppConfig::HostedConfigurationVersion"
   ],
   "where": []
  },
  "strat": {
   "types": [
    "AWS::AppConfig::DeploymentStrategy"
   ],
   "where": [
    {
     "path": [
      "Name"
     ],
     "op": "eq",
     "value": "Demo Strategy"
    }
   ]
  },
  "dep": {
   "types": [
    "AWS::AppConfig::Deployment"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "application",
   "kind": "exists",
   "select": "app",
   "tier": "core",
   "quote": "an AWS AppConfig application named ConfigSourceDemo"
  },
  {
   "id": "environment",
   "kind": "exists",
   "select": "env",
   "tier": "core",
   "quote": "with a Sandbox environment"
  },
  {
   "id": "env_in_app",
   "kind": "ref",
   "from": "env",
   "to": "app",
   "tier": "detail",
   "quote": "with a Sandbox environment"
  },
  {
   "id": "profile",
   "kind": "exists",
   "select": "prof",
   "tier": "core",
   "quote": "a hosted configuration profile named json-profile"
  },
  {
   "id": "profile_hosted",
   "kind": "attr",
   "select": "prof",
   "cond": {
    "path": [
     "LocationUri"
    ],
    "op": "eq",
    "value": "hosted"
   },
   "tier": "core",
   "quote": "a hosted configuration profile"
  },
  {
   "id": "profile_in_app",
   "kind": "ref",
   "from": "prof",
   "to": "app",
   "tier": "detail",
   "quote": "a hosted configuration profile named json-profile"
  },
  {
   "id": "version",
   "kind": "exists",
   "select": "ver",
   "tier": "core",
   "quote": "a hosted configuration version"
  },
  {
   "id": "version_content",
   "kind": "attr",
   "select": "ver",
   "cond": {
    "path": [
     "Content"
    ],
    "op": "regex",
    "value": "\\\"?interestRate\\\"?\\s*:\\s*0\\.15([^0-9]|$)"
   },
   "tier": "core",
   "quote": "containing the JSON data {\"interestRate\": 0.15}"
  },
  {
   "id": "version_content_type",
   "kind": "attr",
   "select": "ver",
   "cond": {
    "path": [
     "ContentType"
    ],
    "op": "eq",
    "value": "application/json"
   },
   "tier": "core",
   "quote": "using content type application/json"
  },
  {
   "id": "version_of_profile",
   "kind": "ref",
   "from": "ver",
   "to": "prof",
   "tier": "detail",
   "quote": "a hosted configuration version containing the JSON data"
  },
  {
   "id": "strategy",
   "kind": "exists",
   "select": "strat",
   "tier": "core",
   "quote": "a deployment strategy called Demo Strategy"
  },
  {
   "id": "strategy_duration",
   "kind": "attr",
   "select": "strat",
   "cond": {
    "path": [
     "DeploymentDurationInMinutes"
    ],
    "op": "eq",
    "value": 1
   },
   "tier": "core",
   "quote": "a 1-minute duration"
  },
  {
   "id": "strategy_growth",
   "kind": "attr",
   "select": "strat",
   "cond": {
    "path": [
     "GrowthFactor"
    ],
    "op": "eq",
    "value": 100
   },
   "tier": "core",
   "quote": "100% growth factor"
  },
  {
   "id": "strategy_no_bake",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "strat",
     "cond": {
      "path": [
       "FinalBakeTimeInMinutes"
      ],
      "op": "eq",
      "value": 0
     }
    },
    {
     "kind": "attr",
     "select": "strat",
     "cond": {
      "path": [
       "FinalBakeTimeInMinutes"
      ],
      "op": "absent"
     }
    }
   ],
   "tier": "core",
   "quote": "no final bake time",
   "justify": "no final bake time = 0 minutes (the AppConfig default)"
  },
  {
   "id": "deployment",
   "kind": "exists",
   "select": "dep",
   "tier": "core",
   "quote": "a deployment of this configuration version to the Sandbox environment"
  },
  {
   "id": "deployment_env",
   "kind": "ref",
   "from": "dep",
   "to": "env",
   "tier": "core",
   "quote": "to the Sandbox environment"
  },
  {
   "id": "deployment_version",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "dep",
     "to": "ver"
    },
    {
     "kind": "attr",
     "select": "dep",
     "cond": {
      "path": [
       "ConfigurationVersion"
      ],
      "op": "eq",
      "value": "1"
     }
    }
   ],
   "tier": "core",
   "quote": "a deployment of this configuration version",
   "justify": "the first hosted configuration version is number 1, so a literal 1 names it"
  },
  {
   "id": "deployment_strategy",
   "kind": "ref",
   "from": "dep",
   "to": "strat",
   "tier": "detail",
   "quote": "a deployment strategy called Demo Strategy"
  },
  {
   "id": "x_replicate_none",
   "kind": "attr",
   "tier": "extra",
   "select": "strat",
   "cond": {
    "path": [
     "ReplicateTo"
    ],
    "op": "eq",
    "value": "NONE"
   }
  },
  {
   "id": "x_dep_profile",
   "kind": "ref",
   "tier": "extra",
   "from": "dep",
   "to": "prof"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
