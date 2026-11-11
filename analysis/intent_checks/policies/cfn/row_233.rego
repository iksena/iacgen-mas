package intent.cfn.row_233

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "flow": {
   "types": [
    "AWS::MediaConnect::Flow"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "flow",
   "kind": "exists",
   "select": "flow",
   "tier": "core",
   "quote": "creates an AWS MediaConnect flow"
  },
  {
   "id": "flow_name",
   "kind": "attr",
   "select": "flow",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "eq",
    "value": "my-flow"
   },
   "tier": "core",
   "quote": "flow named \"my-flow\""
  },
  {
   "id": "source_present",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::MediaConnect::Flow"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Source"
      ],
      "op": "present"
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::MediaConnect::FlowSource"
      ],
      "where": []
     }
    }
   ],
   "tier": "core",
   "quote": "a configured source"
  },
  {
   "id": "source_name",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::MediaConnect::Flow"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Source",
       "Name"
      ],
      "op": "eq",
      "value": "my-source"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::MediaConnect::FlowSource"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Name"
      ],
      "op": "eq",
      "value": "my-source"
     }
    }
   ],
   "tier": "core",
   "quote": "a configured source named \"my-source\""
  },
  {
   "id": "source_protocol",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::MediaConnect::Flow"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Source",
       "Protocol"
      ],
      "op": "eq",
      "value": "rtp"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::MediaConnect::FlowSource"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Protocol"
      ],
      "op": "eq",
      "value": "rtp"
     }
    }
   ],
   "tier": "core",
   "quote": "using the RTP protocol"
  },
  {
   "id": "source_port",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::MediaConnect::Flow"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Source",
       "IngestPort"
      ],
      "op": "eq",
      "value": 5000
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::MediaConnect::FlowSource"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "IngestPort"
      ],
      "op": "eq",
      "value": 5000
     }
    }
   ],
   "tier": "core",
   "quote": "ingest port 5000"
  },
  {
   "id": "source_cidr",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::MediaConnect::Flow"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Source",
       "WhitelistCidr"
      ],
      "op": "eq",
      "value": "10.0.0.0/24"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::MediaConnect::FlowSource"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "WhitelistCidr"
      ],
      "op": "eq",
      "value": "10.0.0.0/24"
     }
    }
   ],
   "tier": "core",
   "quote": "allowed ingress traffic restricted to the \"10.0.0.0/24\" CIDR block"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
