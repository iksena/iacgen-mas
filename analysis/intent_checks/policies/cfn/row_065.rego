package intent.cfn.row_065

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "ch": {
   "types": [
    "AWS::IVS::Channel"
   ],
   "where": []
  },
  "sk": {
   "types": [
    "AWS::IVS::StreamKey"
   ],
   "where": []
  },
  "param": {
   "types": [
    "__parameter__"
   ],
   "where": []
  },
  "out": {
   "types": [
    "__output__"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "ivs_channel",
   "kind": "exists",
   "select": "ch",
   "tier": "core",
   "quote": "creates an AWS IVS channel"
  },
  {
   "id": "stream_key_for_channel",
   "kind": "ref",
   "from": "sk",
   "to": "ch",
   "tier": "core",
   "quote": "associated stream key for live streaming"
  },
  {
   "id": "latency_low",
   "kind": "attr",
   "select": "ch",
   "cond": {
    "path": [
     "LatencyMode"
    ],
    "op": "eq",
    "value": "LOW"
   },
   "tier": "core",
   "quote": "configurable latency mode (default LOW)"
  },
  {
   "id": "type_standard",
   "kind": "attr",
   "select": "ch",
   "cond": {
    "path": [
     "Type"
    ],
    "op": "eq",
    "value": "STANDARD"
   },
   "tier": "core",
   "quote": "channel type (default STANDARD)"
  },
  {
   "id": "authorized_false",
   "kind": "attr",
   "select": "ch",
   "cond": {
    "path": [
     "Authorized"
    ],
    "op": "falsy"
   },
   "tier": "core",
   "quote": "authorization flag (default false)"
  },
  {
   "id": "configurable_parameters",
   "kind": "all_of",
   "tier": "detail",
   "quote": "with configurable latency mode (default LOW), channel type (default STANDARD), and authorization flag (default false)",
   "checks": [
    {
     "kind": "attr",
     "select": "param",
     "cond": {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "LOW"
     }
    },
    {
     "kind": "attr",
     "select": "param",
     "cond": {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "STANDARD"
     }
    },
    {
     "kind": "attr",
     "select": "param",
     "cond": {
      "path": [
       "default"
      ],
      "op": "falsy"
     }
    }
   ]
  },
  {
   "id": "name_prefix_ivs",
   "kind": "any_of",
   "tier": "detail",
   "quote": "using a logical name prefix of \"IVS\"",
   "checks": [
    {
     "kind": "attr",
     "select": "ch",
     "cond": {
      "path": [
       "Name"
      ],
      "op": "regex",
      "value": "^IVS"
     }
    },
    {
     "kind": "exists",
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
        "value": "AWS::IVS::Channel"
       },
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "^IVS"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "param",
     "cond": {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "IVS"
     }
    }
   ]
  },
  {
   "id": "environment_tag",
   "kind": "attr",
   "select": {
    "types": [
     "AWS::IVS::Channel",
     "AWS::IVS::StreamKey"
    ],
    "where": []
   },
   "quantifier": "all",
   "cond": {
    "path": [
     "Tags",
     "*",
     "Key"
    ],
    "op": "eq",
    "value": "environment"
   },
   "tier": "detail",
   "quote": "tagging resources with an environment tag"
  },
  {
   "id": "custom_tag",
   "kind": "attr",
   "select": {
    "types": [
     "AWS::IVS::Channel",
     "AWS::IVS::StreamKey"
    ],
    "where": []
   },
   "quantifier": "all",
   "cond": {
    "path": [
     "Tags"
    ],
    "op": "len_gte",
    "value": 2
   },
   "tier": "detail",
   "quote": "custom key-value pair",
   "justify": "an environment tag plus a custom key-value pair = at least 2 tags"
  },
  {
   "id": "output_ingest_endpoint",
   "kind": "attr",
   "select": "out",
   "cond": {
    "path": [
     "value",
     "attr"
    ],
    "op": "eq",
    "value": "IngestEndpoint"
   },
   "tier": "detail",
   "quote": "outputting the ingest endpoint"
  },
  {
   "id": "output_playback_url",
   "kind": "attr",
   "select": "out",
   "cond": {
    "path": [
     "value",
     "attr"
    ],
    "op": "eq",
    "value": "PlaybackUrl"
   },
   "tier": "detail",
   "quote": "playback URL"
  },
  {
   "id": "output_stream_key_value",
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
      "value": "Value"
     }
    ]
   },
   "to": "sk",
   "tier": "detail",
   "quote": "stream key value"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
