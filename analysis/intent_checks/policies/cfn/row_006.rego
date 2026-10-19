package intent.cfn.row_006

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "gn": {
   "types": [
    "AWS::NetworkManager::GlobalNetwork"
   ],
   "where": []
  },
  "cn": {
   "types": [
    "AWS::NetworkManager::CoreNetwork"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "global_network",
   "kind": "exists",
   "select": "gn",
   "tier": "core",
   "quote": "creates an AWS Cloud WAN global network"
  },
  {
   "id": "core_network_in_global_network",
   "kind": "ref",
   "from": "cn",
   "to": "gn",
   "tier": "core",
   "quote": "global network and core network"
  },
  {
   "id": "edge_locations_multi_region",
   "kind": "attr",
   "select": "cn",
   "cond": {
    "path": [
     "PolicyDocument",
     "core-network-configuration",
     "edge-locations"
    ],
    "op": "len_gte",
    "value": 2
   },
   "tier": "detail",
   "quote": "configured to support edge locations in multiple regions",
   "justify": "\"multiple regions\" implies at least 2 edge locations"
  },
  {
   "id": "segment_production",
   "kind": "attr",
   "select": "cn",
   "cond": {
    "path": [
     "PolicyDocument",
     "segments",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "production"
     },
     {
      "path": [
       "isolate-attachments"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "require-attachment-acceptance"
      ],
      "op": "falsy"
     }
    ]
   },
   "tier": "core",
   "quote": "production isolates attachments and requires no acceptance"
  },
  {
   "id": "segment_development",
   "kind": "attr",
   "select": "cn",
   "cond": {
    "path": [
     "PolicyDocument",
     "segments",
     "*",
     "name"
    ],
    "op": "eq",
    "value": "development"
   },
   "tier": "detail",
   "quote": "segments for production and development"
  },
  {
   "id": "network_function_group",
   "kind": "attr",
   "select": "cn",
   "cond": {
    "path": [
     "PolicyDocument",
     "network-function-groups",
     "*",
     "name"
    ],
    "op": "present"
   },
   "tier": "core",
   "quote": "a network function group for inspection VPCs"
  },
  {
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "cn",
     "cond": {
      "path": [
       "PolicyDocument",
       "attachment-policies",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "action"
        ],
        "op": "regex",
        "value": "network-function-group"
       },
       {
        "path": [
         "conditions"
        ],
        "op": "regex",
        "value": "(?i)tag"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "cn",
     "cond": {
      "path": [
       "PolicyDocument",
       "attachment-policies",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "action"
        ],
        "op": "regex",
        "value": "network-function-group"
       },
       {
        "path": [
         "condition"
        ],
        "op": "regex",
        "value": "(?i)tag"
       }
      ]
     }
    }
   ],
   "id": "attachment_policy_tag_to_nfg",
   "tier": "core",
   "quote": "attachment policies that tag-match inspection VPCs"
  },
  {
   "id": "attachment_policy_domain_tag",
   "kind": "any_of",
   "tier": "detail",
   "quote": "associate segments based on a domain tag",
   "checks": [
    {
     "kind": "attr",
     "select": "cn",
     "cond": {
      "path": [
       "PolicyDocument",
       "attachment-policies",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "action",
         "association-method"
        ],
        "op": "eq",
        "value": "tag"
       },
       {
        "path": [
         "action",
         "tag-value-of-key"
        ],
        "op": "eq",
        "value": "domain"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "cn",
     "cond": {
      "path": [
       "PolicyDocument",
       "attachment-policies",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "conditions",
         "*",
         "key"
        ],
        "op": "eq",
        "value": "domain"
       },
       {
        "path": [
         "action",
         "segment"
        ],
        "op": "present"
       }
      ]
     }
    }
   ]
  },
  {
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "cn",
     "cond": {
      "path": [
       "PolicyDocument",
       "segment-actions",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "segment"
        ],
        "op": "eq",
        "value": "production"
       },
       {
        "path": [
         "via"
        ],
        "op": "regex",
        "value": "network-function-group"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "cn",
     "cond": {
      "path": [
       "PolicyDocument",
       "segment-actions",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "segment"
        ],
        "op": "eq",
        "value": "production"
       },
       {
        "path": [
         "send-via"
        ],
        "op": "regex",
        "value": "network-function-group"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "cn",
     "cond": {
      "path": [
       "PolicyDocument",
       "segment-actions",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "segment"
        ],
        "op": "eq",
        "value": "production"
       },
       {
        "path": [
         "destination"
        ],
        "op": "present"
       }
      ]
     }
    }
   ],
   "id": "segment_action_production_via_nfg",
   "tier": "core",
   "quote": "route traffic from both production and development segments through the inspection VPCs"
  },
  {
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "cn",
     "cond": {
      "path": [
       "PolicyDocument",
       "segment-actions",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "segment"
        ],
        "op": "eq",
        "value": "development"
       },
       {
        "path": [
         "via"
        ],
        "op": "regex",
        "value": "network-function-group"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "cn",
     "cond": {
      "path": [
       "PolicyDocument",
       "segment-actions",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "segment"
        ],
        "op": "eq",
        "value": "development"
       },
       {
        "path": [
         "send-via"
        ],
        "op": "regex",
        "value": "network-function-group"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "cn",
     "cond": {
      "path": [
       "PolicyDocument",
       "segment-actions",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "segment"
        ],
        "op": "eq",
        "value": "development"
       },
       {
        "path": [
         "destination"
        ],
        "op": "present"
       }
      ]
     }
    }
   ],
   "id": "segment_action_development_via_nfg",
   "tier": "detail",
   "quote": "route traffic from both production and development segments through the inspection VPCs"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
