# GENERATED from specs/cfn/row_138.json by intent_checks/build.py -- do not edit.
package intent.cfn.row_138

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "channel": {
   "types": [
    "AWS::MediaPackage::Channel"
   ],
   "where": []
  },
  "hls_ep": {
   "types": [
    "AWS::MediaPackage::OriginEndpoint"
   ],
   "where": [
    {
     "path": [
      "HlsPackage"
     ],
     "op": "present"
    }
   ]
  },
  "decl_dash_ep": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::MediaPackage::OriginEndpoint"
    },
    {
     "path": [
      "properties",
      "DashPackage"
     ],
     "op": "present"
    }
   ]
  },
  "param": {
   "types": [
    "__parameter__"
   ],
   "where": []
  },
  "mp_role": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::IAM::Role"
    },
    {
     "path": [
      "properties",
      "AssumeRolePolicyDocument"
     ],
     "op": "contains",
     "value": "mediapackage.amazonaws.com"
    }
   ]
  },
  "output_type_param": {
   "types": [
    "__parameter__"
   ],
   "where": [
    {
     "path": [
      "default"
     ],
     "op": "eq",
     "value": "APPLE_HLS"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "channel_exists",
   "kind": "exists",
   "select": "channel",
   "tier": "core",
   "quote": "creates a MediaPackage channel for live streaming"
  },
  {
   "id": "hls_endpoint_on_channel",
   "kind": "ref",
   "from": "hls_ep",
   "to": "channel",
   "tier": "core",
   "quote": "HLS and DASH origin endpoints"
  },
  {
   "id": "dash_endpoint_declared",
   "kind": "exists",
   "select": "decl_dash_ep",
   "tier": "core",
   "quote": "HLS and DASH origin endpoints"
  },
  {
   "id": "dash_segment_duration_2",
   "kind": "attr",
   "select": "decl_dash_ep",
   "tier": "core",
   "quote": "the DASH endpoint always uses a hardcoded segment duration of 2 seconds",
   "cond": {
    "path": [
     "properties",
     "DashPackage",
     "SegmentDurationSeconds"
    ],
    "op": "eq",
    "value": 2
   }
  },
  {
   "id": "hls_segment_duration_parameter",
   "kind": "join",
   "tier": "detail",
   "from": "hls_ep",
   "from_path": [
    "HlsPackage",
    "SegmentDurationSeconds"
   ],
   "to": "param",
   "to_path": [
    "default"
   ],
   "quote": "the HLS endpoint uses a user-specified segment duration parameter"
  },
  {
   "id": "origination_allow_without_archive",
   "kind": "any_of",
   "tier": "detail",
   "quote": "origination is set to DENY if a user-provided ArchiveBucket parameter is supplied",
   "checks": [
    {
     "kind": "attr",
     "select": "hls_ep",
     "cond": {
      "path": [
       "Origination"
      ],
      "op": "eq",
      "value": "ALLOW"
     }
    },
    {
     "kind": "attr",
     "select": "hls_ep",
     "cond": {
      "path": [
       "Origination"
      ],
      "op": "absent"
     }
    }
   ],
   "justify": "DENY only when ArchiveBucket is supplied; with the empty default origination stays ALLOW (the service default)"
  },
  {
   "id": "archive_bucket_parameter",
   "kind": "attr",
   "select": "param",
   "tier": "detail",
   "quote": "a user-provided ArchiveBucket parameter",
   "cond": {
    "path": [
     "name"
    ],
    "op": "regex",
    "value": "(?i)^archive_?bucket"
   }
  },
  {
   "id": "vod_source_bucket_parameter",
   "kind": "attr",
   "select": "param",
   "tier": "detail",
   "quote": "a user-provided VodSourceBucket for source content",
   "cond": {
    "path": [
     "name"
    ],
    "op": "regex",
    "value": "(?i)^vod_?source_?bucket"
   }
  },
  {
   "id": "vod_workflow_declared",
   "kind": "exists",
   "tier": "core",
   "quote": "optionally provisions VOD workflows",
   "select": {
    "types": [
     "__declared__"
    ],
    "where": [
     {
      "path": [
       "type"
      ],
      "op": "in",
      "value": [
       "AWS::MediaPackage::PackagingGroup",
       "AWS::MediaPackage::Asset",
       "AWS::MediaPackage::PackagingConfiguration"
      ]
     }
    ]
   }
  },
  {
   "id": "mediapackage_role",
   "kind": "exists",
   "select": "mp_role",
   "tier": "core",
   "quote": "the IAM role necessary for MediaPackage to access those buckets"
  },
  {
   "id": "vod_asset_uses_role",
   "kind": "ref",
   "tier": "detail",
   "quote": "the IAM role necessary for MediaPackage to access those buckets",
   "from": {
    "types": [
     "__declared__"
    ],
    "where": [
     {
      "path": [
       "type"
      ],
      "op": "eq",
      "value": "AWS::MediaPackage::Asset"
     }
    ]
   },
   "to": "mp_role"
  },
  {
   "id": "output_type_default_apple_hls",
   "kind": "all_of",
   "tier": "detail",
   "quote": "specifying the output type (defaulting to APPLE_HLS, with ISO_DASH and ALL also supported)",
   "checks": [
    {
     "kind": "attr",
     "select": "output_type_param",
     "cond": {
      "path": [
       "allowed_values",
       "*"
      ],
      "op": "eq",
      "value": "ISO_DASH"
     }
    },
    {
     "kind": "attr",
     "select": "output_type_param",
     "cond": {
      "path": [
       "allowed_values",
       "*"
      ],
      "op": "eq",
      "value": "ALL"
     }
    }
   ]
  },
  {
   "id": "manifest_name_parameter",
   "kind": "join",
   "tier": "detail",
   "from": "hls_ep",
   "from_path": [
    "ManifestName"
   ],
   "to": "param",
   "to_path": [
    "default"
   ],
   "quote": "manifest name"
  },
  {
   "id": "startover_window_parameter",
   "kind": "join",
   "tier": "detail",
   "from": "hls_ep",
   "from_path": [
    "StartoverWindowSeconds"
   ],
   "to": "param",
   "to_path": [
    "default"
   ],
   "quote": "startover window in seconds"
  },
  {
   "id": "environment_tag",
   "kind": "attr",
   "select": "channel",
   "tier": "detail",
   "quote": "tagging with environment and custom key-value tags",
   "cond": {
    "path": [
     "Tags",
     "*",
     "Key"
    ],
    "op": "regex",
    "value": "(?i)^env"
   },
   "justify": "an environment tag is keyed environment/env"
  },
  {
   "id": "custom_tag",
   "kind": "any_of",
   "tier": "detail",
   "quote": "tagging with environment and custom key-value tags",
   "justify": "an environment tag plus a custom key-value tag = at least two tags, or a parameter for the custom tag (empty by default)",
   "checks": [
    {
     "kind": "attr",
     "select": "channel",
     "cond": {
      "path": [
       "Tags"
      ],
      "op": "len_gte",
      "value": 2
     }
    },
    {
     "kind": "attr",
     "select": "param",
     "cond": {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)(custom_?tag|tag_?key)"
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
