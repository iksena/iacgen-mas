package intent.cfn.row_013

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "trk": {
   "types": [
    "AWS::Location::Tracker"
   ],
   "where": []
  },
  "gc": {
   "types": [
    "AWS::Location::GeofenceCollection"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "tracker",
   "kind": "exists",
   "select": "trk",
   "tier": "core",
   "quote": "an Amazon Location Service tracker"
  },
  {
   "id": "geofence_collection",
   "kind": "exists",
   "select": "gc",
   "tier": "core",
   "quote": "geofence collection"
  },
  {
   "id": "tracker_name",
   "kind": "attr",
   "select": "trk",
   "cond": {
    "path": [
     "TrackerName"
    ],
    "op": "regex",
    "value": "^MyGeoTracker-123456789012$"
   },
   "tier": "core",
   "quote": "the tracker named MyGeoTracker-[account-id]",
   "justify": "the prompt asks for [account-id]; the adapter renders AWS::AccountId as 123456789012"
  },
  {
   "id": "collection_name",
   "kind": "attr",
   "select": "gc",
   "cond": {
    "path": [
     "CollectionName"
    ],
    "op": "regex",
    "value": "^MyGeofenceCollection-123456789012$"
   },
   "tier": "core",
   "quote": "the geofence collection named MyGeofenceCollection-[account-id]",
   "justify": "the prompt asks for [account-id]; the adapter renders AWS::AccountId as 123456789012"
  },
  {
   "id": "tracker_pricing",
   "kind": "any_of",
   "tier": "core",
   "quote": "both using a request-based usage pricing plan",
   "justify": "PricingPlan is deprecated and RequestBasedUsage is its only allowed value, so omitting it means the same plan",
   "checks": [
    {
     "kind": "attr",
     "select": "trk",
     "cond": {
      "path": [
       "PricingPlan"
      ],
      "op": "eq",
      "value": "RequestBasedUsage"
     }
    },
    {
     "kind": "attr",
     "select": "trk",
     "cond": {
      "path": [
       "PricingPlan"
      ],
      "op": "absent"
     }
    }
   ]
  },
  {
   "id": "collection_pricing",
   "kind": "any_of",
   "tier": "core",
   "quote": "both using a request-based usage pricing plan",
   "justify": "PricingPlan is deprecated and RequestBasedUsage is its only allowed value, so omitting it means the same plan",
   "checks": [
    {
     "kind": "attr",
     "select": "gc",
     "cond": {
      "path": [
       "PricingPlan"
      ],
      "op": "eq",
      "value": "RequestBasedUsage"
     }
    },
    {
     "kind": "attr",
     "select": "gc",
     "cond": {
      "path": [
       "PricingPlan"
      ],
      "op": "absent"
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
