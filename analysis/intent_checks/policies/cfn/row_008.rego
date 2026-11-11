package intent.cfn.row_008

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "d": {
   "types": [
    "AWS::GuardDuty::Detector"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "detector",
   "kind": "exists",
   "select": "d",
   "tier": "core",
   "quote": "creates a GuardDuty detector"
  },
  {
   "id": "enabled",
   "kind": "attr",
   "select": "d",
   "cond": {
    "path": [
     "Enable"
    ],
    "op": "truthy"
   },
   "tier": "core",
   "quote": "enabling it"
  },
  {
   "id": "frequency",
   "kind": "attr",
   "select": "d",
   "cond": {
    "path": [
     "FindingPublishingFrequency"
    ],
    "op": "eq",
    "value": "FIFTEEN_MINUTES"
   },
   "tier": "core",
   "quote": "a finding publishing frequency of fifteen minutes"
  },
  {
   "id": "s3_logs",
   "kind": "any_of",
   "tier": "core",
   "quote": "S3 logs",
   "checks": [
    {
     "kind": "attr",
     "select": "d",
     "cond": {
      "path": [
       "DataSources",
       "S3Logs",
       "Enable"
      ],
      "op": "truthy"
     },
     "quantifier": "some"
    },
    {
     "kind": "attr",
     "select": "d",
     "cond": {
      "path": [
       "Features",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Name"
        ],
        "op": "eq",
        "value": "S3_DATA_EVENTS"
       },
       {
        "path": [
         "Status"
        ],
        "op": "eq",
        "value": "ENABLED"
       }
      ]
     },
     "quantifier": "some"
    }
   ],
   "justify": "S3 logs protection = S3Logs datasource or S3_DATA_EVENTS feature"
  },
  {
   "id": "ec2_malware",
   "kind": "any_of",
   "tier": "core",
   "quote": "malware protection for EC2 instances with findings",
   "checks": [
    {
     "kind": "attr",
     "select": "d",
     "cond": {
      "path": [
       "DataSources",
       "MalwareProtection",
       "ScanEc2InstanceWithFindings",
       "EbsVolumes"
      ],
      "op": "truthy"
     },
     "quantifier": "some"
    },
    {
     "kind": "attr",
     "select": "d",
     "cond": {
      "path": [
       "Features",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Name"
        ],
        "op": "eq",
        "value": "EBS_MALWARE_PROTECTION"
       },
       {
        "path": [
         "Status"
        ],
        "op": "eq",
        "value": "ENABLED"
       }
      ]
     },
     "quantifier": "some"
    }
   ],
   "justify": "EBS_MALWARE_PROTECTION is the Features name for malware protection for EC2 instances with findings; ENABLED is its on state"
  },
  {
   "id": "k8s_audit_off",
   "kind": "any_of",
   "tier": "core",
   "quote": "disabling Kubernetes audit logs",
   "checks": [
    {
     "kind": "attr",
     "select": "d",
     "cond": {
      "path": [
       "DataSources",
       "Kubernetes",
       "AuditLogs",
       "Enable"
      ],
      "op": "falsy"
     },
     "quantifier": "some"
    },
    {
     "kind": "attr",
     "select": "d",
     "cond": {
      "path": [
       "Features",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Name"
        ],
        "op": "eq",
        "value": "EKS_AUDIT_LOGS"
       },
       {
        "path": [
         "Status"
        ],
        "op": "eq",
        "value": "DISABLED"
       }
      ]
     },
     "quantifier": "some"
    }
   ],
   "justify": "disabled feature status is DISABLED"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
