package intent.cfn.row_221

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "vpc": {
   "types": [
    "AWS::EC2::VPC"
   ],
   "where": []
  },
  "lg": {
   "types": [
    "AWS::Logs::LogGroup"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "two_vpcs",
   "kind": "exists",
   "select": "vpc",
   "tier": "core",
   "quote": "provisioning two independent VPCs",
   "min": 2
  },
  {
   "id": "vpc_cidr",
   "kind": "attr",
   "select": "vpc",
   "cond": {
    "path": [
     "CidrBlock"
    ],
    "op": "eq",
    "value": "10.0.0.0/24"
   },
   "tier": "core",
   "quote": "each configured with a \"10.0.0.0/24\" CIDR block",
   "quantifier": "all"
  },
  {
   "id": "two_log_groups",
   "kind": "exists",
   "select": "lg",
   "tier": "core",
   "quote": "two CloudWatch log groups",
   "min": 2
  },
  {
   "id": "log_groups_standard",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::Logs::LogGroup"
    ],
    "where": [
     {
      "path": [
       "LogGroupClass"
      ],
      "op": "none_eq",
      "value": "INFREQUENT_ACCESS"
     },
     {
      "path": [
       "LogGroupClass"
      ],
      "op": "none_eq",
      "value": "DELIVERY"
     }
    ]
   },
   "min": 2,
   "tier": "detail",
   "quote": "two standard CloudWatch log groups",
   "justify": "standard is the log group class; omitting it means STANDARD"
  },
  {
   "id": "export_vpc1",
   "kind": "ref",
   "from": {
    "types": [
     "__output__"
    ],
    "where": [
     {
      "path": [
       "export"
      ],
      "op": "eq",
      "value": "svcrolegensupport-AWS-Route53-HostedZone-VPC"
     },
     {
      "path": [
       "value",
       "attr"
      ],
      "op": "absent"
     }
    ]
   },
   "to": "vpc",
   "tier": "detail",
   "quote": "\"svcrolegensupport-AWS-Route53-HostedZone-VPC\""
  },
  {
   "id": "export_vpc2",
   "kind": "ref",
   "from": {
    "types": [
     "__output__"
    ],
    "where": [
     {
      "path": [
       "export"
      ],
      "op": "eq",
      "value": "svcrolegensupport-AWS-Route53-HostedZone-VPC2"
     },
     {
      "path": [
       "value",
       "attr"
      ],
      "op": "absent"
     }
    ]
   },
   "to": "vpc",
   "tier": "detail",
   "quote": "\"svcrolegensupport-AWS-Route53-HostedZone-VPC2\""
  },
  {
   "id": "export_vpcs_distinct",
   "kind": "exists",
   "select": {
    "types": [
     "__output__"
    ],
    "where": [
     {
      "path": [
       "export"
      ],
      "op": "regex",
      "value": "HostedZone-VPC2?$"
     }
    ]
   },
   "min": 2,
   "distinct_path": [
    "value"
   ],
   "tier": "detail",
   "quote": "the references for both VPCs"
  },
  {
   "id": "export_lg1",
   "kind": "ref",
   "from": {
    "types": [
     "__output__"
    ],
    "where": [
     {
      "path": [
       "export"
      ],
      "op": "eq",
      "value": "svcrolegensupport-AWS-Route53-HostedZone-LogGroup"
     }
    ]
   },
   "to": "lg",
   "tier": "detail",
   "quote": "\"svcrolegensupport-AWS-Route53-HostedZone-LogGroup\""
  },
  {
   "id": "export_lg2",
   "kind": "ref",
   "from": {
    "types": [
     "__output__"
    ],
    "where": [
     {
      "path": [
       "export"
      ],
      "op": "eq",
      "value": "svcrolegensupport-AWS-Route53-HostedZone-LogGroup2"
     }
    ]
   },
   "to": "lg",
   "tier": "detail",
   "quote": "\"svcrolegensupport-AWS-Route53-HostedZone-LogGroup2\""
  },
  {
   "id": "export_lg_arn",
   "kind": "exists",
   "select": {
    "types": [
     "__output__"
    ],
    "where": [
     {
      "path": [
       "export"
      ],
      "op": "regex",
      "value": "HostedZone-LogGroup2?$"
     },
     {
      "path": [
       "value"
      ],
      "op": "regex",
      "value": "(?i)\"attr\": \"arn\"|^arn:.*log-group"
     }
    ]
   },
   "min": 2,
   "distinct_path": [
    "value"
   ],
   "tier": "detail",
   "quote": "as well as the ARNs for both log groups",
   "justify": "both named log-group exports hold an ARN (GetAtt Arn or a built ARN string) of different log groups"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
