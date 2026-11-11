package intent.cfn.row_154

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "zone": {
   "types": [
    "AWS::Route53::HostedZone"
   ],
   "where": []
  },
  "grp": {
   "types": [
    "AWS::Route53::RecordSetGroup"
   ],
   "where": []
  },
  "rs": {
   "types": [
    "AWS::Route53::RecordSet"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "zone",
   "tier": "core",
   "kind": "exists",
   "select": "zone",
   "quote": "creates a Route 53 public hosted zone for the domain passengerlist.org"
  },
  {
   "id": "zone_name",
   "tier": "core",
   "kind": "attr",
   "select": "zone",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "regex",
    "value": "(?i)^passengerlist\\.org\\.?$"
   },
   "quote": "creates a Route 53 public hosted zone for the domain passengerlist.org"
  },
  {
   "id": "zone_public",
   "tier": "detail",
   "kind": "any_of",
   "quote": "a Route 53 public hosted zone",
   "checks": [
    {
     "kind": "attr",
     "select": "zone",
     "cond": {
      "path": [
       "VPCs"
      ],
      "op": "absent"
     }
    },
    {
     "kind": "attr",
     "select": "zone",
     "cond": {
      "path": [
       "VPCs"
      ],
      "op": "len_eq",
      "value": 0
     }
    }
   ]
  },
  {
   "id": "spf",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "grp",
     "cond": {
      "path": [
       "RecordSets",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "TXT"
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "(?i)v=spf1"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rs",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "TXT"
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "(?i)v=spf1"
       }
      ]
     }
    }
   ],
   "quote": "TXT records for SPF",
   "justify": "SPF TXT records start with v=spf1"
  },
  {
   "id": "site_verification",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "grp",
     "cond": {
      "path": [
       "RecordSets",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "TXT"
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "(?i)verification"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rs",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "TXT"
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "(?i)verification"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)site.?verif"
       }
      ]
     }
    }
   ],
   "quote": "TXT records for SPF and site verification",
   "justify": "site verification TXT values name verification, or the token is supplied by a parameter named for it"
  },
  {
   "id": "mx_gsuite",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "grp",
     "cond": {
      "path": [
       "RecordSets",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "MX"
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "(?i)google"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rs",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "MX"
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "(?i)google"
       }
      ]
     }
    }
   ],
   "quote": "MX records for G Suite email",
   "justify": "G Suite mail servers are Google hosts"
  },
  {
   "id": "mx_priority",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "grp",
     "cond": {
      "path": [
       "RecordSets",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "MX"
       },
       {
        "path": [
         "ResourceRecords"
        ],
        "op": "regex",
        "value": "^\\[\"?(1|5|10)\\s[^\",]*\"?(,\\s*\"?(1|5|10)\\s[^\",]*\"?)*\\]$"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rs",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "MX"
       },
       {
        "path": [
         "ResourceRecords"
        ],
        "op": "regex",
        "value": "^\\[\"?(1|5|10)\\s[^\",]*\"?(,\\s*\"?(1|5|10)\\s[^\",]*\"?)*\\]$"
       }
      ]
     }
    }
   ],
   "quote": "MX records for G Suite email with standard priority values",
   "justify": "Google's published G Suite MX priorities are 1, 5 and 10"
  },
  {
   "id": "dmarc",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "grp",
     "cond": {
      "path": [
       "RecordSets",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "TXT"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^_dmarc\\.passengerlist\\.org\\.?$"
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "(?i)v=DMARC1"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rs",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "TXT"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^_dmarc\\.passengerlist\\.org\\.?$"
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "(?i)v=DMARC1"
       }
      ]
     }
    }
   ],
   "quote": "a DMARC TXT record on the _dmarc subdomain",
   "justify": "DMARC records start with v=DMARC1"
  },
  {
   "id": "alias_a_root",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "grp",
     "cond": {
      "path": [
       "RecordSets",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "A"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^passengerlist\\.org\\.?$"
       },
       {
        "path": [
         "AliasTarget",
         "HostedZoneId"
        ],
        "op": "eq",
        "value": "Z2FDTNDATAQYW2"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rs",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "A"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^passengerlist\\.org\\.?$"
       },
       {
        "path": [
         "AliasTarget",
         "HostedZoneId"
        ],
        "op": "eq",
        "value": "Z2FDTNDATAQYW2"
       }
      ]
     }
    }
   ],
   "quote": "A and AAAA alias records pointing the root domain and multiple subdomains (www, departures, join, athena, feed) to their respective CloudFront distributions using the standard CloudFront alias hosted zone ID",
   "justify": "the standard CloudFront alias zone ID is Z2FDTNDATAQYW2"
  },
  {
   "id": "alias_a_www",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "grp",
     "cond": {
      "path": [
       "RecordSets",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "A"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^www\\.passengerlist\\.org\\.?$"
       },
       {
        "path": [
         "AliasTarget",
         "HostedZoneId"
        ],
        "op": "eq",
        "value": "Z2FDTNDATAQYW2"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rs",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "A"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^www\\.passengerlist\\.org\\.?$"
       },
       {
        "path": [
         "AliasTarget",
         "HostedZoneId"
        ],
        "op": "eq",
        "value": "Z2FDTNDATAQYW2"
       }
      ]
     }
    }
   ],
   "quote": "A and AAAA alias records pointing the root domain and multiple subdomains (www, departures, join, athena, feed) to their respective CloudFront distributions using the standard CloudFront alias hosted zone ID",
   "justify": "the standard CloudFront alias zone ID is Z2FDTNDATAQYW2"
  },
  {
   "id": "alias_a_departures",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "grp",
     "cond": {
      "path": [
       "RecordSets",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "A"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^departures\\.passengerlist\\.org\\.?$"
       },
       {
        "path": [
         "AliasTarget",
         "HostedZoneId"
        ],
        "op": "eq",
        "value": "Z2FDTNDATAQYW2"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rs",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "A"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^departures\\.passengerlist\\.org\\.?$"
       },
       {
        "path": [
         "AliasTarget",
         "HostedZoneId"
        ],
        "op": "eq",
        "value": "Z2FDTNDATAQYW2"
       }
      ]
     }
    }
   ],
   "quote": "A and AAAA alias records pointing the root domain and multiple subdomains (www, departures, join, athena, feed) to their respective CloudFront distributions using the standard CloudFront alias hosted zone ID",
   "justify": "the standard CloudFront alias zone ID is Z2FDTNDATAQYW2"
  },
  {
   "id": "alias_a_join",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "grp",
     "cond": {
      "path": [
       "RecordSets",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "A"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^join\\.passengerlist\\.org\\.?$"
       },
       {
        "path": [
         "AliasTarget",
         "HostedZoneId"
        ],
        "op": "eq",
        "value": "Z2FDTNDATAQYW2"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rs",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "A"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^join\\.passengerlist\\.org\\.?$"
       },
       {
        "path": [
         "AliasTarget",
         "HostedZoneId"
        ],
        "op": "eq",
        "value": "Z2FDTNDATAQYW2"
       }
      ]
     }
    }
   ],
   "quote": "A and AAAA alias records pointing the root domain and multiple subdomains (www, departures, join, athena, feed) to their respective CloudFront distributions using the standard CloudFront alias hosted zone ID",
   "justify": "the standard CloudFront alias zone ID is Z2FDTNDATAQYW2"
  },
  {
   "id": "alias_a_athena",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "grp",
     "cond": {
      "path": [
       "RecordSets",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "A"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^athena\\.passengerlist\\.org\\.?$"
       },
       {
        "path": [
         "AliasTarget",
         "HostedZoneId"
        ],
        "op": "eq",
        "value": "Z2FDTNDATAQYW2"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rs",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "A"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^athena\\.passengerlist\\.org\\.?$"
       },
       {
        "path": [
         "AliasTarget",
         "HostedZoneId"
        ],
        "op": "eq",
        "value": "Z2FDTNDATAQYW2"
       }
      ]
     }
    }
   ],
   "quote": "A and AAAA alias records pointing the root domain and multiple subdomains (www, departures, join, athena, feed) to their respective CloudFront distributions using the standard CloudFront alias hosted zone ID",
   "justify": "the standard CloudFront alias zone ID is Z2FDTNDATAQYW2"
  },
  {
   "id": "alias_a_feed",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "grp",
     "cond": {
      "path": [
       "RecordSets",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "A"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^feed\\.passengerlist\\.org\\.?$"
       },
       {
        "path": [
         "AliasTarget",
         "HostedZoneId"
        ],
        "op": "eq",
        "value": "Z2FDTNDATAQYW2"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rs",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "A"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^feed\\.passengerlist\\.org\\.?$"
       },
       {
        "path": [
         "AliasTarget",
         "HostedZoneId"
        ],
        "op": "eq",
        "value": "Z2FDTNDATAQYW2"
       }
      ]
     }
    }
   ],
   "quote": "A and AAAA alias records pointing the root domain and multiple subdomains (www, departures, join, athena, feed) to their respective CloudFront distributions using the standard CloudFront alias hosted zone ID",
   "justify": "the standard CloudFront alias zone ID is Z2FDTNDATAQYW2"
  },
  {
   "id": "alias_aaaa_root",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "grp",
     "cond": {
      "path": [
       "RecordSets",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "AAAA"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^passengerlist\\.org\\.?$"
       },
       {
        "path": [
         "AliasTarget",
         "HostedZoneId"
        ],
        "op": "eq",
        "value": "Z2FDTNDATAQYW2"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rs",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "AAAA"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^passengerlist\\.org\\.?$"
       },
       {
        "path": [
         "AliasTarget",
         "HostedZoneId"
        ],
        "op": "eq",
        "value": "Z2FDTNDATAQYW2"
       }
      ]
     }
    }
   ],
   "quote": "A and AAAA alias records pointing the root domain and multiple subdomains (www, departures, join, athena, feed) to their respective CloudFront distributions using the standard CloudFront alias hosted zone ID",
   "justify": "the standard CloudFront alias zone ID is Z2FDTNDATAQYW2"
  },
  {
   "id": "alias_aaaa_www",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "grp",
     "cond": {
      "path": [
       "RecordSets",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "AAAA"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^www\\.passengerlist\\.org\\.?$"
       },
       {
        "path": [
         "AliasTarget",
         "HostedZoneId"
        ],
        "op": "eq",
        "value": "Z2FDTNDATAQYW2"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rs",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "AAAA"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^www\\.passengerlist\\.org\\.?$"
       },
       {
        "path": [
         "AliasTarget",
         "HostedZoneId"
        ],
        "op": "eq",
        "value": "Z2FDTNDATAQYW2"
       }
      ]
     }
    }
   ],
   "quote": "A and AAAA alias records pointing the root domain and multiple subdomains (www, departures, join, athena, feed) to their respective CloudFront distributions using the standard CloudFront alias hosted zone ID",
   "justify": "the standard CloudFront alias zone ID is Z2FDTNDATAQYW2"
  },
  {
   "id": "alias_aaaa_departures",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "grp",
     "cond": {
      "path": [
       "RecordSets",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "AAAA"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^departures\\.passengerlist\\.org\\.?$"
       },
       {
        "path": [
         "AliasTarget",
         "HostedZoneId"
        ],
        "op": "eq",
        "value": "Z2FDTNDATAQYW2"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rs",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "AAAA"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^departures\\.passengerlist\\.org\\.?$"
       },
       {
        "path": [
         "AliasTarget",
         "HostedZoneId"
        ],
        "op": "eq",
        "value": "Z2FDTNDATAQYW2"
       }
      ]
     }
    }
   ],
   "quote": "A and AAAA alias records pointing the root domain and multiple subdomains (www, departures, join, athena, feed) to their respective CloudFront distributions using the standard CloudFront alias hosted zone ID",
   "justify": "the standard CloudFront alias zone ID is Z2FDTNDATAQYW2"
  },
  {
   "id": "alias_aaaa_join",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "grp",
     "cond": {
      "path": [
       "RecordSets",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "AAAA"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^join\\.passengerlist\\.org\\.?$"
       },
       {
        "path": [
         "AliasTarget",
         "HostedZoneId"
        ],
        "op": "eq",
        "value": "Z2FDTNDATAQYW2"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rs",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "AAAA"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^join\\.passengerlist\\.org\\.?$"
       },
       {
        "path": [
         "AliasTarget",
         "HostedZoneId"
        ],
        "op": "eq",
        "value": "Z2FDTNDATAQYW2"
       }
      ]
     }
    }
   ],
   "quote": "A and AAAA alias records pointing the root domain and multiple subdomains (www, departures, join, athena, feed) to their respective CloudFront distributions using the standard CloudFront alias hosted zone ID",
   "justify": "the standard CloudFront alias zone ID is Z2FDTNDATAQYW2"
  },
  {
   "id": "alias_aaaa_athena",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "grp",
     "cond": {
      "path": [
       "RecordSets",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "AAAA"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^athena\\.passengerlist\\.org\\.?$"
       },
       {
        "path": [
         "AliasTarget",
         "HostedZoneId"
        ],
        "op": "eq",
        "value": "Z2FDTNDATAQYW2"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rs",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "AAAA"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^athena\\.passengerlist\\.org\\.?$"
       },
       {
        "path": [
         "AliasTarget",
         "HostedZoneId"
        ],
        "op": "eq",
        "value": "Z2FDTNDATAQYW2"
       }
      ]
     }
    }
   ],
   "quote": "A and AAAA alias records pointing the root domain and multiple subdomains (www, departures, join, athena, feed) to their respective CloudFront distributions using the standard CloudFront alias hosted zone ID",
   "justify": "the standard CloudFront alias zone ID is Z2FDTNDATAQYW2"
  },
  {
   "id": "alias_aaaa_feed",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "grp",
     "cond": {
      "path": [
       "RecordSets",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "AAAA"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^feed\\.passengerlist\\.org\\.?$"
       },
       {
        "path": [
         "AliasTarget",
         "HostedZoneId"
        ],
        "op": "eq",
        "value": "Z2FDTNDATAQYW2"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rs",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "AAAA"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^feed\\.passengerlist\\.org\\.?$"
       },
       {
        "path": [
         "AliasTarget",
         "HostedZoneId"
        ],
        "op": "eq",
        "value": "Z2FDTNDATAQYW2"
       }
      ]
     }
    }
   ],
   "quote": "A and AAAA alias records pointing the root domain and multiple subdomains (www, departures, join, athena, feed) to their respective CloudFront distributions using the standard CloudFront alias hosted zone ID",
   "justify": "the standard CloudFront alias zone ID is Z2FDTNDATAQYW2"
  },
  {
   "id": "cname_zendesk",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "grp",
     "cond": {
      "path": [
       "RecordSets",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "CNAME"
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "(?i)zendesk"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rs",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "CNAME"
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "(?i)zendesk"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)zendesk"
       }
      ]
     }
    }
   ],
   "quote": "CNAME records for Zendesk mail routing",
   "justify": "Zendesk mail routing targets zendesk hosts; the prompt allows referenced values, so a parameter named for the record is accepted"
  },
  {
   "id": "cname_dkim",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "grp",
     "cond": {
      "path": [
       "RecordSets",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "CNAME"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)_domainkey"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rs",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "CNAME"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)_domainkey"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)dkim"
       }
      ]
     }
    }
   ],
   "quote": "DKIM verification",
   "justify": "DKIM selectors live under _domainkey; the prompt allows referenced values, so a parameter named for the record is accepted"
  },
  {
   "id": "cname_squarespace",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "grp",
     "cond": {
      "path": [
       "RecordSets",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "CNAME"
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "(?i)squarespace"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rs",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "CNAME"
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "(?i)squarespace"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)squarespace"
       }
      ]
     }
    }
   ],
   "quote": "Squarespace domain verification",
   "justify": "the prompt allows referenced values, so a parameter named for the record is accepted"
  },
  {
   "id": "cname_acm",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::Route53::RecordSet"
      ],
      "where": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "CNAME"
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "(?i)(^|[^a-z])acm([^e]|$)"
       }
      ]
     },
     "min": 2
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::Route53::RecordSetGroup"
      ],
      "where": [
       {
        "path": [
         "RecordSets",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "Type"
          ],
          "op": "eq",
          "value": "CNAME"
         },
         {
          "path": [
           "ResourceRecords",
           "*"
          ],
          "op": "regex",
          "value": "(?i)(^|[^a-z])acm([^e]|$)"
         }
        ]
       }
      ]
     },
     "min": 2
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Route53::RecordSetGroup"
      ],
      "where": [
       {
        "path": [
         "RecordSets",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "Type"
          ],
          "op": "eq",
          "value": "CNAME"
         },
         {
          "path": [
           "ResourceRecords",
           "*"
          ],
          "op": "regex",
          "value": "(?i)(^|[^a-z])acm([^e]|$)"
         }
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "RecordSets"
      ],
      "op": "regex",
      "value": "(?is)(^|[^a-z])acm([^e]|$).*[^a-z]acm([^e]|$)"
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)(acm|cert).*valid"
       }
      ]
     },
     "min": 2
    }
   ],
   "quote": "CNAME records for AWS ACM certificate validation across several subdomains",
   "justify": "ACM DNS validation CNAME values are acm-validations hosts or ACM-named values; several means at least two; the prompt allows referenced values, so parameters named for ACM validation are accepted"
  },
  {
   "id": "records_in_zone",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "grp",
     "to": "zone"
    },
    {
     "kind": "ref",
     "from": "rs",
     "to": "zone"
    },
    {
     "kind": "attr",
     "select": "grp",
     "cond": {
      "path": [
       "HostedZoneName"
      ],
      "op": "regex",
      "value": "(?i)passengerlist\\.org"
     }
    },
    {
     "kind": "attr",
     "select": "rs",
     "cond": {
      "path": [
       "HostedZoneName"
      ],
      "op": "regex",
      "value": "(?i)passengerlist\\.org"
     }
    }
   ],
   "quote": "provisions all necessary DNS record sets"
  },
  {
   "id": "x_dmarc_reject",
   "tier": "extra",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "grp",
     "cond": {
      "path": [
       "RecordSets",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "TXT"
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "(?i)p=reject"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rs",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "TXT"
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "(?i)p=reject"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "x_spf_hardfail",
   "tier": "extra",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "grp",
     "cond": {
      "path": [
       "RecordSets",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "TXT"
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "-all"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rs",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "TXT"
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "-all"
       }
      ]
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
