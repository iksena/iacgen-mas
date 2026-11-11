package intent.cfn.row_159

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
  "rec": {
   "types": [
    "AWS::Route53::RecordSet"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "hosted_zone",
   "kind": "exists",
   "tier": "core",
   "quote": "creates a Route 53 hosted zone",
   "select": "zone"
  },
  {
   "id": "zone_name",
   "kind": "attr",
   "tier": "core",
   "quote": "for the domain parameter prxu.org (with a trailing period)",
   "select": "zone",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "regex",
    "value": "^prxu\\.org\\.?$"
   }
  },
  {
   "id": "domain_param",
   "kind": "attr",
   "tier": "detail",
   "quote": "the domain parameter prxu.org (with a trailing period)",
   "select": "zone",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "regex",
    "value": "^prxu\\.org\\.$"
   }
  },
  {
   "id": "zone_production",
   "kind": "any_of",
   "tier": "detail",
   "quote": "in the Production environment",
   "checks": [
    {
     "kind": "attr",
     "select": "zone",
     "cond": {
      "path": [
       "HostedZoneTags"
      ],
      "op": "regex",
      "value": "(?i)production"
     }
    },
    {
     "kind": "attr",
     "select": "zone",
     "cond": {
      "path": [
       "HostedZoneConfig",
       "Comment"
      ],
      "op": "regex",
      "value": "(?i)production"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "Production"
     }
    }
   ]
  },
  {
   "id": "txt_apex",
   "kind": "any_of",
   "tier": "core",
   "quote": "apex TXT and MX records with a 300 second TTL for domain verification",
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
         "Name"
        ],
        "op": "regex",
        "value": "^prxu\\.org\\.?$"
       },
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "TXT"
       },
       {
        "path": [
         "TTL"
        ],
        "op": "eq",
        "value": 300
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rec",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "^prxu\\.org\\.?$"
       },
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "TXT"
       },
       {
        "path": [
         "TTL"
        ],
        "op": "eq",
        "value": 300
       }
      ]
     }
    }
   ]
  },
  {
   "id": "mx_apex",
   "kind": "any_of",
   "tier": "core",
   "quote": "email routing to Google's mail servers",
   "justify": "Google Workspace mail servers are *.google.com / googlemail.com hosts",
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
         "Name"
        ],
        "op": "regex",
        "value": "^prxu\\.org\\.?$"
       },
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "MX"
       },
       {
        "path": [
         "TTL"
        ],
        "op": "eq",
        "value": 300
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
     "select": "rec",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "^prxu\\.org\\.?$"
       },
       {
        "path": [
         "Type"
        ],
        "op": "eq",
        "value": "MX"
       },
       {
        "path": [
         "TTL"
        ],
        "op": "eq",
        "value": 300
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
   ]
  },
  {
   "id": "alias_a",
   "kind": "any_of",
   "tier": "core",
   "quote": "alias records (A and AAAA) pointing to the respective CloudFront distributions",
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
         "AliasTarget"
        ],
        "op": "regex",
        "value": "(?i)cloudfront|Z2FDTNDATAQYW2"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rec",
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
         "AliasTarget"
        ],
        "op": "regex",
        "value": "(?i)cloudfront|Z2FDTNDATAQYW2"
       }
      ]
     }
    }
   ],
   "justify": "an alias to CloudFront uses a cloudfront.net target or CloudFront's fixed alias hosted zone ID"
  },
  {
   "id": "alias_aaaa",
   "kind": "any_of",
   "tier": "core",
   "quote": "alias records (A and AAAA) pointing to the respective CloudFront distributions",
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
         "AliasTarget"
        ],
        "op": "regex",
        "value": "(?i)cloudfront|Z2FDTNDATAQYW2"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rec",
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
         "AliasTarget"
        ],
        "op": "regex",
        "value": "(?i)cloudfront|Z2FDTNDATAQYW2"
       }
      ]
     }
    }
   ],
   "justify": "an alias to CloudFront uses a cloudfront.net target or CloudFront's fixed alias hosted zone ID"
  },
  {
   "id": "alias_dovetail_cdn",
   "kind": "any_of",
   "tier": "detail",
   "quote": "the dovetail-cdn",
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
         "Name"
        ],
        "op": "regex",
        "value": "^dovetail\\-cdn\\.prxu\\.org\\.?$"
       },
       {
        "path": [
         "Type"
        ],
        "op": "in",
        "value": [
         "A",
         "AAAA"
        ]
       },
       {
        "path": [
         "AliasTarget"
        ],
        "op": "regex",
        "value": "(?i)cloudfront|Z2FDTNDATAQYW2"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rec",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "^dovetail\\-cdn\\.prxu\\.org\\.?$"
       },
       {
        "path": [
         "Type"
        ],
        "op": "in",
        "value": [
         "A",
         "AAAA"
        ]
       },
       {
        "path": [
         "AliasTarget"
        ],
        "op": "regex",
        "value": "(?i)cloudfront|Z2FDTNDATAQYW2"
       }
      ]
     }
    }
   ],
   "justify": "an alias to CloudFront uses a cloudfront.net target or CloudFront's fixed alias hosted zone ID"
  },
  {
   "id": "alias_dovetail_cdn_staging",
   "kind": "any_of",
   "tier": "detail",
   "quote": "dovetail-cdn-staging",
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
         "Name"
        ],
        "op": "regex",
        "value": "^dovetail-cdn[.-]staging\\.prxu\\.org\\.?$"
       },
       {
        "path": [
         "Type"
        ],
        "op": "in",
        "value": [
         "A",
         "AAAA"
        ]
       },
       {
        "path": [
         "AliasTarget"
        ],
        "op": "regex",
        "value": "(?i)cloudfront|Z2FDTNDATAQYW2"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rec",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "^dovetail-cdn[.-]staging\\.prxu\\.org\\.?$"
       },
       {
        "path": [
         "Type"
        ],
        "op": "in",
        "value": [
         "A",
         "AAAA"
        ]
       },
       {
        "path": [
         "AliasTarget"
        ],
        "op": "regex",
        "value": "(?i)cloudfront|Z2FDTNDATAQYW2"
       }
      ]
     }
    }
   ],
   "justify": "an alias to CloudFront uses a cloudfront.net target or CloudFront's fixed alias hosted zone ID"
  },
  {
   "id": "alias_feeder",
   "kind": "any_of",
   "tier": "detail",
   "quote": "feeder CDN (f",
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
         "Name"
        ],
        "op": "regex",
        "value": "^f\\.prxu\\.org\\.?$"
       },
       {
        "path": [
         "Type"
        ],
        "op": "in",
        "value": [
         "A",
         "AAAA"
        ]
       },
       {
        "path": [
         "AliasTarget"
        ],
        "op": "regex",
        "value": "(?i)cloudfront|Z2FDTNDATAQYW2"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rec",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "^f\\.prxu\\.org\\.?$"
       },
       {
        "path": [
         "Type"
        ],
        "op": "in",
        "value": [
         "A",
         "AAAA"
        ]
       },
       {
        "path": [
         "AliasTarget"
        ],
        "op": "regex",
        "value": "(?i)cloudfront|Z2FDTNDATAQYW2"
       }
      ]
     }
    }
   ],
   "justify": "an alias to CloudFront uses a cloudfront.net target or CloudFront's fixed alias hosted zone ID"
  },
  {
   "id": "alias_feeder_staging",
   "kind": "any_of",
   "tier": "detail",
   "quote": "f-staging",
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
         "Name"
        ],
        "op": "regex",
        "value": "^f\\-staging\\.prxu\\.org\\.?$"
       },
       {
        "path": [
         "Type"
        ],
        "op": "in",
        "value": [
         "A",
         "AAAA"
        ]
       },
       {
        "path": [
         "AliasTarget"
        ],
        "op": "regex",
        "value": "(?i)cloudfront|Z2FDTNDATAQYW2"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rec",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "^f\\-staging\\.prxu\\.org\\.?$"
       },
       {
        "path": [
         "Type"
        ],
        "op": "in",
        "value": [
         "A",
         "AAAA"
        ]
       },
       {
        "path": [
         "AliasTarget"
        ],
        "op": "regex",
        "value": "(?i)cloudfront|Z2FDTNDATAQYW2"
       }
      ]
     }
    }
   ],
   "justify": "an alias to CloudFront uses a cloudfront.net target or CloudFront's fixed alias hosted zone ID"
  },
  {
   "id": "alias_feeder_dev",
   "kind": "any_of",
   "tier": "detail",
   "quote": "f.development)",
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
         "Name"
        ],
        "op": "regex",
        "value": "^f\\.development\\.prxu\\.org\\.?$"
       },
       {
        "path": [
         "Type"
        ],
        "op": "in",
        "value": [
         "A",
         "AAAA"
        ]
       },
       {
        "path": [
         "AliasTarget"
        ],
        "op": "regex",
        "value": "(?i)cloudfront|Z2FDTNDATAQYW2"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rec",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "^f\\.development\\.prxu\\.org\\.?$"
       },
       {
        "path": [
         "Type"
        ],
        "op": "in",
        "value": [
         "A",
         "AAAA"
        ]
       },
       {
        "path": [
         "AliasTarget"
        ],
        "op": "regex",
        "value": "(?i)cloudfront|Z2FDTNDATAQYW2"
       }
      ]
     }
    }
   ],
   "justify": "an alias to CloudFront uses a cloudfront.net target or CloudFront's fixed alias hosted zone ID"
  },
  {
   "id": "alias_ads",
   "kind": "any_of",
   "tier": "detail",
   "quote": "ad files CDN (a)",
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
         "Name"
        ],
        "op": "regex",
        "value": "^a\\.prxu\\.org\\.?$"
       },
       {
        "path": [
         "Type"
        ],
        "op": "in",
        "value": [
         "A",
         "AAAA"
        ]
       },
       {
        "path": [
         "AliasTarget"
        ],
        "op": "regex",
        "value": "(?i)cloudfront|Z2FDTNDATAQYW2"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rec",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "^a\\.prxu\\.org\\.?$"
       },
       {
        "path": [
         "Type"
        ],
        "op": "in",
        "value": [
         "A",
         "AAAA"
        ]
       },
       {
        "path": [
         "AliasTarget"
        ],
        "op": "regex",
        "value": "(?i)cloudfront|Z2FDTNDATAQYW2"
       }
      ]
     }
    }
   ],
   "justify": "an alias to CloudFront uses a cloudfront.net target or CloudFront's fixed alias hosted zone ID"
  },
  {
   "id": "alias_sandbox",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a development sandbox CDN (ryan-cdn) subdomains",
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
         "Name"
        ],
        "op": "regex",
        "value": "^ryan\\-cdn\\.prxu\\.org\\.?$"
       },
       {
        "path": [
         "Type"
        ],
        "op": "in",
        "value": [
         "A",
         "AAAA"
        ]
       },
       {
        "path": [
         "AliasTarget"
        ],
        "op": "regex",
        "value": "(?i)cloudfront|Z2FDTNDATAQYW2"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rec",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "^ryan\\-cdn\\.prxu\\.org\\.?$"
       },
       {
        "path": [
         "Type"
        ],
        "op": "in",
        "value": [
         "A",
         "AAAA"
        ]
       },
       {
        "path": [
         "AliasTarget"
        ],
        "op": "regex",
        "value": "(?i)cloudfront|Z2FDTNDATAQYW2"
       }
      ]
     }
    }
   ],
   "justify": "an alias to CloudFront uses a cloudfront.net target or CloudFront's fixed alias hosted zone ID"
  },
  {
   "id": "legacy_cname_prod",
   "kind": "any_of",
   "tier": "core",
   "quote": "legacy CNAME records pointing to the corresponding dovetail-cdn subdomains with a 3600 second TTL",
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
         "TTL"
        ],
        "op": "eq",
        "value": 3600
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "^dovetail-cdn\\.prxu\\.org\\.?$"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rec",
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
         "TTL"
        ],
        "op": "eq",
        "value": 3600
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "^dovetail-cdn\\.prxu\\.org\\.?$"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "legacy_cname_staging",
   "kind": "any_of",
   "tier": "core",
   "quote": "legacy CNAME records pointing to the corresponding dovetail-cdn subdomains with a 3600 second TTL",
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
         "TTL"
        ],
        "op": "eq",
        "value": 3600
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "^dovetail-cdn[.-]staging\\.prxu\\.org\\.?$"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rec",
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
         "TTL"
        ],
        "op": "eq",
        "value": 3600
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "^dovetail-cdn[.-]staging\\.prxu\\.org\\.?$"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "router_prod",
   "kind": "any_of",
   "tier": "core",
   "quote": "CNAME records for the dovetail router covering production and staging subdomains with a 30 second TTL",
   "justify": "the production router subdomain is named for dovetail or the router, optionally marked prod, and is not the staging one",
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
         "TTL"
        ],
        "op": "eq",
        "value": 30
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^(prod[a-z]*[-.])?(dovetail|router|dovetail[-.]router|router[-.]dovetail)([-.]prod[a-z]*)?\\.prxu\\.org\\.?$"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rec",
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
         "TTL"
        ],
        "op": "eq",
        "value": 30
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^(prod[a-z]*[-.])?(dovetail|router|dovetail[-.]router|router[-.]dovetail)([-.]prod[a-z]*)?\\.prxu\\.org\\.?$"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "router_staging",
   "kind": "any_of",
   "tier": "core",
   "quote": "CNAME records for the dovetail router covering production and staging subdomains with a 30 second TTL",
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
         "TTL"
        ],
        "op": "eq",
        "value": 30
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)(dovetail|router).*(staging|stg)|(staging|stg).*(dovetail|router)"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rec",
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
         "TTL"
        ],
        "op": "eq",
        "value": 30
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)(dovetail|router).*(staging|stg)|(staging|stg).*(dovetail|router)"
       }
      ]
     }
    }
   ],
   "justify": "the staging router subdomain names dovetail or the router and staging"
  },
  {
   "id": "proxy_cname_prod",
   "kind": "any_of",
   "tier": "core",
   "quote": "CNAME records for the authenticated feed proxy subdomains (production and staging) with a 3600 second TTL",
   "justify": "p abbreviates proxy; the production subdomain names the feed proxy, optionally marked prod, and is not the staging one",
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
         "TTL"
        ],
        "op": "eq",
        "value": 3600
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^(prod[a-z]*[-.])?(p|auth[a-z]*([-.]?feed)?([-.]?proxy)?|feed([-.]?proxy)?|proxy)([-.]prod[a-z]*)?\\.prxu\\.org\\.?$"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rec",
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
         "TTL"
        ],
        "op": "eq",
        "value": 3600
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^(prod[a-z]*[-.])?(p|auth[a-z]*([-.]?feed)?([-.]?proxy)?|feed([-.]?proxy)?|proxy)([-.]prod[a-z]*)?\\.prxu\\.org\\.?$"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "proxy_cname_3600",
   "kind": "any_of",
   "tier": "core",
   "quote": "CNAME records for the authenticated feed proxy subdomains (production and staging) with a 3600 second TTL",
   "justify": "p abbreviates proxy; the name must identify the feed proxy and staging, so a legacy staging CNAME does not count",
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
         "TTL"
        ],
        "op": "eq",
        "value": 3600
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)(auth|feed|proxy|^p[.-]).*(staging|stg)|(staging|stg).*(auth|feed|proxy)"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rec",
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
         "TTL"
        ],
        "op": "eq",
        "value": 3600
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)(auth|feed|proxy|^p[.-]).*(staging|stg)|(staging|stg).*(auth|feed|proxy)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "acm_validation",
   "kind": "any_of",
   "tier": "core",
   "quote": "all necessary ACM DNS validation CNAME records",
   "justify": "ACM DNS validation targets end in acm-validations.aws",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::CertificateManager::Certificate"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "DomainValidationOptions",
       "*",
       "HostedZoneId"
      ],
      "op": "present"
     }
    },
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
        "value": "(?i)acm-validations\\.aws"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "rec",
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
        "value": "(?i)acm-validations\\.aws"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "records_in_zone",
   "kind": "any_of",
   "tier": "detail",
   "quote": "creates a Route 53 hosted zone",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Route53::RecordSetGroup"
      ],
      "where": []
     },
     "to": "zone"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Route53::RecordSet"
      ],
      "where": []
     },
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
      "value": "^prxu\\.org\\.?$"
     }
    },
    {
     "kind": "attr",
     "select": "rec",
     "cond": {
      "path": [
       "HostedZoneName"
      ],
      "op": "regex",
      "value": "^prxu\\.org\\.?$"
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
