# GENERATED from specs/cfn/row_074.json by intent_checks/build.py -- do not edit.
package intent.cfn.row_074

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "hosted_zone",
   "kind": "attr",
   "select": {
    "types": [
     "AWS::Route53::HostedZone"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "Name"
    ],
    "op": "regex",
    "value": "(?i)^earhustlesq\\.com\\.?$"
   },
   "tier": "core",
   "quote": "creates a Route53 hosted zone for a parameterized domain (defaulting to earhustlesq.com)"
  },
  {
   "id": "domain_parameter",
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
    "value": "earhustlesq.com"
   },
   "tier": "detail",
   "quote": "a parameterized domain (defaulting to earhustlesq.com)"
  },
  {
   "id": "records_in_zone",
   "kind": "any_of",
   "tier": "core",
   "quote": "configures the full set of DNS records",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Route53::RecordSetGroup"
      ],
      "where": []
     },
     "to": {
      "types": [
       "AWS::Route53::HostedZone"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Route53::RecordSet"
      ],
      "where": []
     },
     "to": {
      "types": [
       "AWS::Route53::HostedZone"
      ],
      "where": []
     }
    }
   ]
  },
  {
   "id": "txt_spf",
   "kind": "any_of",
   "tier": "core",
   "quote": "TXT records for SPF",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Route53::RecordSetGroup"
      ],
      "where": []
     },
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
        "op": "contains",
        "value": "v=spf1"
       }
      ]
     }
    },
    {
     "kind": "attr",
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
        "value": "TXT"
       }
      ]
     },
     "cond": {
      "path": [
       "ResourceRecords",
       "*"
      ],
      "op": "contains",
      "value": "v=spf1"
     }
    }
   ]
  },
  {
   "id": "txt_google_site_verification",
   "kind": "any_of",
   "tier": "detail",
   "quote": "Google site verification",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Route53::RecordSetGroup"
      ],
      "where": []
     },
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
        "op": "contains",
        "value": "google-site-verification"
       }
      ]
     }
    },
    {
     "kind": "attr",
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
        "value": "TXT"
       }
      ]
     },
     "cond": {
      "path": [
       "ResourceRecords",
       "*"
      ],
      "op": "contains",
      "value": "google-site-verification"
     }
    }
   ]
  },
  {
   "id": "txt_zoom_verification",
   "kind": "any_of",
   "tier": "detail",
   "quote": "Zoom verification",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Route53::RecordSetGroup"
      ],
      "where": []
     },
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
        "value": "(?i)zoom"
       }
      ]
     }
    },
    {
     "kind": "attr",
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
        "value": "TXT"
       }
      ]
     },
     "cond": {
      "path": [
       "ResourceRecords",
       "*"
      ],
      "op": "regex",
      "value": "(?i)zoom"
     }
    }
   ]
  },
  {
   "id": "txt_dmarc",
   "kind": "any_of",
   "tier": "core",
   "quote": "DMARC",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Route53::RecordSetGroup"
      ],
      "where": []
     },
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
        "op": "contains",
        "value": "v=DMARC1"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^_dmarc\\."
       }
      ]
     }
    },
    {
     "kind": "attr",
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
        "value": "TXT"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^_dmarc\\."
       }
      ]
     },
     "cond": {
      "path": [
       "ResourceRecords",
       "*"
      ],
      "op": "contains",
      "value": "v=DMARC1"
     }
    }
   ]
  },
  {
   "id": "txt_atproto",
   "kind": "any_of",
   "tier": "core",
   "quote": "ATProto",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Route53::RecordSetGroup"
      ],
      "where": []
     },
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
        "value": "(?i)^_atproto\\."
       }
      ]
     }
    },
    {
     "kind": "attr",
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
        "value": "TXT"
       }
      ]
     },
     "cond": {
      "path": [
       "Name"
      ],
      "op": "regex",
      "value": "(?i)^_atproto\\."
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Route53::RecordSetGroup"
      ],
      "where": []
     },
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
        "value": "(?i)(did=|atproto)"
       }
      ]
     }
    },
    {
     "kind": "attr",
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
        "value": "TXT"
       }
      ]
     },
     "cond": {
      "path": [
       "ResourceRecords",
       "*"
      ],
      "op": "regex",
      "value": "(?i)(did=|atproto)"
     }
    }
   ]
  },
  {
   "id": "mx_gsuite_primary",
   "kind": "any_of",
   "tier": "core",
   "quote": "MX records for G Suite email on both the primary domain",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Route53::RecordSetGroup"
      ],
      "where": []
     },
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
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^earhustlesq\\.com\\.?$"
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
        "value": "MX"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^earhustlesq\\.com\\.?$"
       }
      ]
     },
     "cond": {
      "path": [
       "ResourceRecords",
       "*"
      ],
      "op": "regex",
      "value": "(?i)google"
     }
    }
   ]
  },
  {
   "id": "mx_gsuite_old_subdomain",
   "kind": "any_of",
   "tier": "core",
   "quote": "and an old subdomain",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Route53::RecordSetGroup"
      ],
      "where": []
     },
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
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^old\\."
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
        "value": "MX"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^old\\."
       }
      ]
     },
     "cond": {
      "path": [
       "ResourceRecords",
       "*"
      ],
      "op": "regex",
      "value": "(?i)google"
     }
    }
   ]
  },
  {
   "id": "a_record_apex",
   "kind": "any_of",
   "tier": "core",
   "quote": "A records pointing to Squarespace IPs",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Route53::RecordSetGroup"
      ],
      "where": []
     },
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
        "value": "(?i)^earhustlesq\\.com\\.?$"
       }
      ]
     }
    },
    {
     "kind": "attr",
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
        "value": "A"
       }
      ]
     },
     "cond": {
      "path": [
       "Name"
      ],
      "op": "regex",
      "value": "(?i)^earhustlesq\\.com\\.?$"
     }
    }
   ]
  },
  {
   "id": "cname_www",
   "kind": "any_of",
   "tier": "core",
   "quote": "CNAMEs for www",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Route53::RecordSetGroup"
      ],
      "where": []
     },
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
        "value": "(?i)^www\\."
       }
      ]
     }
    },
    {
     "kind": "attr",
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
       }
      ]
     },
     "cond": {
      "path": [
       "Name"
      ],
      "op": "regex",
      "value": "(?i)^www\\."
     }
    }
   ]
  },
  {
   "id": "cname_podcast_feeds",
   "kind": "any_of",
   "tier": "detail",
   "quote": "podcast feeds",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Route53::RecordSetGroup"
      ],
      "where": []
     },
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
        "value": "(?i)^feeds\\."
       }
      ]
     }
    },
    {
     "kind": "attr",
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
       }
      ]
     },
     "cond": {
      "path": [
       "Name"
      ],
      "op": "regex",
      "value": "(?i)^feeds\\."
     }
    }
   ]
  },
  {
   "id": "cname_squarespace_verification",
   "kind": "any_of",
   "tier": "detail",
   "quote": "Squarespace domain verification",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Route53::RecordSetGroup"
      ],
      "where": []
     },
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
        "value": "(?i)verif"
       }
      ]
     }
    },
    {
     "kind": "attr",
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
       }
      ]
     },
     "cond": {
      "path": [
       "ResourceRecords",
       "*"
      ],
      "op": "regex",
      "value": "(?i)verif"
     }
    }
   ],
   "justify": "\"domain verification\" -> the CNAME target is a verification endpoint (verify.squarespace.com)"
  },
  {
   "id": "zendesk_txt_verification",
   "kind": "any_of",
   "tier": "detail",
   "quote": "ZenDesk TXT",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Route53::RecordSetGroup"
      ],
      "where": []
     },
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
        "value": "(?i)zendesk"
       }
      ]
     }
    },
    {
     "kind": "attr",
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
        "value": "TXT"
       }
      ]
     },
     "cond": {
      "path": [
       "Name"
      ],
      "op": "regex",
      "value": "(?i)zendesk"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Route53::RecordSetGroup"
      ],
      "where": []
     },
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
        "value": "(?i)zendesk"
       }
      ]
     }
    },
    {
     "kind": "attr",
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
        "value": "TXT"
       }
      ]
     },
     "cond": {
      "path": [
       "ResourceRecords",
       "*"
      ],
      "op": "regex",
      "value": "(?i)zendesk"
     }
    }
   ]
  },
  {
   "id": "zendesk_cname",
   "kind": "any_of",
   "tier": "core",
   "quote": "ZenDesk TXT and CNAME records",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Route53::RecordSetGroup"
      ],
      "where": []
     },
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
       }
      ]
     },
     "cond": {
      "path": [
       "ResourceRecords",
       "*"
      ],
      "op": "regex",
      "value": "(?i)zendesk"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Route53::RecordSetGroup"
      ],
      "where": []
     },
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
        "value": "(?i)zendesk"
       }
      ]
     }
    },
    {
     "kind": "attr",
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
       }
      ]
     },
     "cond": {
      "path": [
       "Name"
      ],
      "op": "regex",
      "value": "(?i)zendesk"
     }
    }
   ]
  },
  {
   "id": "zendesk_dkim",
   "kind": "any_of",
   "tier": "detail",
   "quote": "DKIM",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Route53::RecordSetGroup"
      ],
      "where": []
     },
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
        "op": "in",
        "value": [
         "CNAME",
         "TXT"
        ]
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)_domainkey\\."
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
     "select": {
      "types": [
       "AWS::Route53::RecordSet"
      ],
      "where": [
       {
        "path": [
         "Type"
        ],
        "op": "in",
        "value": [
         "CNAME",
         "TXT"
        ]
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)_domainkey\\."
       }
      ]
     },
     "cond": {
      "path": [
       "ResourceRecords",
       "*"
      ],
      "op": "regex",
      "value": "(?i)zendesk"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Route53::RecordSetGroup"
      ],
      "where": []
     },
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
        "op": "in",
        "value": [
         "CNAME",
         "TXT"
        ]
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "."
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)zen[^.]*\\._domainkey\\."
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Route53::RecordSet"
      ],
      "where": [
       {
        "path": [
         "Type"
        ],
        "op": "in",
        "value": [
         "CNAME",
         "TXT"
        ]
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "."
       }
      ]
     },
     "cond": {
      "path": [
       "Name"
      ],
      "op": "regex",
      "value": "(?i)zen[^.]*\\._domainkey\\."
     }
    }
   ],
   "justify": "DKIM records are published under <selector>._domainkey"
  },
  {
   "id": "campaign_monitor_mx",
   "kind": "any_of",
   "tier": "detail",
   "quote": "Campaign Monitor DKIM, SPF alignment, and MX records",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Route53::RecordSetGroup"
      ],
      "where": []
     },
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
        "value": "(?i)(createsend|campaign)"
       }
      ]
     }
    },
    {
     "kind": "attr",
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
        "value": "MX"
       }
      ]
     },
     "cond": {
      "path": [
       "ResourceRecords",
       "*"
      ],
      "op": "regex",
      "value": "(?i)(createsend|campaign)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Route53::RecordSetGroup"
      ],
      "where": []
     },
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
         "Name"
        ],
        "op": "regex",
        "value": "(?i)(campaign|cm[-.]|createsend)"
       }
      ]
     }
    },
    {
     "kind": "attr",
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
        "value": "MX"
       }
      ]
     },
     "cond": {
      "path": [
       "Name"
      ],
      "op": "regex",
      "value": "(?i)(campaign|cm[-.]|createsend)"
     }
    }
   ],
   "justify": "Campaign Monitor mail is served by its createsend.com domain; also accept campaign/cm-named records"
  },
  {
   "id": "campaign_monitor_spf",
   "kind": "any_of",
   "tier": "detail",
   "quote": "SPF alignment",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Route53::RecordSetGroup"
      ],
      "where": []
     },
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
        "value": "(?i)v=spf1.*(createsend|campaign|cmail)"
       }
      ]
     }
    },
    {
     "kind": "attr",
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
        "value": "TXT"
       }
      ]
     },
     "cond": {
      "path": [
       "ResourceRecords",
       "*"
      ],
      "op": "regex",
      "value": "(?i)v=spf1.*(createsend|campaign|cmail)"
     }
    }
   ],
   "justify": "Campaign Monitor SPF includes are cmail1.com/cmail2.com (createsend.com historically); accept any of them or a campaign-monitor include"
  },
  {
   "id": "dkim_txt",
   "kind": "any_of",
   "tier": "detail",
   "quote": "Google Workspace DKIM",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Route53::RecordSetGroup"
      ],
      "where": []
     },
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
        "value": "(?i)_domainkey\\."
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "contains",
        "value": "v=DKIM1"
       }
      ]
     }
    },
    {
     "kind": "attr",
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
        "value": "TXT"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)_domainkey\\."
       }
      ]
     },
     "cond": {
      "path": [
       "ResourceRecords",
       "*"
      ],
      "op": "contains",
      "value": "v=DKIM1"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Route53::RecordSetGroup"
      ],
      "where": []
     },
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
        "op": "in",
        "value": [
         "CNAME",
         "TXT"
        ]
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "."
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)google[^.]*\\._domainkey\\."
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Route53::RecordSet"
      ],
      "where": [
       {
        "path": [
         "Type"
        ],
        "op": "in",
        "value": [
         "CNAME",
         "TXT"
        ]
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "."
       }
      ]
     },
     "cond": {
      "path": [
       "Name"
      ],
      "op": "regex",
      "value": "(?i)google[^.]*\\._domainkey\\."
     }
    }
   ],
   "justify": "DKIM records are published under <selector>._domainkey (TXT v=DKIM1)"
  },
  {
   "id": "acm_validation_feeds",
   "kind": "any_of",
   "tier": "core",
   "quote": "an ACM certificate validation CNAME for the feeds subdomain",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Route53::RecordSetGroup"
      ],
      "where": []
     },
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
        "value": "(?i)^_[^.]+\\.feeds\\."
       }
      ]
     }
    },
    {
     "kind": "attr",
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
       }
      ]
     },
     "cond": {
      "path": [
       "Name"
      ],
      "op": "regex",
      "value": "(?i)^_[^.]+\\.feeds\\."
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::CertificateManager::Certificate"
      ],
      "where": [
       {
        "path": [
         "DomainName"
        ],
        "op": "regex",
        "value": "(?i)^feeds\\."
       }
      ]
     },
     "cond": {
      "path": [
       "DomainValidationOptions"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "tag_environment",
   "kind": "attr",
   "select": {
    "types": [
     "AWS::Route53::HostedZone"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "HostedZoneTags",
     "*"
    ],
    "op": "has_kv",
    "value": {
     "key": "prx:ops:environment",
     "value": "Production"
    }
   },
   "tier": "detail",
   "quote": "prx:ops:environment set to Production"
  },
  {
   "id": "tag_application",
   "kind": "attr",
   "select": {
    "types": [
     "AWS::Route53::HostedZone"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "HostedZoneTags",
     "*"
    ],
    "op": "has_kv",
    "value": {
     "key": "prx:dev:application",
     "value": "Ear Hustle"
    }
   },
   "tier": "detail",
   "quote": "prx:dev:application set to Ear Hustle"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
