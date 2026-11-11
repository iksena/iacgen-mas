package intent.cfn.row_108

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "zone": {
   "types": [
    "AWS::Route53::HostedZone"
   ],
   "where": [
    {
     "path": [
      "VPCs",
      "*"
     ],
     "op": "absent"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "hosted_zone",
   "kind": "exists",
   "select": "zone",
   "tier": "core",
   "quote": "creates a Route 53 public hosted zone",
   "justify": "a public hosted zone has no associated VPCs"
  },
  {
   "id": "one_hosted_zone",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::Route53::HostedZone"
    ],
    "where": []
   },
   "min": 1,
   "max": 1,
   "tier": "detail",
   "quote": "the one hosted zone the stack creates"
  },
  {
   "id": "hosted_zone_domain",
   "kind": "attr",
   "select": "zone",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "regex",
    "value": "(?i)^podcastgarage\\.org\\.?$"
   },
   "tier": "core",
   "quote": "for a specified domain (defaulting to podcastgarage.org)"
  },
  {
   "id": "domain_parameter",
   "kind": "exists",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "default"
      ],
      "op": "regex",
      "value": "(?i)^podcastgarage\\.org\\.?$"
     }
    ]
   },
   "tier": "detail",
   "quote": "for a specified domain (defaulting to podcastgarage.org)"
  },
  {
   "id": "records_in_zone",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Route53::RecordSetGroup",
       "AWS::Route53::RecordSet"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "HostedZoneId",
       "ref"
      ],
      "op": "present"
     },
     "quantifier": "all"
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Route53::RecordSetGroup",
       "AWS::Route53::RecordSet"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "HostedZoneName"
      ],
      "op": "regex",
      "value": "(?i)^podcastgarage\\.org\\.?$"
     },
     "quantifier": "all"
    }
   ],
   "tier": "core",
   "quote": "All of these records should live under the one hosted zone the stack creates"
  },
  {
   "id": "txt_spf",
   "kind": "any_of",
   "checks": [
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
          "value": "TXT"
         },
         {
          "path": [
           "Name"
          ],
          "op": "regex",
          "value": "(?i)^podcastgarage\\.org\\.?$"
         },
         {
          "path": [
           "ResourceRecords",
           "*"
          ],
          "op": "regex",
          "value": "v=spf1"
         }
        ]
       }
      ]
     }
    },
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
        "value": "TXT"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^podcastgarage\\.org\\.?$"
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "v=spf1"
       }
      ]
     }
    }
   ],
   "tier": "core",
   "quote": "a TXT record combining our SPF policy and a Google site verification token"
  },
  {
   "id": "txt_google_verification",
   "kind": "any_of",
   "checks": [
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
          "value": "TXT"
         },
         {
          "path": [
           "Name"
          ],
          "op": "regex",
          "value": "(?i)^podcastgarage\\.org\\.?$"
         },
         {
          "path": [
           "ResourceRecords",
           "*"
          ],
          "op": "regex",
          "value": "google-site-verification"
         }
        ]
       }
      ]
     }
    },
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
        "value": "TXT"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^podcastgarage\\.org\\.?$"
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "google-site-verification"
       }
      ]
     }
    }
   ],
   "tier": "core",
   "quote": "a TXT record combining our SPF policy and a Google site verification token"
  },
  {
   "id": "root_a_record",
   "kind": "any_of",
   "checks": [
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
          "value": "A"
         },
         {
          "path": [
           "Name"
          ],
          "op": "regex",
          "value": "(?i)^podcastgarage\\.org\\.?$"
         }
        ]
       }
      ]
     }
    },
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
        "value": "A"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^podcastgarage\\.org\\.?$"
       }
      ]
     }
    }
   ],
   "tier": "core",
   "quote": "A and CNAME records pointing the root and www subdomains at Squarespace's website hosting IP addresses"
  },
  {
   "id": "root_a_multiple_ips",
   "kind": "any_of",
   "checks": [
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
          "value": "A"
         },
         {
          "path": [
           "Name"
          ],
          "op": "regex",
          "value": "(?i)^podcastgarage\\.org\\.?$"
         },
         {
          "path": [
           "ResourceRecords"
          ],
          "op": "len_gte",
          "value": 2
         }
        ]
       }
      ]
     }
    },
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
        "value": "A"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^podcastgarage\\.org\\.?$"
       },
       {
        "path": [
         "ResourceRecords"
        ],
        "op": "len_gte",
        "value": 2
       }
      ]
     }
    }
   ],
   "tier": "detail",
   "quote": "Squarespace's website hosting IP addresses",
   "justify": "plural IP addresses"
  },
  {
   "id": "www_cname_squarespace",
   "kind": "any_of",
   "checks": [
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
           "Name"
          ],
          "op": "regex",
          "value": "(?i)^www\\."
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
      ]
     }
    },
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
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^www\\."
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
    }
   ],
   "tier": "core",
   "quote": "CNAME target for our marketing site"
  },
  {
   "id": "mx_gsuite",
   "kind": "any_of",
   "checks": [
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
          "value": "MX"
         },
         {
          "path": [
           "Name"
          ],
          "op": "regex",
          "value": "(?i)^podcastgarage\\.org\\.?$"
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
      ]
     }
    },
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
        "value": "MX"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^podcastgarage\\.org\\.?$"
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
   "tier": "core",
   "quote": "an MX record and a DMARC TXT record for our G Suite mail delivery and reporting"
  },
  {
   "id": "dmarc_txt",
   "kind": "any_of",
   "checks": [
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
          "value": "TXT"
         },
         {
          "path": [
           "Name"
          ],
          "op": "regex",
          "value": "(?i)^_dmarc\\."
         },
         {
          "path": [
           "ResourceRecords",
           "*"
          ],
          "op": "regex",
          "value": "v=DMARC1"
         }
        ]
       }
      ]
     }
    },
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
        "value": "TXT"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^_dmarc\\."
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "v=DMARC1"
       }
      ]
     }
    }
   ],
   "tier": "core",
   "quote": "a DMARC TXT record"
  },
  {
   "id": "printer_a_record",
   "kind": "any_of",
   "checks": [
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
          "value": "A"
         },
         {
          "path": [
           "Name"
          ],
          "op": "regex",
          "value": "(?i)printer"
         },
         {
          "path": [
           "ResourceRecords",
           "*"
          ],
          "op": "regex",
          "value": "^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.)"
         }
        ]
       }
      ]
     }
    },
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
        "value": "A"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)printer"
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.)"
       }
      ]
     }
    }
   ],
   "tier": "core",
   "quote": "an internal A record for an office printer on our local network",
   "justify": "a local-network address is a private RFC1918 address"
  },
  {
   "id": "zendesk_txt",
   "kind": "any_of",
   "checks": [
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
      ]
     }
    },
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
          "value": "TXT"
         },
         {
          "path": [
           "ResourceRecords",
           "*"
          ],
          "op": "regex",
          "value": "(?i)zendesk.*verif|verif.*zendesk"
         }
        ]
       }
      ]
     }
    },
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
        "value": "TXT"
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "(?i)zendesk.*verif|verif.*zendesk"
       }
      ]
     }
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
           "Name"
          ],
          "op": "regex",
          "value": "(?i)zendesk.*verif|verif.*zendesk"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::Route53::RecordSet"
      ],
      "where": [
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)zendesk.*verif|verif.*zendesk"
       }
      ]
     }
    }
   ],
   "tier": "core",
   "quote": "a ZenDesk verification token"
  },
  {
   "id": "zendesk_domain_validation_cname",
   "kind": "any_of",
   "checks": [
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
           "Name"
          ],
          "op": "regex",
          "value": "(?i)^([^_]*|_zendesk.*)$"
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
      ]
     }
    },
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
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^([^_]*|_zendesk.*)$"
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
           "Name"
          ],
          "op": "regex",
          "value": "(?i)^[^_.]*zendesk[^_.]*\\.podcastgarage"
         }
        ]
       }
      ]
     }
    },
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
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^[^_.]*zendesk[^_.]*\\.podcastgarage"
       }
      ]
     }
    }
   ],
   "tier": "core",
   "quote": "domain validation and DKIM CNAME records"
  },
  {
   "id": "zendesk_dkim_cname",
   "kind": "any_of",
   "checks": [
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
           "Name"
          ],
          "op": "regex",
          "value": "(?i)_domainkey"
         }
        ]
       }
      ]
     }
    },
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
         "Name"
        ],
        "op": "regex",
        "value": "(?i)_domainkey"
       }
      ]
     }
    }
   ],
   "tier": "core",
   "quote": "domain validation and DKIM CNAME records",
   "justify": "DKIM records live under the _domainkey label"
  },
  {
   "id": "google_dkim_txt",
   "kind": "any_of",
   "checks": [
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
          "value": "TXT"
         },
         {
          "path": [
           "Name"
          ],
          "op": "regex",
          "value": "(?i)^google[^.]*\\._domainkey\\."
         }
        ]
       }
      ]
     }
    },
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
        "value": "TXT"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^google[^.]*\\._domainkey\\."
       }
      ]
     }
    }
   ],
   "tier": "core",
   "quote": "our Google Workspace DKIM signing key",
   "justify": "Google Workspace DKIM uses the google selector"
  },
  {
   "id": "campaign_monitor_dkim_txt",
   "kind": "any_of",
   "checks": [
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
          "value": "TXT"
         },
         {
          "path": [
           "Name"
          ],
          "op": "regex",
          "value": "(?i)^([^g]|g[^o]).*_domainkey\\."
         }
        ]
       }
      ]
     }
    },
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
        "value": "TXT"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^([^g]|g[^o]).*_domainkey\\."
       }
      ]
     }
    }
   ],
   "tier": "core",
   "quote": "a DKIM TXT record",
   "justify": "a second DKIM TXT whose selector is not the Google one"
  },
  {
   "id": "campaign_monitor_subdomain_txt",
   "kind": "any_of",
   "checks": [
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
          "value": "TXT"
         },
         {
          "path": [
           "Name"
          ],
          "op": "regex",
          "value": "(?i)^.+\\.podcastgarage\\.org\\.?$"
         },
         {
          "path": [
           "ResourceRecords",
           "*"
          ],
          "op": "regex",
          "value": "v=spf1"
         }
        ]
       }
      ]
     }
    },
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
        "value": "TXT"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^.+\\.podcastgarage\\.org\\.?$"
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "v=spf1"
       }
      ]
     }
    }
   ],
   "tier": "core",
   "quote": "a dedicated SPF-aligned subdomain with its own TXT"
  },
  {
   "id": "campaign_monitor_subdomain_mx",
   "kind": "any_of",
   "checks": [
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
          "value": "MX"
         },
         {
          "path": [
           "Name"
          ],
          "op": "regex",
          "value": "(?i)^.+\\.podcastgarage\\.org\\.?$"
         }
        ]
       }
      ]
     }
    },
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
        "value": "MX"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^.+\\.podcastgarage\\.org\\.?$"
       }
      ]
     }
    }
   ],
   "tier": "core",
   "quote": "a dedicated SPF-aligned subdomain with its own TXT and MX records"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
