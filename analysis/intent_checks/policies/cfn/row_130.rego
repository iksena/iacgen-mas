package intent.cfn.row_130

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "hosted_zone",
   "kind": "exists",
   "tier": "core",
   "quote": "creates a public Route 53 hosted zone for the domain radiotopia.fm",
   "select": {
    "types": [
     "AWS::Route53::HostedZone"
    ],
    "where": [
     {
      "path": [
       "Name"
      ],
      "op": "regex",
      "value": "(?i)^radiotopia\\.fm\\.?$"
     }
    ]
   }
  },
  {
   "id": "zone_public",
   "tier": "core",
   "quote": "a public Route 53 hosted zone",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Route53::HostedZone"
      ],
      "where": []
     },
     "quantifier": "all",
     "cond": {
      "path": [
       "VPCs"
      ],
      "op": "absent"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Route53::HostedZone"
      ],
      "where": []
     },
     "quantifier": "all",
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
   "id": "records_in_zone",
   "kind": "any_of",
   "tier": "detail",
   "quote": "along with a comprehensive set of DNS record sets",
   "checks": [
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
    },
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
     "kind": "exists",
     "select": {
      "types": [
       "AWS::Route53::RecordSet"
      ],
      "where": [
       {
        "path": [
         "HostedZoneName"
        ],
        "op": "regex",
        "value": "(?i)radiotopia\\.fm"
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
         "HostedZoneName"
        ],
        "op": "regex",
        "value": "(?i)radiotopia\\.fm"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "txt_spf",
   "kind": "any_of",
   "tier": "core",
   "quote": "a TXT record on the apex containing an SPF policy",
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
        "value": "TXT"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^radiotopia\\.fm\\.?$"
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
          "value": "(?i)^radiotopia\\.fm\\.?$"
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
      ]
     }
    }
   ]
  },
  {
   "id": "txt_apex_values",
   "kind": "any_of",
   "tier": "detail",
   "quote": "plus two domain ownership verification tokens",
   "justify": "SPF plus two tokens makes at least three values on the apex TXT record",
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
        "value": "TXT"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^radiotopia\\.fm\\.?$"
       },
       {
        "path": [
         "ResourceRecords"
        ],
        "op": "len_gte",
        "value": 3
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
           "Name"
          ],
          "op": "regex",
          "value": "(?i)^radiotopia\\.fm\\.?$"
         },
         {
          "path": [
           "ResourceRecords"
          ],
          "op": "len_gte",
          "value": 3
         }
        ]
       }
      ]
     }
    }
   ]
  },
  {
   "id": "txt_dmarc_reject",
   "kind": "any_of",
   "tier": "core",
   "quote": "a DMARC TXT record with a reject policy",
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
        "value": "TXT"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^_dmarc\\.radiotopia\\.fm\\.?$"
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
          "value": "(?i)^_dmarc\\.radiotopia\\.fm\\.?$"
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
      ]
     }
    }
   ]
  },
  {
   "id": "mx_apex",
   "kind": "any_of",
   "tier": "core",
   "quote": "an MX record routing mail for the domain to a hosted email provider",
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
        "value": "MX"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^radiotopia\\.fm\\.?$"
       },
       {
        "path": [
         "ResourceRecords"
        ],
        "op": "present"
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
          "value": "MX"
         },
         {
          "path": [
           "Name"
          ],
          "op": "regex",
          "value": "(?i)^radiotopia\\.fm\\.?$"
         },
         {
          "path": [
           "ResourceRecords"
          ],
          "op": "present"
         }
        ]
       }
      ]
     }
    }
   ]
  },
  {
   "id": "apex_a",
   "kind": "any_of",
   "tier": "core",
   "quote": "a set of apex A records pointing at the static IP addresses of a third-party website hosting service",
   "justify": "a set of A records means more than one address",
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
        "value": "A"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^radiotopia\\.fm\\.?$"
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$"
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
          "value": "A"
         },
         {
          "path": [
           "Name"
          ],
          "op": "regex",
          "value": "(?i)^radiotopia\\.fm\\.?$"
         },
         {
          "path": [
           "ResourceRecords",
           "*"
          ],
          "op": "regex",
          "value": "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$"
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
    }
   ]
  },
  {
   "id": "www_cname",
   "kind": "any_of",
   "tier": "core",
   "quote": "a www CNAME alias to that same hosting service",
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
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^www\\.radiotopia\\.fm\\.?$"
       },
       {
        "path": [
         "ResourceRecords"
        ],
        "op": "present"
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
          "value": "(?i)^www\\.radiotopia\\.fm\\.?$"
         },
         {
          "path": [
           "ResourceRecords"
          ],
          "op": "present"
         }
        ]
       }
      ]
     }
    }
   ]
  },
  {
   "id": "alias_a_media",
   "tier": "core",
   "quote": "alias A and AAAA record pairs for several subdomains, including media, tower, v1, and plus, that each point at their own dedicated CloudFront distribution",
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
        "value": "A"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^media\\.radiotopia\\.fm\\.?$"
       },
       {
        "path": [
         "AliasTarget"
        ],
        "op": "regex",
        "value": "(?i)(cloudfront\\.net|Z2FDTNDATAQYW2)"
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
          "value": "A"
         },
         {
          "path": [
           "Name"
          ],
          "op": "regex",
          "value": "(?i)^media\\.radiotopia\\.fm\\.?$"
         },
         {
          "path": [
           "AliasTarget"
          ],
          "op": "regex",
          "value": "(?i)(cloudfront\\.net|Z2FDTNDATAQYW2)"
         }
        ]
       }
      ]
     }
    }
   ],
   "justify": "a CloudFront alias has a cloudfront.net target or the fixed CloudFront alias zone Z2FDTNDATAQYW2"
  },
  {
   "id": "alias_aaaa_media",
   "tier": "core",
   "quote": "alias A and AAAA record pairs for several subdomains, including media, tower, v1, and plus, that each point at their own dedicated CloudFront distribution",
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
        "value": "AAAA"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^media\\.radiotopia\\.fm\\.?$"
       },
       {
        "path": [
         "AliasTarget"
        ],
        "op": "regex",
        "value": "(?i)(cloudfront\\.net|Z2FDTNDATAQYW2)"
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
          "value": "AAAA"
         },
         {
          "path": [
           "Name"
          ],
          "op": "regex",
          "value": "(?i)^media\\.radiotopia\\.fm\\.?$"
         },
         {
          "path": [
           "AliasTarget"
          ],
          "op": "regex",
          "value": "(?i)(cloudfront\\.net|Z2FDTNDATAQYW2)"
         }
        ]
       }
      ]
     }
    }
   ],
   "justify": "a CloudFront alias has a cloudfront.net target or the fixed CloudFront alias zone Z2FDTNDATAQYW2"
  },
  {
   "id": "alias_a_tower",
   "tier": "core",
   "quote": "alias A and AAAA record pairs for several subdomains, including media, tower, v1, and plus, that each point at their own dedicated CloudFront distribution",
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
        "value": "A"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^tower\\.radiotopia\\.fm\\.?$"
       },
       {
        "path": [
         "AliasTarget"
        ],
        "op": "regex",
        "value": "(?i)(cloudfront\\.net|Z2FDTNDATAQYW2)"
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
          "value": "A"
         },
         {
          "path": [
           "Name"
          ],
          "op": "regex",
          "value": "(?i)^tower\\.radiotopia\\.fm\\.?$"
         },
         {
          "path": [
           "AliasTarget"
          ],
          "op": "regex",
          "value": "(?i)(cloudfront\\.net|Z2FDTNDATAQYW2)"
         }
        ]
       }
      ]
     }
    }
   ],
   "justify": "a CloudFront alias has a cloudfront.net target or the fixed CloudFront alias zone Z2FDTNDATAQYW2"
  },
  {
   "id": "alias_aaaa_tower",
   "tier": "core",
   "quote": "alias A and AAAA record pairs for several subdomains, including media, tower, v1, and plus, that each point at their own dedicated CloudFront distribution",
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
        "value": "AAAA"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^tower\\.radiotopia\\.fm\\.?$"
       },
       {
        "path": [
         "AliasTarget"
        ],
        "op": "regex",
        "value": "(?i)(cloudfront\\.net|Z2FDTNDATAQYW2)"
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
          "value": "AAAA"
         },
         {
          "path": [
           "Name"
          ],
          "op": "regex",
          "value": "(?i)^tower\\.radiotopia\\.fm\\.?$"
         },
         {
          "path": [
           "AliasTarget"
          ],
          "op": "regex",
          "value": "(?i)(cloudfront\\.net|Z2FDTNDATAQYW2)"
         }
        ]
       }
      ]
     }
    }
   ],
   "justify": "a CloudFront alias has a cloudfront.net target or the fixed CloudFront alias zone Z2FDTNDATAQYW2"
  },
  {
   "id": "alias_a_v1",
   "tier": "core",
   "quote": "alias A and AAAA record pairs for several subdomains, including media, tower, v1, and plus, that each point at their own dedicated CloudFront distribution",
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
        "value": "A"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^v1\\.radiotopia\\.fm\\.?$"
       },
       {
        "path": [
         "AliasTarget"
        ],
        "op": "regex",
        "value": "(?i)(cloudfront\\.net|Z2FDTNDATAQYW2)"
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
          "value": "A"
         },
         {
          "path": [
           "Name"
          ],
          "op": "regex",
          "value": "(?i)^v1\\.radiotopia\\.fm\\.?$"
         },
         {
          "path": [
           "AliasTarget"
          ],
          "op": "regex",
          "value": "(?i)(cloudfront\\.net|Z2FDTNDATAQYW2)"
         }
        ]
       }
      ]
     }
    }
   ],
   "justify": "a CloudFront alias has a cloudfront.net target or the fixed CloudFront alias zone Z2FDTNDATAQYW2"
  },
  {
   "id": "alias_aaaa_v1",
   "tier": "core",
   "quote": "alias A and AAAA record pairs for several subdomains, including media, tower, v1, and plus, that each point at their own dedicated CloudFront distribution",
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
        "value": "AAAA"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^v1\\.radiotopia\\.fm\\.?$"
       },
       {
        "path": [
         "AliasTarget"
        ],
        "op": "regex",
        "value": "(?i)(cloudfront\\.net|Z2FDTNDATAQYW2)"
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
          "value": "AAAA"
         },
         {
          "path": [
           "Name"
          ],
          "op": "regex",
          "value": "(?i)^v1\\.radiotopia\\.fm\\.?$"
         },
         {
          "path": [
           "AliasTarget"
          ],
          "op": "regex",
          "value": "(?i)(cloudfront\\.net|Z2FDTNDATAQYW2)"
         }
        ]
       }
      ]
     }
    }
   ],
   "justify": "a CloudFront alias has a cloudfront.net target or the fixed CloudFront alias zone Z2FDTNDATAQYW2"
  },
  {
   "id": "alias_a_plus",
   "tier": "core",
   "quote": "alias A and AAAA record pairs for several subdomains, including media, tower, v1, and plus, that each point at their own dedicated CloudFront distribution",
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
        "value": "A"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^plus\\.radiotopia\\.fm\\.?$"
       },
       {
        "path": [
         "AliasTarget"
        ],
        "op": "regex",
        "value": "(?i)(cloudfront\\.net|Z2FDTNDATAQYW2)"
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
          "value": "A"
         },
         {
          "path": [
           "Name"
          ],
          "op": "regex",
          "value": "(?i)^plus\\.radiotopia\\.fm\\.?$"
         },
         {
          "path": [
           "AliasTarget"
          ],
          "op": "regex",
          "value": "(?i)(cloudfront\\.net|Z2FDTNDATAQYW2)"
         }
        ]
       }
      ]
     }
    }
   ],
   "justify": "a CloudFront alias has a cloudfront.net target or the fixed CloudFront alias zone Z2FDTNDATAQYW2"
  },
  {
   "id": "alias_aaaa_plus",
   "tier": "core",
   "quote": "alias A and AAAA record pairs for several subdomains, including media, tower, v1, and plus, that each point at their own dedicated CloudFront distribution",
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
        "value": "AAAA"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^plus\\.radiotopia\\.fm\\.?$"
       },
       {
        "path": [
         "AliasTarget"
        ],
        "op": "regex",
        "value": "(?i)(cloudfront\\.net|Z2FDTNDATAQYW2)"
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
          "value": "AAAA"
         },
         {
          "path": [
           "Name"
          ],
          "op": "regex",
          "value": "(?i)^plus\\.radiotopia\\.fm\\.?$"
         },
         {
          "path": [
           "AliasTarget"
          ],
          "op": "regex",
          "value": "(?i)(cloudfront\\.net|Z2FDTNDATAQYW2)"
         }
        ]
       }
      ]
     }
    }
   ],
   "justify": "a CloudFront alias has a cloudfront.net target or the fixed CloudFront alias zone Z2FDTNDATAQYW2"
  },
  {
   "id": "distinct_cloudfront",
   "kind": "any_of",
   "tier": "detail",
   "quote": "that each point at their own dedicated CloudFront distribution",
   "justify": "four subdomains each with their own distribution",
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
        "value": "A"
       },
       {
        "path": [
         "AliasTarget"
        ],
        "op": "present"
       }
      ]
     },
     "distinct_path": [
      "AliasTarget",
      "DNSName"
     ],
     "min": 4
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
          "value": "A"
         },
         {
          "path": [
           "AliasTarget"
          ],
          "op": "present"
         }
        ]
       }
      ]
     },
     "distinct_path": [
      "RecordSets",
      "*",
      "AliasTarget",
      "DNSName"
     ],
     "min": 4
    }
   ]
  },
  {
   "id": "cloudfront_zone_id",
   "kind": "any_of",
   "tier": "detail",
   "quote": "CloudFront distribution",
   "justify": "Z2FDTNDATAQYW2 is the fixed alias hosted zone ID for CloudFront",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Route53::RecordSet"
      ],
      "where": [
       {
        "path": [
         "AliasTarget"
        ],
        "op": "present"
       }
      ]
     },
     "cond": {
      "path": [
       "AliasTarget",
       "HostedZoneId"
      ],
      "op": "eq",
      "value": "Z2FDTNDATAQYW2"
     },
     "quantifier": "all"
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
         "*",
         "AliasTarget",
         "HostedZoneId"
        ],
        "op": "present"
       }
      ]
     },
     "cond": {
      "path": [
       "RecordSets",
       "*",
       "AliasTarget",
       "HostedZoneId"
      ],
      "op": "eq",
      "value": "Z2FDTNDATAQYW2",
      "every": true
     },
     "quantifier": "all"
    }
   ]
  },
  {
   "id": "podcast_cname",
   "tier": "core",
   "quote": "a CNAME record for a podcast feed subdomain pointing at a feed-proxy service",
   "justify": "the prompt names no subdomain, so any name mentioning feed, podcast or rss",
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
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^[^.]*(feed|podcast|rss)[^.]*\\.radiotopia\\.fm\\.?$"
       },
       {
        "path": [
         "ResourceRecords"
        ],
        "op": "present"
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
          "value": "(?i)^[^.]*(feed|podcast|rss)[^.]*\\.radiotopia\\.fm\\.?$"
         },
         {
          "path": [
           "ResourceRecords"
          ],
          "op": "present"
         }
        ]
       }
      ]
     }
    }
   ]
  },
  {
   "id": "event_a_single",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a single A record for a special event subdomain",
   "justify": "a single A record has one address",
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
        "value": "A"
       },
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^[^.]+\\.radiotopia\\.fm\\.?$"
       },
       {
        "path": [
         "ResourceRecords"
        ],
        "op": "len_eq",
        "value": 1
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
          "value": "A"
         },
         {
          "path": [
           "Name"
          ],
          "op": "regex",
          "value": "(?i)^[^.]+\\.radiotopia\\.fm\\.?$"
         },
         {
          "path": [
           "ResourceRecords"
          ],
          "op": "len_eq",
          "value": 1
         }
        ]
       }
      ]
     }
    }
   ]
  },
  {
   "id": "acm_validation_media",
   "kind": "any_of",
   "tier": "detail",
   "quote": "Include the CNAME validation records that ACM issues for certificates on each of the CloudFront-backed subdomains",
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
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^_([^.]+\\.media|[^.]*media[^.]*)\\.radiotopia\\.fm\\.?$"
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "(?i)acm-validations"
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
          "value": "(?i)^_([^.]+\\.media|[^.]*media[^.]*)\\.radiotopia\\.fm\\.?$"
         },
         {
          "path": [
           "ResourceRecords",
           "*"
          ],
          "op": "regex",
          "value": "(?i)acm-validations"
         }
        ]
       }
      ]
     }
    }
   ]
  },
  {
   "id": "acm_validation_tower",
   "kind": "any_of",
   "tier": "detail",
   "quote": "Include the CNAME validation records that ACM issues for certificates on each of the CloudFront-backed subdomains",
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
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^_([^.]+\\.tower|[^.]*tower[^.]*)\\.radiotopia\\.fm\\.?$"
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "(?i)acm-validations"
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
          "value": "(?i)^_([^.]+\\.tower|[^.]*tower[^.]*)\\.radiotopia\\.fm\\.?$"
         },
         {
          "path": [
           "ResourceRecords",
           "*"
          ],
          "op": "regex",
          "value": "(?i)acm-validations"
         }
        ]
       }
      ]
     }
    }
   ]
  },
  {
   "id": "acm_validation_v1",
   "kind": "any_of",
   "tier": "detail",
   "quote": "Include the CNAME validation records that ACM issues for certificates on each of the CloudFront-backed subdomains",
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
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^_([^.]+\\.v1|[^.]*v1[^.]*)\\.radiotopia\\.fm\\.?$"
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "(?i)acm-validations"
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
          "value": "(?i)^_([^.]+\\.v1|[^.]*v1[^.]*)\\.radiotopia\\.fm\\.?$"
         },
         {
          "path": [
           "ResourceRecords",
           "*"
          ],
          "op": "regex",
          "value": "(?i)acm-validations"
         }
        ]
       }
      ]
     }
    }
   ]
  },
  {
   "id": "acm_validation_plus",
   "kind": "any_of",
   "tier": "detail",
   "quote": "Include the CNAME validation records that ACM issues for certificates on each of the CloudFront-backed subdomains",
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
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^_([^.]+\\.plus|[^.]*plus[^.]*)\\.radiotopia\\.fm\\.?$"
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "(?i)acm-validations"
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
          "value": "(?i)^_([^.]+\\.plus|[^.]*plus[^.]*)\\.radiotopia\\.fm\\.?$"
         },
         {
          "path": [
           "ResourceRecords",
           "*"
          ],
          "op": "regex",
          "value": "(?i)acm-validations"
         }
        ]
       }
      ]
     }
    }
   ]
  },
  {
   "id": "vendor_zendesk",
   "tier": "detail",
   "quote": "the CNAME and TXT verification and DKIM records required by the organization's third-party mail and marketing tools, including Zendesk, MailChimp, Squarespace, Campaign Monitor, and Google Workspace",
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
        "value": "(?i)^([^.]+\\.)+radiotopia\\.fm\\.?$"
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
          "value": "(?i)^([^.]+\\.)+radiotopia\\.fm\\.?$"
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
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "(?i)^\"?[a-z_-]*(zendesk)[a-z_-]*="
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
          "value": "(?i)^\"?[a-z_-]*(zendesk)[a-z_-]*="
         }
        ]
       }
      ]
     }
    }
   ]
  },
  {
   "id": "vendor_mailchimp",
   "tier": "detail",
   "quote": "the CNAME and TXT verification and DKIM records required by the organization's third-party mail and marketing tools, including Zendesk, MailChimp, Squarespace, Campaign Monitor, and Google Workspace",
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
        "value": "(?i)^([^.]+\\.)+radiotopia\\.fm\\.?$"
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "(?i)(mcsv|mailchimp|mandrill)"
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
          "value": "(?i)^([^.]+\\.)+radiotopia\\.fm\\.?$"
         },
         {
          "path": [
           "ResourceRecords",
           "*"
          ],
          "op": "regex",
          "value": "(?i)(mcsv|mailchimp|mandrill)"
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
        "value": "(?i)(mailchimp|mandrill)"
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
          "value": "(?i)(mailchimp|mandrill)"
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
        "value": "(?i)^\"?[a-z_-]*(mailchimp)[a-z_-]*="
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
          "value": "(?i)^\"?[a-z_-]*(mailchimp)[a-z_-]*="
         }
        ]
       }
      ]
     }
    }
   ]
  },
  {
   "id": "vendor_squarespace",
   "tier": "detail",
   "quote": "the CNAME and TXT verification and DKIM records required by the organization's third-party mail and marketing tools, including Zendesk, MailChimp, Squarespace, Campaign Monitor, and Google Workspace",
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
        "value": "(?i)^([^.]+\\.)+radiotopia\\.fm\\.?$"
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "(?i)(verif[a-z.-]*squarespace|squarespace[a-z_.-]*verif)"
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
          "value": "(?i)^([^.]+\\.)+radiotopia\\.fm\\.?$"
         },
         {
          "path": [
           "ResourceRecords",
           "*"
          ],
          "op": "regex",
          "value": "(?i)(verif[a-z.-]*squarespace|squarespace[a-z_.-]*verif)"
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
        "value": "(?i)squarespace"
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
        "value": "TXT"
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "(?i)^\"?[a-z_-]*(squarespace)[a-z_-]*="
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
          "value": "(?i)^\"?[a-z_-]*(squarespace)[a-z_-]*="
         }
        ]
       }
      ]
     }
    }
   ]
  },
  {
   "id": "vendor_campaignmonitor",
   "tier": "detail",
   "quote": "the CNAME and TXT verification and DKIM records required by the organization's third-party mail and marketing tools, including Zendesk, MailChimp, Squarespace, Campaign Monitor, and Google Workspace",
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
        "value": "(?i)^([^.]+\\.)+radiotopia\\.fm\\.?$"
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "(?i)(createsend|campaign-?monitor|cmail[0-9]*\\.)"
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
          "value": "(?i)^([^.]+\\.)+radiotopia\\.fm\\.?$"
         },
         {
          "path": [
           "ResourceRecords",
           "*"
          ],
          "op": "regex",
          "value": "(?i)(createsend|campaign-?monitor|cmail[0-9]*\\.)"
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
        "value": "(?i)^(cm|cmail[0-9]*)[-_.]|campaign-?monitor|createsend"
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
          "value": "(?i)^(cm|cmail[0-9]*)[-_.]|campaign-?monitor|createsend"
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
        "value": "(?i)^\"?[a-z_-]*(campaign-?monitor|createsend)[a-z_-]*="
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
          "value": "(?i)^\"?[a-z_-]*(campaign-?monitor|createsend)[a-z_-]*="
         }
        ]
       }
      ]
     }
    }
   ]
  },
  {
   "id": "vendor_google_workspace",
   "tier": "detail",
   "quote": "the CNAME and TXT verification and DKIM records required by the organization's third-party mail and marketing tools, including Zendesk, MailChimp, Squarespace, Campaign Monitor, and Google Workspace",
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
        "value": "(?i)^([^.]+\\.)+radiotopia\\.fm\\.?$"
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "(?i)(google-[a-z-]*verification|googlehosted|\\.google\\.com)"
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
          "value": "(?i)^([^.]+\\.)+radiotopia\\.fm\\.?$"
         },
         {
          "path": [
           "ResourceRecords",
           "*"
          ],
          "op": "regex",
          "value": "(?i)(google-[a-z-]*verification|googlehosted|\\.google\\.com)"
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
        "value": "(?i)google"
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
        "value": "TXT"
       },
       {
        "path": [
         "ResourceRecords",
         "*"
        ],
        "op": "regex",
        "value": "(?i)^\"?[a-z_-]*(google)[a-z_-]*="
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
          "value": "(?i)^\"?[a-z_-]*(google)[a-z_-]*="
         }
        ]
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
