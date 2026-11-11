package intent.tf.row_321

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "provider": {
   "types": [
    "aws_iam_openid_connect_provider"
   ],
   "where": []
  },
  "role": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "Sentinel-OIDC-Organizations-ReadOnly"
    }
   ]
  },
  "attach": {
   "types": [
    "aws_iam_role_policy_attachment",
    "aws_iam_policy_attachment"
   ],
   "where": [
    {
     "path": [
      "policy_arn"
     ],
     "op": "regex",
     "value": "AWSOrganizationsReadOnlyAccess$"
    }
   ]
  },
  "decl_doc_provider": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "data.aws_iam_policy_document"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "oidc_provider",
   "kind": "exists",
   "tier": "core",
   "quote": "creates an IAM OpenID Connect identity provider",
   "select": "provider"
  },
  {
   "id": "oidc_url",
   "kind": "attr",
   "tier": "core",
   "quote": "issuer https://sts.windows.net/<tenant id>/",
   "justify": "issuer URL is built from the stated tenant id",
   "select": "provider",
   "cond": {
    "path": [
     "url"
    ],
    "op": "regex",
    "value": "^https://sts\\.windows\\.net/221ca1d3-b3f2-4346-8abc-88f802495c7d/?$"
   }
  },
  {
   "id": "oidc_client_id",
   "kind": "attr",
   "tier": "core",
   "quote": "client ID \"c8b9cf86-e2b4-4428-b356-14313412a4d1\"",
   "select": "provider",
   "cond": {
    "path": [
     "client_id_list",
     "*"
    ],
    "op": "eq",
    "value": "c8b9cf86-e2b4-4428-b356-14313412a4d1"
   }
  },
  {
   "id": "thumbprint",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a thumbprint taken from the issuer TLS certificate",
   "checks": [
    {
     "kind": "ref",
     "from": "provider",
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.tls_certificate"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "provider",
     "cond": {
      "path": [
       "thumbprint_list",
       "*"
      ],
      "op": "regex",
      "value": "^[0-9a-fA-F]{40}$"
     }
    }
   ]
  },
  {
   "id": "role_named",
   "kind": "exists",
   "tier": "core",
   "quote": "an IAM role named \"Sentinel-OIDC-Organizations-ReadOnly\"",
   "select": "role"
  },
  {
   "id": "web_identity",
   "kind": "any_of",
   "tier": "core",
   "quote": "that this provider can assume via web identity",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "AssumeRoleWithWebIdentity"
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_iam_role"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "AssumeRoleWithWebIdentity"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "role",
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "AssumeRoleWithWebIdentity"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "provider_trusted",
   "kind": "any_of",
   "tier": "core",
   "quote": "this provider can assume",
   "checks": [
    {
     "kind": "ref",
     "from": "role",
     "to": "provider"
    },
    {
     "kind": "ref",
     "from": "decl_doc_provider",
     "to": "provider"
    }
   ]
  },
  {
   "id": "audience_condition",
   "kind": "any_of",
   "tier": "detail",
   "quote": "when the token audience matches that client ID",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "(?i)(:aud|audience|c8b9cf86-e2b4-4428-b356-14313412a4d1)"
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_iam_role"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)(:aud|audience|c8b9cf86-e2b4-4428-b356-14313412a4d1)"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "role",
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)(:aud|audience|c8b9cf86-e2b4-4428-b356-14313412a4d1)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "managed_policy",
   "kind": "any_of",
   "tier": "core",
   "quote": "should have the AWS managed AWSOrganizationsReadOnlyAccess policy attached",
   "checks": [
    {
     "kind": "ref",
     "from": "attach",
     "to": "role"
    },
    {
     "kind": "join",
     "from": "attach",
     "from_path": [
      "role"
     ],
     "to": "role",
     "to_path": [
      "name"
     ]
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "managed_policy_arns",
       "*"
      ],
      "op": "regex",
      "value": "AWSOrganizationsReadOnlyAccess$"
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
