package intent.tf.row_338

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "oidc_provider",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_iam_openid_connect_provider"
    ],
    "where": []
   },
   "quote": "creates an IAM OpenID Connect identity provider for GitHub Actions"
  },
  {
   "id": "oidc_url",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_iam_openid_connect_provider"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "url"
    ],
    "op": "regex",
    "value": "token\\.actions\\.githubusercontent\\.com"
   },
   "quote": "using the token.actions.githubusercontent.com issuer"
  },
  {
   "id": "oidc_audience",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_iam_openid_connect_provider"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "client_id_list",
     "*"
    ],
    "op": "eq",
    "value": "sts.amazonaws.com"
   },
   "quote": "\"sts.amazonaws.com\" as the audience"
  },
  {
   "id": "tls_fetch",
   "tier": "core",
   "kind": "ref",
   "from": {
    "types": [
     "aws_iam_openid_connect_provider"
    ],
    "where": []
   },
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
   },
   "quote": "fetched from the issuer's TLS certificate"
  },
  {
   "id": "thumb_combo",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_openid_connect_provider"
      ],
      "where": [
       {
        "path": [
         "thumbprint_list"
        ],
        "op": "len_gte",
        "value": 3
       }
      ]
     },
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
        "value": "aws_iam_openid_connect_provider"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "thumbprint_list"
      ],
      "op": "regex",
      "value": "tls_certificate"
     }
    }
   ],
   "quote": "combines the CA fingerprints fetched from the issuer's TLS certificate with GitHub's two published thumbprints",
   "justify": "at least one fetched CA fingerprint plus GitHub's two published thumbprints gives three or more"
  },
  {
   "id": "roles_optional",
   "tier": "core",
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
       "gated"
      ],
      "op": "truthy"
     }
    ]
   },
   "quote": "support optionally creating GitHub-federated IAM roles",
   "justify": "optional capability checked as a declared, count/for_each-gated role"
  },
  {
   "id": "roles_federated",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "Federated|AssumeRoleWithWebIdentity"
     }
    },
    {
     "kind": "attr",
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
        "value": "data.aws_iam_policy_document"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "statement"
      ],
      "op": "regex",
      "value": "Federated|AssumeRoleWithWebIdentity"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "AssumeRoleWithWebIdentity"
     }
    }
   ],
   "quote": "GitHub-federated IAM roles",
   "justify": "federated roles assume via web identity"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
