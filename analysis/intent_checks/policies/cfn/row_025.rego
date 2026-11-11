package intent.cfn.row_025

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "sec": {
   "types": [
    "AWS::SecretsManager::Secret"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "secret",
   "kind": "exists",
   "select": "sec",
   "tier": "core",
   "quote": "creates a Secrets Manager secret"
  },
  {
   "id": "name",
   "kind": "attr",
   "select": "sec",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "eq",
    "value": "MyRDSSecret4dbuser1"
   },
   "tier": "core",
   "quote": "the secret named \"MyRDSSecret4dbuser1\""
  },
  {
   "id": "username",
   "kind": "attr",
   "select": "sec",
   "cond": {
    "path": [
     "GenerateSecretString",
     "SecretStringTemplate"
    ],
    "op": "contains",
    "value": "dbuser1"
   },
   "tier": "core",
   "quote": "a username of \"dbuser1\""
  },
  {
   "id": "generated_password",
   "kind": "attr",
   "select": "sec",
   "cond": {
    "path": [
     "GenerateSecretString",
     "GenerateStringKey"
    ],
    "op": "regex",
    "value": "(?i)pass|pwd"
   },
   "tier": "core",
   "quote": "a dynamically generated password",
   "justify": "the generated key holds the password, so its name says so"
  },
  {
   "id": "length_30",
   "kind": "attr",
   "select": "sec",
   "cond": {
    "path": [
     "GenerateSecretString",
     "PasswordLength"
    ],
    "op": "eq",
    "value": 30
   },
   "tier": "core",
   "quote": "password of 30 characters"
  },
  {
   "id": "excluded_chars",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::SecretsManager::Secret"
      ],
      "where": [
       {
        "path": [
         "GenerateSecretString",
         "ExcludeCharacters"
        ],
        "op": "contains",
        "value": "'"
       },
       {
        "path": [
         "GenerateSecretString",
         "ExcludeCharacters"
        ],
        "op": "contains",
        "value": "\""
       },
       {
        "path": [
         "GenerateSecretString",
         "ExcludeCharacters"
        ],
        "op": "contains",
        "value": "/"
       },
       {
        "path": [
         "GenerateSecretString",
         "ExcludeCharacters"
        ],
        "op": "contains",
        "value": "\\"
       },
       {
        "path": [
         "GenerateSecretString",
         "ExcludeCharacters"
        ],
        "op": "contains",
        "value": ";"
       },
       {
        "path": [
         "GenerateSecretString",
         "ExcludeCharacters"
        ],
        "op": "contains",
        "value": "("
       },
       {
        "path": [
         "GenerateSecretString",
         "ExcludeCharacters"
        ],
        "op": "contains",
        "value": ")"
       },
       {
        "path": [
         "GenerateSecretString",
         "ExcludeCharacters"
        ],
        "op": "contains",
        "value": "{"
       },
       {
        "path": [
         "GenerateSecretString",
         "ExcludeCharacters"
        ],
        "op": "contains",
        "value": "}"
       },
       {
        "path": [
         "GenerateSecretString",
         "ExcludeCharacters"
        ],
        "op": "contains",
        "value": "["
       },
       {
        "path": [
         "GenerateSecretString",
         "ExcludeCharacters"
        ],
        "op": "contains",
        "value": "]"
       },
       {
        "path": [
         "GenerateSecretString",
         "ExcludeCharacters"
        ],
        "op": "contains",
        "value": "<"
       },
       {
        "path": [
         "GenerateSecretString",
         "ExcludeCharacters"
        ],
        "op": "contains",
        "value": ">"
       },
       {
        "path": [
         "GenerateSecretString",
         "ExcludeCharacters"
        ],
        "op": "contains",
        "value": "="
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "sec",
     "cond": {
      "path": [
       "GenerateSecretString",
       "ExcludePunctuation"
      ],
      "op": "truthy"
     }
    }
   ],
   "quote": "excluding single quotes, double quotes, slashes, backslashes, semicolons, parentheses, curly braces, square brackets, angle brackets, spaces, and equals signs",
   "justify": "each listed punctuation character is a literal exclusion named in the prompt; ExcludePunctuation removes all of them too"
  },
  {
   "id": "excluded_space",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "sec",
     "cond": {
      "path": [
       "GenerateSecretString",
       "ExcludeCharacters"
      ],
      "op": "regex",
      "value": " "
     }
    },
    {
     "kind": "attr",
     "select": "sec",
     "cond": {
      "path": [
       "GenerateSecretString",
       "IncludeSpace"
      ],
      "op": "absent"
     }
    },
    {
     "kind": "attr",
     "select": "sec",
     "cond": {
      "path": [
       "GenerateSecretString",
       "IncludeSpace"
      ],
      "op": "eq",
      "value": false
     }
    }
   ],
   "quote": "angle brackets, spaces, and equals signs",
   "justify": "generated passwords contain no spaces unless IncludeSpace is set, so omitting it also excludes spaces"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
