package intent.cfn.row_112

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "nq": {
   "types": [
    "AWS::Athena::NamedQuery"
   ],
   "where": []
  },
  "glue_db": {
   "types": [
    "AWS::Glue::Database"
   ],
   "where": [
    {
     "path": [
      "DatabaseInput",
      "Name"
     ],
     "op": "eq",
     "value": "appstream-usage"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "named_queries",
   "kind": "exists",
   "tier": "core",
   "quote": "creates a set of Amazon Athena named queries",
   "select": "nq",
   "min": 5,
   "justify": "five query topics are listed"
  },
  {
   "id": "database_appstream_usage",
   "kind": "any_of",
   "tier": "core",
   "quote": "using a database named \"appstream-usage\"",
   "checks": [
    {
     "kind": "attr",
     "select": "nq",
     "cond": {
      "path": [
       "Database"
      ],
      "op": "eq",
      "value": "appstream-usage"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Athena::NamedQuery"
      ],
      "where": [
       {
        "path": [
         "Database",
         "ref"
        ],
        "op": "present"
       }
      ]
     },
     "to": "glue_db"
    }
   ]
  },
  {
   "id": "queries_run_against_database",
   "kind": "attr",
   "tier": "core",
   "quote": "that the queries run against",
   "select": "nq",
   "cond": {
    "path": [
     "Database"
    ],
    "op": "regex",
    "value": "(?i)^appstream-usage$|\"ref\""
   },
   "quantifier": "all",
   "justify": "every query names the stated database, literally or by a reference to the database resource"
  },
  {
   "id": "q_avg_session_length",
   "kind": "any_of",
   "tier": "core",
   "quote": "average session length per stack",
   "checks": [
    {
     "kind": "attr",
     "select": "nq",
     "cond": {
      "path": [
       "QueryString"
      ],
      "op": "regex",
      "value": "(?is)avg.{0,300}stack|stack.{0,300}avg"
     }
    }
   ]
  },
  {
   "id": "q_daily_sessions",
   "kind": "any_of",
   "tier": "core",
   "quote": "daily session counts",
   "checks": [
    {
     "kind": "attr",
     "select": "nq",
     "cond": {
      "path": [
       "QueryString"
      ],
      "op": "regex",
      "value": "(?is)select\\s.{0,300}(date|day|substr).{0,300}count\\s*\\(|count\\s*\\(.{0,400}group\\s+by.{0,100}(date|day|substr)"
     }
    }
   ]
  },
  {
   "id": "q_all_sessions",
   "kind": "any_of",
   "tier": "core",
   "quote": "all session details",
   "checks": [
    {
     "kind": "attr",
     "select": "nq",
     "cond": {
      "path": [
       "QueryString"
      ],
      "op": "regex",
      "value": "(?is)select\\s+\\*\\s+from"
     }
    },
    {
     "kind": "attr",
     "select": "nq",
     "cond": {
      "path": [
       "Name"
      ],
      "op": "regex",
      "value": "(?i)(all|every).{0,15}session|session.{0,15}detail"
     }
    },
    {
     "kind": "attr",
     "select": "nq",
     "cond": {
      "path": [
       "Description"
      ],
      "op": "regex",
      "value": "(?i)(all|every).{0,15}session|session.{0,15}detail"
     }
    }
   ],
   "justify": "all details means SELECT * or a query named for them"
  },
  {
   "id": "q_streaming_hours_user",
   "kind": "any_of",
   "tier": "core",
   "quote": "streaming hours per user",
   "checks": [
    {
     "kind": "attr",
     "select": "nq",
     "cond": {
      "path": [
       "QueryString"
      ],
      "op": "regex",
      "value": "(?is)user.{0,400}sum\\s*\\(.{0,300}(3600|hour|60\\s*/\\s*60|60\\s*\\*\\s*60)|sum\\s*\\(.{0,300}(3600|hour|60\\s*/\\s*60|60\\s*\\*\\s*60).{0,400}group\\s+by.{0,100}user"
     }
    }
   ]
  },
  {
   "id": "q_unique_users_app",
   "kind": "any_of",
   "tier": "core",
   "quote": "unique users per application",
   "checks": [
    {
     "kind": "attr",
     "select": "nq",
     "cond": {
      "path": [
       "QueryString"
      ],
      "op": "regex",
      "value": "(?is)distinct[\\s(].{0,100}user.{0,400}\\bapp(lication)?(_\\w+)?\\b|\\bapp(lication)?(_\\w+)?\\b.{0,400}distinct[\\s(].{0,100}user|distinct[\\s(].{0,100}\\bapp(lication)?(_\\w+)?\\b.{0,200}user"
     }
    }
   ]
  },
  {
   "id": "q_previous_month",
   "kind": "any_of",
   "tier": "detail",
   "quote": "current and previous month comparisons",
   "checks": [
    {
     "kind": "attr",
     "select": "nq",
     "cond": {
      "path": [
       "QueryString"
      ],
      "op": "regex",
      "value": "(?i)-\\s*1|prev|last_month|interval"
     }
    },
    {
     "kind": "attr",
     "select": "nq",
     "cond": {
      "path": [
       "Name"
      ],
      "op": "regex",
      "value": "(?i)prev|last"
     }
    },
    {
     "kind": "attr",
     "select": "nq",
     "cond": {
      "path": [
       "Description"
      ],
      "op": "regex",
      "value": "(?i)prev|last"
     }
    }
   ]
  },
  {
   "id": "q_current_month",
   "kind": "any_of",
   "tier": "detail",
   "quote": "current and previous month comparisons",
   "checks": [
    {
     "kind": "attr",
     "select": "nq",
     "cond": {
      "path": [
       "QueryString"
      ],
      "op": "regex",
      "value": "(?i)current_date\\s*[^-\\s]|now\\(\\)\\s*[^-\\s]|curr_mo|current_month|this_month"
     }
    },
    {
     "kind": "attr",
     "select": "nq",
     "cond": {
      "path": [
       "Name"
      ],
      "op": "regex",
      "value": "(?i)curr|this"
     }
    },
    {
     "kind": "attr",
     "select": "nq",
     "cond": {
      "path": [
       "Description"
      ],
      "op": "regex",
      "value": "(?i)curr|this"
     }
    }
   ]
  },
  {
   "id": "x_count_pairs",
   "kind": "exists",
   "tier": "extra",
   "select": "nq",
   "min": 10
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
