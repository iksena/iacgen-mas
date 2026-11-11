package intent.cfn.row_018

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "b": {
   "types": [
    "AWS::Budgets::Budget"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "budget",
   "kind": "exists",
   "select": "b",
   "tier": "core",
   "quote": "creates a monthly cost budget"
  },
  {
   "id": "budget_monthly",
   "kind": "attr",
   "select": "b",
   "cond": {
    "path": [
     "Budget",
     "TimeUnit"
    ],
    "op": "eq",
    "value": "MONTHLY"
   },
   "tier": "core",
   "quote": "a monthly cost budget"
  },
  {
   "id": "budget_cost_type",
   "kind": "attr",
   "select": "b",
   "cond": {
    "path": [
     "Budget",
     "BudgetType"
    ],
    "op": "eq",
    "value": "COST"
   },
   "tier": "core",
   "quote": "cost budget"
  },
  {
   "id": "budget_amount",
   "kind": "attr",
   "select": "b",
   "cond": {
    "path": [
     "Budget",
     "BudgetLimit",
     "Amount"
    ],
    "op": "regex",
    "value": "^100(\\.0+)?$"
   },
   "tier": "core",
   "quote": "$100 USD"
  },
  {
   "id": "budget_unit",
   "kind": "attr",
   "select": "b",
   "cond": {
    "path": [
     "Budget",
     "BudgetLimit",
     "Unit"
    ],
    "op": "eq",
    "value": "USD"
   },
   "tier": "core",
   "quote": "$100 USD"
  },
  {
   "id": "alert_80",
   "kind": "attr",
   "select": "b",
   "cond": {
    "path": [
     "NotificationsWithSubscribers",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "Notification",
       "Threshold"
      ],
      "op": "eq",
      "value": 80
     },
     {
      "path": [
       "Notification",
       "NotificationType"
      ],
      "op": "eq",
      "value": "ACTUAL"
     },
     {
      "path": [
       "Notification",
       "ComparisonOperator"
      ],
      "op": "eq",
      "value": "GREATER_THAN"
     },
     {
      "path": [
       "Subscribers",
       "*",
       "SubscriptionType"
      ],
      "op": "eq",
      "value": "EMAIL"
     },
     {
      "path": [
       "Subscribers",
       "*",
       "Address"
      ],
      "op": "eq",
      "value": "email@example.com"
     }
    ]
   },
   "tier": "core",
   "quote": "email alerts sent to email@example.com when actual costs exceed 80%",
   "justify": "exceed implies GREATER_THAN"
  },
  {
   "id": "alert_99",
   "kind": "attr",
   "select": "b",
   "cond": {
    "path": [
     "NotificationsWithSubscribers",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "Notification",
       "Threshold"
      ],
      "op": "eq",
      "value": 99
     },
     {
      "path": [
       "Notification",
       "NotificationType"
      ],
      "op": "eq",
      "value": "ACTUAL"
     },
     {
      "path": [
       "Notification",
       "ComparisonOperator"
      ],
      "op": "eq",
      "value": "GREATER_THAN"
     },
     {
      "path": [
       "Subscribers",
       "*",
       "SubscriptionType"
      ],
      "op": "eq",
      "value": "EMAIL"
     },
     {
      "path": [
       "Subscribers",
       "*",
       "Address"
      ],
      "op": "eq",
      "value": "email@example.com"
     }
    ]
   },
   "tier": "core",
   "quote": "email alerts sent to email@example.com when actual costs exceed 80% and 99% of the budget",
   "justify": "exceed implies GREATER_THAN"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
