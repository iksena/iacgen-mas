package intent.lib

import rego.v1

res_by_id := {r.id: r | some r in input.resources}

selector(spec, s) := spec.selectors[s] if is_string(s)

selector(spec, s) := s if is_object(s)

sel_ids(spec, s) := {r.id |
	sel := selector(spec, s)
	some r in input.resources
	r.type in sel.types
	every c in object.get(sel, "where", []) {
		cond_ok(r.values, c)
	}
}

path_values(obj, pattern) := {v |
	walk(obj, [p, v])
	count(p) == count(pattern)
	every i, seg in pattern {
		seg_ok(seg, p[i])
	}
}

seg_ok(seg, _) if seg == "*"

seg_ok(seg, actual) if seg == actual

cond_ok(values, c) if {
	not c.op in {"absent", "match", "none_eq"}
	not object.get(c, "every", false)
	some v in path_values(values, c.path)
	op_ok(c.op, v, object.get(c, "value", null))
}

cond_ok(values, c) if {
	not c.op in {"absent", "match", "none_eq"}
	object.get(c, "every", false) == true
	vals := path_values(values, c.path)
	count(vals) > 0
	every v in vals {
		op_ok(c.op, v, object.get(c, "value", null))
	}
}

cond_ok(values, c) if {
	c.op == "none_eq"
	count({v | some v in path_values(values, c.path); norm(v) == norm(c.value)}) == 0
}

cond_ok(values, c) if {
	c.op == "absent"
	count({v | some v in path_values(values, c.path); not is_null(v)}) == 0
}

cond_ok(values, c) if {
	c.op == "match"
	some v in path_values(values, c.path)
	every sc in c.value {
		subcond_ok(v, sc)
	}
}

subcond_ok(v, sc) if {
	not sc.op in {"absent", "none_eq"}
	some x in path_values(v, sc.path)
	op_ok(sc.op, x, object.get(sc, "value", null))
}

subcond_ok(v, sc) if {
	sc.op == "none_eq"
	count({x | some x in path_values(v, sc.path); norm(x) == norm(sc.value)}) == 0
}

subcond_ok(v, sc) if {
	sc.op == "absent"
	count({x | some x in path_values(v, sc.path); not is_null(x)}) == 0
}

norm(x) := lower(trim_space(sprintf("%v", [x])))

op_ok("eq", v, w) if norm(v) == norm(w)

op_ok("neq", v, w) if {
	not is_null(v)
	norm(v) != norm(w)
}

op_ok("in", v, w) if {
	some x in w
	norm(v) == norm(x)
}

op_ok("contains", v, w) if contains(norm(v), norm(w))

op_ok("regex", v, w) if regex.match(w, sprintf("%v", [v]))

op_ok("gte", v, w) if to_number(v) >= w

op_ok("lte", v, w) if to_number(v) <= w

op_ok("present", v, _) if {
	not is_null(v)
	v != ""
	v != []
	v != {}
}

op_ok("truthy", v, _) if norm(v) == "true"

op_ok("falsy", v, _) if norm(v) == "false"

op_ok("len_gte", v, w) if count(v) >= w

op_ok("len_eq", v, w) if count(v) == w

op_ok("has_kv", v, w) if {
	is_object(v)
	norm(first_of(v, ["Key", "key"])) == norm(w.key)
	norm(first_of(v, ["Value", "value"])) == norm(w.value)
}

op_ok("port_covers", v, w) if {
	is_object(v)
	to_number(first_of(v, ["from_port", "FromPort"])) <= w
	w <= to_number(first_of(v, ["to_port", "ToPort"]))
}

op_ok("port_covers", v, _) if {
	is_object(v)
	norm(first_of(v, ["protocol", "IpProtocol", "ip_protocol"])) in {"-1", "all"}
}

op_ok("glob_covers", v, w) if {
	is_string(v)
	glob.match(lower(v), [], lower(w))
}

first_of(obj, keys) := [obj[k] | some k in keys; k in object.keys(obj)][0]

leaf_ok(spec, c) if {
	c.kind == "exists"
	c.distinct_path
	n := count({norm(v) |
		some id in sel_ids(spec, c.select)
		some v in path_values(res_by_id[id].values, c.distinct_path)
		not is_null(v)
	})
	n >= object.get(c, "min", 1)
	n <= object.get(c, "max", 1000000)
}

leaf_ok(spec, c) if {
	c.kind == "exists"
	not c.distinct_path
	n := count(sel_ids(spec, c.select))
	n >= object.get(c, "min", 1)
	n <= object.get(c, "max", 1000000)
}

leaf_ok(spec, c) if {
	c.kind == "attr"
	object.get(c, "quantifier", "some") == "some"
	some id in sel_ids(spec, c.select)
	cond_ok(res_by_id[id].values, c.cond)
}

leaf_ok(spec, c) if {
	c.kind == "attr"
	c.quantifier == "all"
	ids := sel_ids(spec, c.select)
	count(ids) > 0
	every id in ids {
		cond_ok(res_by_id[id].values, c.cond)
	}
}

leaf_ok(spec, c) if {
	c.kind == "ref"
	some a in sel_ids(spec, c.from)
	some b in sel_ids(spec, c.to)
	res_by_id[b].cfg in res_by_id[a].refs
}

leaf_ok(spec, c) if {
	c.kind == "ref"
	object.get(c, "bidirectional", false) == true
	some a in sel_ids(spec, c.from)
	some b in sel_ids(spec, c.to)
	res_by_id[a].cfg in res_by_id[b].refs
}

leaf_ok(spec, c) if {
	c.kind == "join"
	some a in sel_ids(spec, c.from)
	some b in sel_ids(spec, c.to)
	a != b
	some va in path_values(res_by_id[a].values, c.from_path)
	not is_null(va)
	some vb in path_values(res_by_id[b].values, c.to_path)
	norm(va) == norm(vb)
}

check_ok(spec, c) if {
	not c.kind in {"any_of", "all_of"}
	leaf_ok(spec, c)
}

check_ok(spec, c) if {
	c.kind == "any_of"
	some sub in c.checks
	leaf_ok(spec, sub)
}

check_ok(spec, c) if {
	c.kind == "all_of"
	count(c.checks) > 0
	every sub in c.checks {
		leaf_ok(spec, sub)
	}
}

check_pass(spec, c) := true if check_ok(spec, c)

else := false

evaluate(spec) := {c.id: check_pass(spec, c) | some c in spec.checks}

leaves(c) := c.checks if c.kind in {"any_of", "all_of"}

else := [c]

leaf_targets(spec, l) := {"select": sel_ids(spec, l.select)} if l.kind in {"exists", "attr"}

leaf_targets(spec, l) := {"from": sel_ids(spec, l.from), "to": sel_ids(spec, l.to)} if l.kind in {"ref", "join"}

targets(spec) := {c.id: [leaf_targets(spec, l) | some l in leaves(c)] | some c in spec.checks}
