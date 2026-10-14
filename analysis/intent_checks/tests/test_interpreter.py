#!/usr/bin/env python3
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import intent_core as ic

INPUT = {'meta': {'lang': 'tf', 'mode': 'plan', 'warnings': []}, 'resources': [
    {'id': 'aws_vpc.main', 'cfg': 'aws_vpc.main', 'type': 'aws_vpc', 'refs': [],
     'values': {'cidr_block': '10.0.0.0/16', 'tags': {'Name': 'main'}}},
    {'id': 'aws_security_group.web', 'cfg': 'aws_security_group.web', 'type': 'aws_security_group',
     'refs': ['aws_vpc.main'],
     'values': {'name': 'web', 'ingress': [{'from_port': 443, 'to_port': 443, 'protocol': 'tcp',
                                            'cidr_blocks': ['0.0.0.0/0']}],
                'egress': [{'from_port': 0, 'to_port': 0, 'protocol': '-1', 'cidr_blocks': ['10.0.0.0/16']}]}},
    {'id': 'aws_iam_policy.p', 'cfg': 'aws_iam_policy.p', 'type': 'aws_iam_policy', 'refs': [],
     'values': {'Statement': [{'Action': ['s3:Get*', 'logs:PutLogEvents'], 'Effect': 'Allow'}]}},
    {'id': 'aws_cloudwatch_log_group.lg', 'cfg': 'aws_cloudwatch_log_group.lg', 'type': 'aws_cloudwatch_log_group',
     'refs': [], 'values': {'name': '/app/logs', 'retention_in_days': 30}},
    {'id': 'aws_cloudwatch_log_metric_filter.f', 'cfg': 'aws_cloudwatch_log_metric_filter.f',
     'type': 'aws_cloudwatch_log_metric_filter', 'refs': [],
     'values': {'log_group_name': '/app/logs', 'metric_transformation': [{'name': 'Errors'}]}},
    {'id': '__output__.vpc_id', 'cfg': '__output__.vpc_id', 'type': '__output__', 'refs': ['aws_vpc.main'],
     'values': {'name': 'vpc_id', 'value': None}},
    {'id': '__declared__.aws_sqs_queue.dlq', 'cfg': '__declared__.aws_sqs_queue.dlq', 'type': '__declared__',
     'refs': [], 'values': {'type': 'aws_sqs_queue', 'name': 'dlq', 'gated': True, 'gate': 'var.dlq ? 1 : 0',
                            'properties': {'fifo_queue': True}}},
]}

SG = {'types': ['aws_security_group']}
POL = {'types': ['aws_iam_policy']}
CHECKS_PASS = [
    {'id': 'vpc', 'kind': 'exists', 'select': {'types': ['aws_vpc'], 'where': [
        {'path': 'cidr_block', 'op': 'eq', 'value': '10.0.0.0/16'}]}},
    {'id': 'count', 'kind': 'exists', 'select': SG, 'min': 1, 'max': 1},
    {'id': 'match', 'kind': 'attr', 'select': SG, 'cond': {'path': 'ingress.*', 'op': 'match', 'value': [
        {'path': '', 'op': 'port_covers', 'value': 443}, {'path': 'cidr_blocks.*', 'op': 'eq', 'value': '0.0.0.0/0'}]}},
    {'id': 'every', 'kind': 'attr', 'select': SG, 'cond': {'path': 'ingress.*.from_port', 'op': 'eq',
                                                          'value': 443, 'every': True}},
    {'id': 'none_eq', 'kind': 'attr', 'select': SG, 'cond': {'path': 'egress.*.cidr_blocks.*', 'op': 'none_eq',
                                                            'value': '0.0.0.0/0'}},
    {'id': 'port_all_proto', 'kind': 'attr', 'select': SG, 'cond': {'path': 'egress.*', 'op': 'port_covers',
                                                                   'value': 8080}},
    {'id': 'glob', 'kind': 'attr', 'select': POL, 'cond': {'path': 'Statement.*.Action.*', 'op': 'glob_covers',
                                                          'value': 's3:GetObject'}},
    {'id': 'regex', 'kind': 'attr', 'select': {'types': ['aws_cloudwatch_log_group']},
     'cond': {'path': 'name', 'op': 'regex', 'value': '^/app/'}},
    {'id': 'gte', 'kind': 'attr', 'select': {'types': ['aws_cloudwatch_log_group']},
     'cond': {'path': 'retention_in_days', 'op': 'gte', 'value': 14}},
    {'id': 'ref', 'kind': 'ref', 'from': SG, 'to': {'types': ['aws_vpc']}},
    {'id': 'join', 'kind': 'join', 'from': {'types': ['aws_cloudwatch_log_metric_filter']},
     'from_path': 'log_group_name', 'to': {'types': ['aws_cloudwatch_log_group']}, 'to_path': 'name'},
    {'id': 'output', 'kind': 'ref', 'from': {'types': ['__output__']}, 'to': {'types': ['aws_vpc']}},
    {'id': 'declared', 'kind': 'attr', 'select': {'types': ['__declared__'], 'where': [
        {'path': 'type', 'op': 'eq', 'value': 'aws_sqs_queue'}]},
     'cond': {'path': 'properties.fifo_queue', 'op': 'truthy'}},
    {'id': 'any_of', 'kind': 'any_of', 'checks': [
        {'kind': 'exists', 'select': {'types': ['aws_nonexistent']}},
        {'kind': 'exists', 'select': {'types': ['aws_vpc']}}]},
    {'id': 'all_of', 'kind': 'all_of', 'checks': [
        {'kind': 'exists', 'select': {'types': ['aws_vpc']}}, {'kind': 'exists', 'select': SG}]},
]
CHECKS_FAIL = [
    {'id': 'f_eq', 'kind': 'attr', 'select': SG, 'cond': {'path': 'name', 'op': 'eq', 'value': 'db'}},
    {'id': 'f_every', 'kind': 'attr', 'select': SG, 'cond': {'path': 'egress.*.from_port', 'op': 'eq',
                                                            'value': 443, 'every': True}},
    {'id': 'f_none_eq', 'kind': 'attr', 'select': SG, 'cond': {'path': 'ingress.*.cidr_blocks.*',
                                                              'op': 'none_eq', 'value': '0.0.0.0/0'}},
    {'id': 'f_glob', 'kind': 'attr', 'select': POL, 'cond': {'path': 'Statement.*.Action.*', 'op': 'glob_covers',
                                                            'value': 's3:PutObject'}},
    {'id': 'f_join', 'kind': 'join', 'from': {'types': ['aws_cloudwatch_log_metric_filter']},
     'from_path': 'metric_transformation.*.name', 'to': {'types': ['aws_cloudwatch_log_group']}, 'to_path': 'name'},
    {'id': 'f_ref', 'kind': 'ref', 'from': {'types': ['aws_vpc']}, 'to': SG},
    {'id': 'f_count', 'kind': 'exists', 'select': SG, 'min': 2},
    {'id': 'f_all_of', 'kind': 'all_of', 'checks': [
        {'kind': 'exists', 'select': {'types': ['aws_vpc']}}, {'kind': 'exists', 'select': {'types': ['aws_x']}}]},
]
PROMPT = 'A web security group in a VPC with logging and a policy.'


def with_meta(checks):
    return [{**c, 'tier': 'core', 'quote': 'A web security group', 'justify': 'synthetic test'} for c in checks]


def main():
    tmp = Path(tempfile.mkdtemp())
    for name in ('SPECS', 'POLICIES', 'FIXTURES', 'VALIDATION'):
        setattr(ic, name, tmp / name.lower())
    lang, row = 'tf', 9999
    info = {'lang': lang, 'row_number': row, 'prompt': PROMPT, 'gt_hash': 'g', 'prompt_hash': 'p'}
    ic.fixture_path(lang, row).parent.mkdir(parents=True)
    ic.fixture_path(lang, row).write_text(json.dumps(INPUT))

    def write_spec(checks):
        spec = {'lang': lang, 'row_number': row, 'source_hash': {'gt': 'g', 'prompt': 'p'},
                'checks': with_meta(checks)}
        ic.spec_path(lang, row).parent.mkdir(parents=True, exist_ok=True)
        ic.spec_path(lang, row).write_text(json.dumps(spec))
        return spec

    failures = []
    spec = write_spec(CHECKS_PASS + CHECKS_FAIL)
    assert not ic.structural_errors(spec, info), ic.structural_errors(spec, info)
    ic.generate_policy(lang, row)
    single = ic.opa_eval(lang, row, INPUT)
    batch = ic.opa_eval_many(lang, row, {'a': INPUT, 'b': {'meta': {}, 'resources': []}})
    if batch['a'] != single:
        failures.append('batched evaluation disagrees with single evaluation')
    if any(batch['b'].values()):
        failures.append(f'checks pass on empty input: {[k for k, v in batch["b"].items() if v]}')
    for c in CHECKS_PASS:
        if single.get(c['id']) is not True:
            failures.append(f'expected PASS: {c["id"]}')
    for c in CHECKS_FAIL:
        if single.get(c['id']) is not False:
            failures.append(f'expected FAIL: {c["id"]}')

    write_spec(CHECKS_PASS)
    rep = ic.validate(lang, row, info)
    if rep['status'] != 'valid':
        failures.append(f'harness rejects a good spec: {rep}')

    write_spec(CHECKS_PASS + [
        {'id': 'bad_always', 'kind': 'attr', 'select': POL, 'cond': {'path': 'Statement.*.Effect', 'op': 'regex',
                                                                   'value': '.*'}}])
    rep = ic.validate(lang, row, info)
    if 'bad_always' not in rep['mutation_survivors']:
        failures.append(f'harness missed an always-true check: {rep["mutation_survivors"]}')

    bad_quote = write_spec(CHECKS_PASS)
    bad_quote['checks'][0]['quote'] = 'not in the prompt'
    if not ic.structural_errors(bad_quote, info):
        failures.append('structural check accepted a non-verbatim quote')
    curly = dict(info, prompt='The stack’s bucket')
    ok_quote = {**bad_quote, 'checks': [{**bad_quote['checks'][0], 'quote': "stack's bucket"}]}
    if any('verbatim' in e for e in ic.structural_errors(ok_quote, curly)):
        failures.append('curly apostrophe not normalised in quote matching')

    lint_info = dict(info, prompt='We need an S3 bucket named data-lake with versioning, '
                                  'and a CloudWatch alarm on write throttle events across two subnets.')
    def lint(checks):
        return ic.strictness_flags({'checks': [{**c, 'tier': 'core', 'quote': 'x'} for c in checks]}, lint_info)
    gt_only = lint([{'id': 'ip', 'kind': 'attr', 'select': SG,
                     'cond': {'path': 'cidr', 'op': 'eq', 'value': '198.185.159.144'}},
                    {'id': 'az', 'kind': 'attr', 'select': SG,
                     'cond': {'path': 'availability_zone', 'op': 'eq', 'value': 'us-east-1a'}},
                    {'id': 'cnt', 'kind': 'exists', 'select': SG, 'min': 12}])
    if {f['check'] for f in gt_only} != {'ip', 'az', 'cnt'}:
        failures.append(f'lint missed GT-only values: {gt_only}')
    translated = lint([{'id': 'metric', 'kind': 'attr', 'select': SG,
                        'cond': {'path': 'MetricName', 'op': 'eq', 'value': 'WriteThrottleEvents'}},
                       {'id': 'name', 'kind': 'attr', 'select': SG,
                        'cond': {'path': 'BucketName', 'op': 'eq', 'value': 'data-lake'}},
                       {'id': 'type', 'kind': 'exists', 'select': {'types': ['__declared__'], 'where': [
                           {'path': 'type', 'op': 'eq', 'value': 'aws_s3_bucket_versioning'}]}}])
    if translated:
        failures.append(f'lint flagged prompt-stated / translated values: {translated}')
    justified = ic.strictness_flags({'checks': [{'id': 'az', 'kind': 'attr', 'select': SG, 'tier': 'core',
        'quote': 'x', 'justify': 'prompt names the AZ', 'cond': {'path': 'az', 'op': 'eq', 'value': 'us-east-1a'}}]},
        lint_info)
    if not justified or not all(f['justified'] for f in justified):
        failures.append('justify did not clear the lint flag')
    write_spec(CHECKS_PASS)
    unjust = json.loads(ic.spec_path(lang, row).read_text())
    for c in unjust['checks']:
        c.pop('justify', None)
    ic.spec_path(lang, row).write_text(json.dumps(unjust))
    if ic.validate(lang, row, info)['status'] == 'valid':
        failures.append('unjustified strictness flags did not invalidate the spec')

    hcl = '''resource "aws_x" "a" {
  protocol_type = "HTTP"
  tags = { Env = "dev" }
  ingress { from_port = 80 }
  ingress { from_port = 443 }
  lifecycle { prevent_destroy = true }
  dynamic "entry" {
    for_each = var.cidrs
    content { cidr = entry.value }
  }
  name = var.n
}
variable "n" { default = "api" }'''
    vals = [r for r in ic.normalize_tf_static({'m.tf': hcl})['resources'] if r['type'] == 'aws_x'][0]['values']
    want = {'protocol_type': 'HTTP', 'tags': {'Env': 'dev'}, 'name': 'api'}
    if any(vals.get(k) != v for k, v in want.items()) or vals.get('ingress') != [{'from_port': 80}, {'from_port': 443}] \
            or vals.get('lifecycle') != [{'prevent_destroy': True}] or 'content' not in vals.get('dynamic', {}).get('entry', {}):
        failures.append(f'static HCL shape differs from plan shape: {vals}')

    if failures:
        print('FAILED:\n  ' + '\n  '.join(failures))
        sys.exit(1)
    print(f'all interpreter/harness tests passed ({len(CHECKS_PASS)} pass-cases, {len(CHECKS_FAIL)} fail-cases)')


if __name__ == '__main__':
    main()
