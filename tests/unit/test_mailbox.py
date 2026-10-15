import json
import pytest
from core.review_mailbox import ReviewMailboxProvider, ReviewPending


def test_pause_replay_and_prompt_change_invalidate_previous_review(tmp_path):
    provider = ReviewMailboxProvider(tmp_path)
    messages = [{"role": "user", "content": "Review actual code A"}]
    with pytest.raises(ReviewPending) as pending:
        provider.chat(messages)
    request = json.loads(pending.value.request_path.read_text(encoding="utf-8"))
    pending.value.response_path.write_text(json.dumps({"request_id": request['request_id'], 'response': {'status': 'NO_FINDING'}}))
    assert provider.chat(messages) == {'status': 'NO_FINDING'}
    with pytest.raises(ReviewPending):
        provider.chat([{'role': 'user', 'content': 'Review changed binary code B'}])
    assert len(list(tmp_path.glob('*.request.json'))) == 2


def test_wrong_response_identity_cannot_be_replayed(tmp_path):
    provider = ReviewMailboxProvider(tmp_path)
    with pytest.raises(ReviewPending) as pending:
        provider.chat([])
    pending.value.response_path.write_text(json.dumps({'request_id': 'different', 'response': {'status': 'SUPPORTED'}}))
    with pytest.raises(ValueError, match='identity'):
        provider.chat([])


def test_pause_is_not_converted_into_an_analysis_failure(tmp_path):
    provider = ReviewMailboxProvider(tmp_path)
    with pytest.raises(ReviewPending):
        try:
            provider.chat([])
        except Exception:
            pytest.fail('Workflow pause was swallowed')


def test_cli_pauses_then_resumes_without_api_or_claiming_a_finding(tmp_path):
    import subprocess
    import sys
    from analysis.models import ACDG, RouteNode
    ACDG(routes=[RouteNode('/fixture', '', 'handler', 'hub')], firmware_name='smoke').save_json(tmp_path / 'smoke_acdg.json')
    snapshot = tmp_path / 'snapshot.json'
    snapshot.write_text(json.dumps({'schema_version': 1, 'queries': [
        {'command': 'get_status', 'params': {}, 'result': {'status': 'ok', 'data': {'binary_name': 'fixture'}}},
        {'command': 'decompile', 'params': {'address': 'handler'}, 'result': {'status': 'ok', 'data': {'code': 'int handler() { return 0; }'}}},
        {'command': 'get_callees', 'params': {'address': 'handler'}, 'result': {'status': 'ok', 'data': []}},
    ]}))
    directory = tmp_path / 'mailbox'
    command = [sys.executable, 'PANGU.py', '-f', 'smoke', '-p', '3', '-o', str(tmp_path),
               '--ida-snapshot', str(snapshot), '--review-mailbox', str(directory), '--max-routes', '1']
    paused = subprocess.run(command, capture_output=True, timeout=15)
    assert paused.returncode == 2, paused.stderr
    request_path = next(directory.glob('*.request.json'))
    request = json.loads(request_path.read_text(encoding='utf-8'))
    response_path = request_path.with_name(request_path.name.replace('.request.json', '.response.json'))
    response_path.write_text(json.dumps({'request_id': request['request_id'], 'response': {
        'status': 'INSUFFICIENT_EVIDENCE', 'reasoning': 'CLI smoke test; no semantic assessment performed'}}))
    completed = subprocess.run(command, capture_output=True, timeout=15)
    assert completed.returncode == 0, completed.stderr
    report = json.loads((tmp_path / 'smoke_detection_report.json').read_text(encoding='utf-8'))
    assert report['findings'] == []
    assert report['coverage']['investigation_outcomes'][0]['status'] == 'INSUFFICIENT_EVIDENCE'
