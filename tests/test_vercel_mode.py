"""Vercel mode: shared Upstash store, run_session lifecycle, and the app.py
entrypoint. Upstash is faked at the HTTP layer so the real REST client runs."""
# This is the testing file.
import json
import os

import httpx
import pytest

os.environ['LITELLM_LOCAL_MODEL_COST_MAP'] = 'True'
import jaclang  # noqa: F401  (registers the Jac importer)
from fastapi.testclient import TestClient

from services import attacklab, findings, ratelimit, research, store, web
from fake_upstash import FakeUpstash

RESULTS = [{'title': 'Pricing', 'url': 'https://example.com/pricing', 'snippet': 'Project pricing is $12 per month.'}]


@pytest.fixture(autouse=True)
def offline(monkeypatch, tmp_path):
    for key in ('OPENAI_API_KEY', 'GEMINI_API_KEY', 'GOOGLE_API_KEY', 'GUARD_URL', 'VERCEL', 'TRUSTED_PROXY_CIDRS',
                'REDIS_URL', 'KV_REST_API_URL', 'KV_REST_API_TOKEN', 'UPSTASH_REDIS_REST_URL', 'UPSTASH_REDIS_REST_TOKEN'):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv('LATCH_DATA_DIR', str(tmp_path))
    monkeypatch.setattr(research, 'raw_search', lambda q: [web.RawResult(**RESULTS[0])])
    monkeypatch.setattr(research, 'raw_fetch', lambda url: '<p>Project pricing is $12 per month.</p>')
    ratelimit.reset_rate_limits()
    monkeypatch.setattr(ratelimit, '_shared_salt', '')


@pytest.fixture(params=['rest', 'redis'])
def upstash(monkeypatch, request):
    if request.param == 'redis':
        import fakeredis
        client = fakeredis.FakeRedis(decode_responses=True)
        calls = []
        execute = client.execute_command

        def command(*args, **kwargs):
            calls.append(list(args))
            return execute(*args, **kwargs)

        monkeypatch.setenv('REDIS_URL', 'redis://redis.example:6379/0')
        monkeypatch.setattr(client, 'execute_command', command)
        monkeypatch.setattr(store, '_redis_client', lambda url: client)
        client.calls = calls
        return client
    fake = FakeUpstash()
    calls = []

    def post(url, json=None, headers=None, timeout=None):
        assert url == 'https://kv.example' and headers['Authorization'] == 'Bearer tok'
        calls.append(json)
        try:
            return httpx.Response(200, json={'result': fake.run(json)}, request=httpx.Request('POST', url))
        except ValueError as exc:
            return httpx.Response(400, json={'error': str(exc)}, request=httpx.Request('POST', url))

    monkeypatch.setenv('KV_REST_API_URL', 'https://kv.example/')
    monkeypatch.setenv('KV_REST_API_TOKEN', 'tok')
    monkeypatch.setattr(store.httpx, 'post', post)
    fake.calls = calls
    return fake


def test_run_session_runs_once_and_rejects_unknown_sessions():
    sid = research.start_research('Compare project pricing').session_id
    assert research.run_session(sid).ok
    again = research.run_session(sid)
    assert not again.ok and 'already' in again.error
    assert not research.run_session('ses_missing').ok
    assert research.get_session('ses_missing') is None


def test_stalled_run_is_reported_failed(monkeypatch):
    sid = research.start_research('Compare project pricing').session_id
    raw = json.loads(store.kv_get('latch:session:' + sid))
    raw['updated'] -= research.STALE_AFTER + 1
    store.kv_put('latch:session:' + sid, json.dumps(raw), 60)
    view = research.get_session(sid)
    assert view.status == 'FAILED' and 'stopped' in view.error


def test_shared_store_serves_sessions_findings_and_limits(upstash, monkeypatch):
    assert store.shared_store()
    sid = research.start_research('Compare project pricing').session_id
    assert research.run_session(sid).ok
    # Another instance has no working memory: the view must come from the store.
    assert sid not in research._sessions
    view = research.get_session(sid)
    assert view.status == 'COMPLETE' and view.validation.passed
    assert any(c[0] == 'SET' and c[1] == 'latch:session:' + sid for c in upstash.calls)

    attacklab.run_attack_fixture('instruction_override')
    items = findings.list_findings()
    assert items and items[0].seq == 101
    assert findings.flag_finding(items[0].finding_id).review_status == 'HUMAN_FLAGGED'
    assert findings.list_findings()[0].review_status == 'HUMAN_FLAGGED'
    assert not os.listdir(os.environ['LATCH_DATA_DIR'])  # nothing written to disk

    monkeypatch.setenv('RATE_LIMIT_REQUESTS', '2')
    assert ratelimit.check_rate_limit('9.9.9.9')[0]
    # A second instance (own process salt, empty cache) must share the count.
    monkeypatch.setattr(ratelimit, '_salt', 'other-instance')
    monkeypatch.setattr(ratelimit, '_shared_salt', '')
    assert ratelimit.check_rate_limit('9.9.9.9')[0]
    allowed, retry = ratelimit.check_rate_limit('9.9.9.9')
    assert not allowed and 0 < retry <= 3600


def test_vercel_client_ip_header_is_used_only_on_vercel(monkeypatch):
    headers = {'x-vercel-forwarded-for': '5.6.7.8', 'x-forwarded-for': 'spoof'}
    assert ratelimit.resolve_client_ip(headers, '10.0.0.1') == '10.0.0.1'
    monkeypatch.setenv('VERCEL', '1')
    assert ratelimit.resolve_client_ip(headers, '10.0.0.1') == '5.6.7.8'


def test_app_entrypoint_envelope_gate_and_allowlist(monkeypatch):
    import app as vercel_app
    monkeypatch.setenv('RATE_LIMIT_REQUESTS', '1')
    client = TestClient(vercel_app.app)
    first = client.post('/function/start_research', json={'task': 'Compare project pricing'})
    body = first.json()
    assert first.status_code == 200 and body['ok'] and body['data']['result']['_jac_type'] == 'StartResult'
    sid = body['data']['result']['session_id']
    assert client.post('/function/run_session', json={'session_id': sid}).json()['data']['result']['ok']
    view = client.post('/function/get_session', json={'session_id': sid, 'refresh_token': 1}).json()['data']['result']
    assert view['status'] == 'COMPLETE' and view['events'][0]['label'] == 'TASK RECEIVED'
    assert client.post('/function/start_research', json={'task': 'Compare project pricing'}).status_code == 429
    assert client.post('/function/record_finding', json={}).status_code == 404
    assert client.post('/function/_run_session', json={'sid': sid}).status_code == 404


def test_vercel_without_shared_store_fails_clearly(monkeypatch):
    import app as vercel_app
    monkeypatch.setenv('VERCEL', '1')
    res = TestClient(vercel_app.app).post('/function/guard_status', json={})
    assert res.status_code == 503 and 'Upstash' in res.json()['error']['message']


def test_vercel_shared_store_research_lifecycle(upstash, monkeypatch):
    import app as vercel_app
    monkeypatch.setenv('VERCEL', '1')
    client = TestClient(vercel_app.app)
    started = client.post('/function/start_research', json={'task': 'Compare project pricing'})
    assert started.status_code == 200
    sid = started.json()['data']['result']['session_id']
    assert client.post('/function/run_session', json={'session_id': sid}).json()['data']['result']['ok']
    assert not client.post('/function/run_session', json={'session_id': sid}).json()['data']['result']['ok']
    view = client.post('/function/get_session', json={'session_id': sid}).json()['data']['result']
    assert view['status'] == 'COMPLETE'


def test_native_client_pool_and_timeouts():
    client = store._redis_client('rediss://localhost:6379/0')
    assert store._redis_client('rediss://localhost:6379/0') is client
    options = client.connection_pool.connection_kwargs
    assert options['decode_responses'] is True
    assert options['socket_timeout'] == options['socket_connect_timeout'] == 8.0
    assert options['retry']._retries == 0


def test_redis_failure_does_not_fall_back_to_memory(monkeypatch):
    import redis
    monkeypatch.setenv('REDIS_URL', 'redis://redis.example:6379')

    class BrokenRedis:
        def execute_command(self, *args):
            raise redis.ConnectionError('unavailable')

    monkeypatch.setattr(store, '_redis_client', lambda url: BrokenRedis())
    with pytest.raises(redis.ConnectionError):
        store.kv_put('failure-test', 'value', 60)
    assert 'failure-test' not in store._mem
