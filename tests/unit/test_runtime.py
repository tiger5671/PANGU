import json
from pathlib import Path
from types import SimpleNamespace
import pytest
from core.llm import LLMProvider
from core.bridge.snapshot_client import SnapshotIDAClient
from analysis.firmware_analyzer import FirmwareAnalyzer
from analysis.storage_graph import StorageGraph
from analysis.evidence import EvidenceCollector
from scripts.ida_snapshot import export_snapshot


def test_provider_uses_runtime_model_and_api_usage(monkeypatch):
    requests = []
    def create(**kwargs):
        requests.append(kwargs)
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content='{"ok": true}'))],
                               usage=SimpleNamespace(prompt_tokens=12, completion_tokens=4))
    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    monkeypatch.setenv("OPENAI_MODEL", "configured-model")
    provider = LLMProvider(client=client)
    assert provider.chat([{"role": "user", "content": "Return JSON"}]) == {"ok": True}
    assert requests[0]["model"] == "configured-model" and provider.last_usage == (12, 4)


def test_provider_failures_have_three_total_attempts(monkeypatch):
    attempts = []
    def create(**kwargs):
        attempts.append(1)
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content='invalid'))], usage=None)
    monkeypatch.setattr("core.llm.time.sleep", lambda _: None)
    provider = LLMProvider(client=SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create))))
    assert provider.chat([]) is None and len(attempts) == 3


def test_optional_dependencies_not_imported_on_openai_path():
    import subprocess
    import sys
    completed = subprocess.run([sys.executable, "-c", "import sys; import core.llm; assert 'tiktoken' not in sys.modules; assert 'google.generativeai' not in sys.modules"], capture_output=True)
    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize("bits,endian,machine,expected", [(1, 1, 40, "ARM 32-bit LE"), (2, 2, 8, "MIPS 64-bit BE"), (2, 1, 183, "AArch64 64-bit LE")])
def test_elf_machine_respects_endianness(tmp_path, bits, endian, machine, expected):
    header = bytearray(20)
    header[:6] = b'\x7fELF' + bytes([bits, endian])
    header[18:20] = machine.to_bytes(2, 'little' if endian == 1 else 'big')
    path = tmp_path / 'binary'
    path.write_bytes(header)
    assert FirmwareAnalyzer(str(tmp_path), False)._get_elf_architecture(path) == expected


def test_truncated_elf_is_unresolved(tmp_path):
    path = tmp_path / 'binary'
    path.write_bytes(b'\x7fELF')
    assert FirmwareAnalyzer(str(tmp_path), False)._get_elf_architecture(path) == "unknown"


def test_snapshot_replay_never_invents_queries(tmp_path):
    path = tmp_path / 'snapshot.json'
    path.write_text(json.dumps({"schema_version": 1, "queries": [{"command": "get_status", "params": {}, "result": {"status": "ok", "data": {"binary_id": "id"}}}]}))
    client = SnapshotIDAClient(path)
    assert client.connect() and client.get_status()["data"]["binary_id"] == "id"
    assert client.decompile("unknown")["status"] == "error"
    returned = client.get_status()
    returned['data']['binary_id'] = 'changed'
    assert client.get_status()['data']['binary_id'] == 'id'


def test_headless_runner_copies_input_uses_argv_and_publishes_only_complete_json(tmp_path, monkeypatch):
    ida = tmp_path / 'IDA with spaces.exe'
    target = tmp_path / 'firmware & sample.i64'
    output = tmp_path / 'output.json'
    ida.write_bytes(b'fixture')
    target.write_bytes(b'original')
    def run(command, **kwargs):
        assert isinstance(command, list) and kwargs['shell'] is False
        copy = Path(command[-1])
        assert copy != target and copy.read_bytes() == b'original'
        copy.write_bytes(b'changed copy')
        snapshot = copy.parent / 'snapshot.json'
        snapshot.write_text(json.dumps({'schema_version': 1, 'queries': [{'command':'get_status','params':{},'result':{'status':'ok'}}]}))
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr('scripts.ida_snapshot.subprocess.run', run)
    assert export_snapshot(ida, target, output, functions=[]) == 0
    assert target.read_bytes() == b'original' and json.loads(output.read_text())['schema_version'] == 1
    def failed(*args, **kwargs): return SimpleNamespace(returncode=1)
    monkeypatch.setattr('scripts.ida_snapshot.subprocess.run', failed)
    with pytest.raises(RuntimeError): export_snapshot(ida, target, output, functions=[])
    assert json.loads(output.read_text())['schema_version'] == 1


def storage_snapshot(tmp_path, filename, accesses):
    path = tmp_path / filename
    path.write_text(json.dumps({'schema_version': 1, 'queries': [{'command': 'get_storage_accesses', 'result': {'status': 'ok', 'data': {'accesses': accesses, 'gaps': []}}}]}))
    return path


def access(binary, mode, key='config_key', namespace='nvram'):
    return {'binary_id': binary, 'mode': mode, 'namespace': namespace, 'key': key,
            'function': 'handler', 'function_address': '0x1000', 'callsite': '0x1010'}


def test_storage_join_requires_distinct_binaries_same_key_namespace_and_write_read(tmp_path):
    writer = storage_snapshot(tmp_path, 'writer.json', [access('web', 'write'), access('web', 'read')])
    reader = storage_snapshot(tmp_path, 'reader.json', [access('daemon', 'read'), access('daemon', 'read', namespace='other'), access('daemon', 'read', key='different')])
    graph = StorageGraph.from_snapshots([writer, reader], 'firmware')
    assert len(graph.edges) == 1
    assert graph.edges[0]['status'] == 'CANDIDATE_CHANNEL' and not graph.edges[0]['taint_verified']
    evidence = EvidenceCollector(None, storage_graph=graph, binary_id='web')
    assert len(evidence.query('get_storage_links', address='handler')['data']['links']) == 1
    assert not graph.query('other_binary', 'handler')['data']['links']
    assert not graph.query('web', 'unrelated_function')['data']['links']


def test_storage_missing_evidence_and_budget_are_explicit(tmp_path):
    a = storage_snapshot(tmp_path, 'writer.json', [access('web', 'write')])
    b = storage_snapshot(tmp_path, 'reader.json', [access('d1', 'read'), access('d2', 'read')])
    graph = StorageGraph.from_snapshots([a, b], 'firmware', max_edges=1)
    assert len(graph.edges) == 1 and 'Storage edge budget exhausted' in graph.gaps
    assert EvidenceCollector(None).query('get_storage_links', address='handler')['status'] == 'error'
