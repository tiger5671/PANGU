"""Strict offline replay: unrecorded queries return errors, never invented data."""
import json
from core.bridge.ida_client import IDAProClient


class SnapshotIDAClient(IDAProClient):
    def __init__(self, path):
        super().__init__()
        with open(path, encoding="utf-8") as stream:
            snapshot = json.load(stream)
        if snapshot.get("schema_version") != 1 or not isinstance(snapshot.get("queries"), list):
            raise ValueError("Unsupported IDA snapshot")
        self.responses = {self._key(q["command"], q.get("params", {})): q["result"]
                          for q in snapshot["queries"]}

    @staticmethod
    def _key(command, params):
        return json.dumps([command, params or {}], sort_keys=True)

    def connect(self):
        return True

    def close(self):
        pass

    def _send(self, cmd, params=None):
        if cmd == "batch":
            return {"status": "ok", "data": [self._send(q["command"], q.get("params"))
                                               for q in (params or {}).get("requests", [])]}
        result = self.responses.get(self._key(cmd, params))
        return json.loads(json.dumps(result)) if result is not None else {
            "status": "error", "error": f"Query not recorded in snapshot: {cmd}"}
