"""File-based human/agent review transport requiring no model API.

Each missing response pauses execution with a durable request. Rerunning the
same analysis replays only responses whose complete prompt hash still matches.
This is an explicit review workflow, not access to an internal model endpoint.
"""
import hashlib
import json
from pathlib import Path
import tempfile
from core.llm import token_stats


class ReviewPending(BaseException):
    # A deliberate workflow pause must pass through legacy "except Exception"
    # handlers that otherwise turn unavailable model evidence into partial data.
    def __init__(self, request_path, response_path):
        self.request_path, self.response_path = Path(request_path), Path(response_path)
        super().__init__(f"Review response required for {self.request_path}")


class ReviewMailboxProvider:
    model_name = "review-mailbox"
    max_attempts = 1

    def __init__(self, directory):
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.stats = token_stats
        self.last_error = None

    def validate_configuration(self):
        return None

    @staticmethod
    def _write_atomic(path, value):
        with tempfile.NamedTemporaryFile(dir=path.parent, suffix=".json", mode="w", encoding="utf-8", delete=False) as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            temporary = Path(stream.name)
        try:
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)

    def chat(self, messages, json_mode=True, caller="unknown"):
        payload = {"messages": messages, "json_mode": json_mode, "caller": caller}
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
        request_path = self.directory / (digest + ".request.json")
        response_path = self.directory / (digest + ".response.json")
        if not request_path.exists():
            self._write_atomic(request_path, dict(payload, request_id=digest,
                                                  response_file=str(response_path)))
        if not response_path.exists():
            raise ReviewPending(request_path, response_path)
        record = json.loads(response_path.read_text(encoding="utf-8"))
        if not isinstance(record, dict) or record.get("request_id") != digest or "response" not in record:
            raise ValueError("Review response identity/schema mismatch")
        response = record["response"]
        if json_mode and not isinstance(response, (dict, list)):
            raise ValueError("Expected a structured JSON review response")
        if not json_mode and not isinstance(response, str):
            raise ValueError("Expected a text review response")
        self.stats.record_call(self.stats.count_messages_tokens(messages), self.stats.count_tokens(response), caller)
        return response
