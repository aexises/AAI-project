import json

import pytest
from pydantic import ValidationError

from traceguard.agent import validate_task_agent_response_json


def test_task_agent_response_rejects_gateway_schema_extra_key():
    payload = {
        "kind": "tool_call",
        "tool_name": "calculator",
        "arguments": {"expression": "12 * 7"},
        "consumed_observation_ids": [],
        "requested_resources": [],
        "answer": None,
        "additionalProperties": False,
    }

    with pytest.raises(ValidationError):
        validate_task_agent_response_json(json.dumps(payload))
