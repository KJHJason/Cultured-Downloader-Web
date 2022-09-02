# import third-party libraries
from fastapi.responses import JSONResponse

# import Python's standard libraries
import json
from typing import Any

class PrettyJSONResponse(JSONResponse):
    """Returns the JSON response with proper indentations"""
    def render(self, content: Any) -> bytes:
        return json.dumps(
            obj=content,
            ensure_ascii=False,
            allow_nan=False,
            indent=4,
            separators=(", ", ": "),
        ).encode("utf-8")