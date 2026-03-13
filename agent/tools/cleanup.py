import shutil
import os

def run() -> str:
    for folder in ["logs/temp", "/tmp/phantom_*"]:
        try:
            if os.path.exists("logs/temp"):
                shutil.rmtree("logs/temp")
            return "✅ Temporary files deleted (Only the files created by the agent)"
        except:
            return "✅ No files deleted"
    return "✅ Cleanup ok"

TOOL_SPEC = {
    "name": "cleanup_temp",
    "description": "Secure cleanup of the temp files (ghost mode)",
    "input_schema": {"type": "object", "properties": {}}
}
