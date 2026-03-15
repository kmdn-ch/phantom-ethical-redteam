import glob
import shutil
import os


def run() -> str:
    deleted = []
    errors = []

    # Fixed path
    if os.path.exists("logs/temp"):
        try:
            shutil.rmtree("logs/temp")
            deleted.append("logs/temp")
        except Exception as e:
            errors.append(f"logs/temp: {e}")

    # Glob-expanded paths
    for path in glob.glob("/tmp/phantom_*"):
        try:
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
            deleted.append(path)
        except Exception as e:
            errors.append(f"{path}: {e}")

    if errors:
        return f"⚠️ Cleanup partial — deleted: {deleted}, errors: {errors}"
    if deleted:
        return f"✅ Temporary files deleted: {deleted}"
    return "✅ Nothing to clean"


TOOL_SPEC = {
    "name": "cleanup_temp",
    "description": "Secure cleanup of the temp files (ghost mode)",
    "input_schema": {"type": "object", "properties": {}},
}
