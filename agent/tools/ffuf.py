import subprocess


def run(url: str, wordlist: str = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt") -> str:
    cmd = [
        "ffuf", "-u", url, "-w", wordlist,
        "-mc", "200,204,301,302,307,403",
        "-o", "logs/ffuf.json", "-of", "json",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        if result.returncode != 0:
            return f"⚠️ ffuf exited with code {result.returncode}\n{result.stderr[-300:]}"
        return "✅ ffuf terminé – résultats dans logs/ffuf.json"
    except Exception as e:
        return f"❌ Erreur ffuf : {str(e)}"


TOOL_SPEC = {
    "name": "run_ffuf",
    "description": "Fuzzing directories/files ultra-rapide",
    "input_schema": {
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "wordlist": {"type": "string"},
        },
        "required": ["url"],
    },
}
