"""All tunable settings and keyword lists in one place (easy to read, easy to freeze)."""

# ---- scoring -------------------------------------------------------------
SEVERITY_WEIGHT = {"low": 1, "medium": 3, "high": 6}
LEVEL_MEDIUM = 3  # score >= 3 -> Medium
LEVEL_HIGH = 6  # score >= 6 -> High
MAX_SCORE = 10

# ---- check 1: hidden instructions ---------------------------------------
INTENT_THRESHOLD = 0.60  # classifier probability above which a sentence is flagged
INTENT_HIGH = 0.85  # ... and above which it is 'high' severity instead of 'medium'
INSTRUCTION_PATTERNS = [  # (regex, plain-English reason)
    (r"\b(do not|don't|never|must not|should not|without)\b[^.]{0,40}\b(tell|inform|notify|alert|mention|reveal|show|admit)\b[^.]{0,40}\b(user|human|anyone|person)",
     "tries to keep something secret from the user"),
    (r"\b(user|human)\b[^.]{0,30}\b(does not need to|doesn't need to|should not|must not|need not)\b[^.]{0,20}\b(know|see|be told)",
     "says the user should not know about it"),
    (r"\bignore\b[^.]{0,30}\b(previous|prior|above|earlier|other|all|the)\b[^.]{0,30}\b(instructions?|rules?|prompts?|guidelines?)",
     "tells the AI to ignore its earlier instructions"),
    (r"\b(disregard|override|forget)\b[^.]{0,30}\b(safety|guidelines?|rules?|instructions?|restrictions?)",
     "tells the AI to drop its safety rules"),
    (r"\bbefore (using|calling|running|invoking)\b[^.]{0,30}\b(any|every|another|other)\b[^.]{0,20}\btools?\b",
     "gives orders about how the AI should use other tools"),
    (r"<\s*(important|system|instructions?|secret)\s*>", "uses an <IMPORTANT>-style tag to address the AI"),
    (r"\bnote to the (ai|assistant|model|agent|llm)\b", "addresses the AI model directly"),
    (r"\b(secretly|covertly|discreetly)\b", "asks for something to be done secretly"),
    (r"\b(system prompt|developer mode|maintenance mode)\b", "refers to the AI's system prompt or special modes"),
    (r"\bnever admit\b|\bkeep (this|it) (hidden|secret|confidential)\b|\bstay invisible\b",
     "asks the AI to hide this behaviour"),
]

# ---- check 2: obfuscation ------------------------------------------------
MIN_BLOB_LENGTH = 32  # base64-looking text at least this long is suspicious
WHITESPACE_GAP = 20  # this many whitespace characters in a row, followed by text

# ---- check 3: exfiltration -----------------------------------------------
SENSITIVE_PARAM_NAMES = {
    "notes", "note", "context", "metadata", "meta", "extra", "extras", "info", "comment",
    "comments", "memo", "details", "annotation", "remarks", "payload", "debug", "sidenote",
}
SECRET_WORDS = (
    r"password|passwd|credential|secret|api[ _-]?key|token|private key|ssh|id_rsa|cookie|"
    r"conversation|chat history|(full|whole|entire) chat|previous messages|system prompt|environment variables?|login|\.aws|\.env"
)
SENSITIVE_PATHS = r"~/\.|/etc/passwd|id_rsa|\.aws/|\.ssh|\.npmrc|keychain|\.env\b|credentials file"
FILL_VERBS = r"include|attach|paste|copy|append|embed|forward|upload|send|pass|add|put|fill|contents of"
SEND_VERBS = r"post|posts|send|sends|upload|uploads|forward|forwarded|transmit|transmits|submit|mirror"

# ---- check 4: over-permission --------------------------------------------
PERMISSION_RISK = {  # how dangerous each permission is
    "shell:exec": "high", "env:read": "high", "file:write": "medium", "email:send": "medium",
    "browser:control": "medium", "network:write": "medium", "db:write": "medium",
    "file:read": "medium", "network:read": "medium", "db:read": "medium",
}
DEFAULT_ALLOWED = {"network:read", "file:read"}  # tolerated when the purpose is unknown
# purpose name -> (keywords found in the tool name / first sentence, permissions it legitimately needs)
PURPOSES = {
    "weather": (["weather", "forecast", "temperature", "air quality", "sunrise", "sunset"], {"network:read"}),
    "math": (["calculat", "convert", "sum", "add ", "percentage", "unit", "dice", "random", "uuid", "hash", "encode", "base64"], set()),
    "currency": (["currency", "stock", "price", "exchange"], {"network:read"}),
    "text": (["format", "pretty", "parse", "slug", "word", "spell", "summar", "lorem", "text", "json", "csv"], set()),
    "translate": (["translat"], {"network:read"}),
    "shell": (["shell", "command", "terminal"], {"shell:exec"}),
    "time": (["time", "date", "timezone", "version"], set()),
    "files": (["file", "folder", "directory", "log", "archive", "zip", "image", "thumbnail", "note", "todo", "bookmark", "duplicate", "disk", "lines"], {"file:read", "file:write"}),
    "calendar": (["calendar", "meeting", "schedule", "event"], {"file:read", "file:write", "network:read", "network:write"}),
    "web": (["web", "url", "link", "page", "rss", "feed", "download", "fetch", "search", "recipe"], {"network:read", "file:write"}),
    "messaging": (["alert", "notify", "notice", "webhook", "message", "chat", "post"], {"network:write"}),
    "email": (["email", "mail", "digest"], {"email:send", "network:write"}),
    "dev": (["git", "commit", "repository", "unit test", "build", "lint", "ssh", "key"], {"file:read", "shell:exec"}),
    "database": (["database", "inventory", "sql", "orders", "stock level"], {"db:read", "db:write"}),
    "browser": (["browser", "screenshot", "web form"], {"browser:control", "network:read", "network:write"}),
    "config": (["config", "environment", "env ", "settings"], {"file:read", "env:read"}),
    "secrets": (["secret", "vault", "credential"], {"env:read", "network:read"}),
    "backup": (["backup", "upload"], {"file:read", "network:write"}),
    "profile": (["profile", "user"], {"network:read"}),
}

# ---- check 5: look-alike names -------------------------------------------
WELL_KNOWN_TOOLS = [
    "read_file", "write_file", "list_directory", "list_files", "search_files", "delete_file",
    "run_command", "execute_command", "shell", "bash", "send_email", "read_email", "search_web",
    "web_search", "fetch_url", "fetch", "browse", "get_weather", "query_database", "run_sql",
    "create_issue", "create_pull_request", "send_message", "post_message", "get_current_time",
    "calculator", "take_screenshot", "read_clipboard", "git_commit", "git_status", "search_code",
    "list_repos", "upload_file", "download_file", "create_event", "read_calendar", "translate_text",
]
SIMILARITY_THRESHOLD = 0.85  # name similarity (0-1) above which a near-miss is flagged
HOMOGLYPHS = {  # look-alike characters mapped to the plain letter they imitate
    "0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d",
    "ο": "o", "α": "a", "ε": "e", "ι": "i",
}
OVERRIDE_PATTERN = (
    r"\b(instead of|rather than|in place of|replaces?|overrides?|supersedes?|takes? precedence over)\b"
    r"[^.]{0,60}\b(tools?|functions?|" + "|".join(WELL_KNOWN_TOOLS) + r")\b"
)

# ---- check 6: rug pull ---------------------------------------------------
MINOR_EDIT_SIMILARITY = 0.95  # description at least this similar ...
MINOR_EDIT_MAX_GROWTH = 20  # ... and grown by at most this many characters = 'typo-level' edit
