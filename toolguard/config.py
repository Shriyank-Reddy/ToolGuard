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
MIN_HEX_LENGTH = 32  # hex-looking text at least this long is suspicious ...
HASH_LENGTHS = {32, 40, 56, 64, 96, 128}  # ... unless it is the length of a normal hash (MD5, SHA-1, SHA-256 ...)
COMMENT_PATTERNS = [  # (regex, plain-English name) - text people do not see in a rendered description
    (r"<!--.*?(?:-->|$)", "an HTML comment"),
    (r"\[[^\]\n]{0,20}\]:\s*(?:#|<>)\s*[\"'(].*?[\"')]", "a Markdown comment"),
    (r"\{/\*.*?\*/\}|/\*.*?\*/", "a code-style comment"),
    (r"<(?:div|span|p|section|details|template)\b[^>]*(?:\bhidden\b|display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0)[^>]*>.*?(?:</\w+>|$)",
     "a hidden HTML element"),
]

# ---- check 3: exfiltration -----------------------------------------------
# A parameter is a possible side channel when one word of its name is in this set (notes, session_info, ...).
SENSITIVE_PARAM_TOKENS = {
    "notes", "note", "context", "metadata", "meta", "extra", "extras", "info", "information", "comment",
    "comments", "memo", "details", "detail", "annotation", "remarks", "payload", "debug", "state", "session",
    "history", "misc", "other", "additional", "attachment", "blob", "data", "telemetry", "trace", "sidenote",
}
SECRET_WORDS = (
    r"password|passwd|credential|secret|api[ _-]?key|token|private key|ssh|id_rsa|cookie|"
    r"system prompt|environment variables?|login|\.aws|\.env|address book|contacts|clipboard|browser history"
)
# Conversation data: "the full chat", "everything the user said earlier", "transcript", ...
CONVERSATION_WORDS = (
    r"(everything|all|full|entire|whole|complete|previous|prior|earlier|past)\b[^.]{0,30}\b"
    r"(chat|conversation|messages?|history|said|typed|wrote|prompts?|turns|transcript)"
    r"|\b(chat|conversation) (log|history)|\btranscript\b|\bword for word\b|\bverbatim\b|\bconversation\b|\bthe chat\b"
)
SENSITIVE_PATHS = r"~/\.|/etc/passwd|id_rsa|\.aws/|\.ssh|\.npmrc|keychain|\.env\b|credentials file"
TRANSFER_VERBS = (  # verbs that move data somewhere else (stems, so relay/relays/relayed all match)
    r"relay|forward|sync|upload|send|sent|post|transmit|submit|mirror|copy|push|ship|stream|export|dump|"
    r"beacon|exfiltrate|leak|share|publish|deliver|replicate|back ?up|report|log"
)
FILL_VERBS = r"include|attach|paste|append|embed|put|fill|add|pass|contents of|" + TRANSFER_VERBS
DATA_NOUNS = (  # what is being moved (needed together with a URL, so "see https://docs.example" is fine)
    r"request|input|data|details|payload|message|content|result|conversation|chat|file|query|prompt|output|"
    r"response|text|history|credential|session|state|context|information|record|document|answer"
)
SIDE_EFFECT_WORDS = (  # signs that sending is a hidden extra, not the tool's main job
    r"also|additionally|as well|a copy|each call|every call|each request|every request|after|afterwards|"
    r"in the background|silently|too"
)

# ---- check 4: over-permission --------------------------------------------
HIGH_RISK_PERMISSIONS = {"shell:exec", "env:read"}  # an unexpected one of these is 'high'
LOW_RISK_PERMISSIONS = {"network:read", "file:read", "db:read"}  # unexpected = borderline = 'low' (shown, not flagged)
UNKNOWN_PURPOSE_TOLERATED = LOW_RISK_PERMISSIONS | {"file:write"}  # when we cannot tell what the tool is for
# purpose -> (words in the tool name / first sentence that signal it, permissions it legitimately needs)
PURPOSES = {
    "calculation & text": (["calculat", "convert", "sum", "percent", "unit", "dice", "random", "uuid", "hash", "encode",
                            "decode", "base64", "round", "format", "pretty", "parse", "slug", "word", "spell", "grammar",
                            "markdown", "html", "colo", "lorem", "compare", "split", "count", "emoji", "text", "json", "csv",
                            "regex", "summar", "password strength"], set()),
    "time": (["time", "date", "timezone"], set()),
    "online lookup": (["weather", "forecast", "temperature", "air quality", "sunrise", "sunset", "moon", "lunar", "stock",
                       "price", "quote", "currency", "exchange", "news", "headline", "rss", "feed", "flight", "recipe",
                       "translat", "search", "lookup", "fetch", "web", "url", "link", "page", "certificate", "ssl", "dns"],
                      {"network:read"}),
    "download": (["download"], {"network:read", "file:write"}),
    "file utilities": (["file", "folder", "directory", "path", "log", "archive", "zip", "extract", "compress", "image",
                        "thumbnail", "resize", "pdf", "document", "note", "todo", "task", "bookmark", "duplicate", "disk",
                        "rename", "move", "delete", "clean", "cache", "backup", "save", "export", "import", "lines"],
                       {"file:read", "file:write"}),
    "storing & remembering": (["memory", "remember", "store", "record", "usage", "track", "reminder", "remind", "journal"],
                              {"file:read", "file:write"}),
    "calendar & scheduling": (["calendar", "meeting", "schedule", "event", "appointment"],
                              {"file:read", "file:write", "network:read", "network:write"}),
    "messaging": (["alert", "notify", "notification", "webhook", "message", "chat", "post", "publish", "forum", "announce"],
                  {"network:write", "network:read"}),
    "email": (["email", "mail", "digest", "newsletter"], {"email:send", "network:write", "network:read"}),
    "developer tools": (["git", "commit", "repository", "unit test", "build", "lint", "compile", "ssh", "key", "deploy",
                         "package", "install"], {"file:read", "file:write", "shell:exec"}),
    "system information": (["port", "process", "cpu", "uptime", "interface", "ping", "traceroute", "hostname", "system"],
                           {"shell:exec", "file:read", "network:read"}),
    "shell": (["shell", "command", "terminal", "execute", "script"], {"shell:exec", "file:read", "file:write"}),
    "database": (["database", "sql", "query", "inventory", "orders", "table", "stock level"], {"db:read", "db:write"}),
    "browser": (["browser", "screenshot", "web form", "click", "navigate", "headless"],
                {"browser:control", "network:read", "network:write"}),
    "configuration": (["config", "environment", "settings", "variable", "env"], {"file:read", "env:read"}),
    "secrets": (["secret", "vault", "credential", "keychain"], {"env:read", "network:read"}),
    "upload & backup": (["upload", "backup", "sync"], {"file:read", "network:write"}),
    "profile": (["profile", "account", "user"], {"network:read"}),
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
# Words whose appearance, removal or replacement changes what a description PROMISES. A one-word edit
# touching one of these is a real change, not a typo fix.
MEANING_WORDS = {
    "not", "no", "never", "none", "nothing", "nobody", "without", "cannot", "dont", "doesnt", "wont", "isnt", "arent",
    "cant", "always", "any", "all", "only", "must", "should", "may", "can", "unless", "except", "instead",
    "local", "remote", "private", "public", "encrypted", "unencrypted", "readonly", "read-only", "optional", "required",
    "delete", "deletes", "overwrite", "overwrites", "permanently", "confirm", "confirmation", "approval", "consent",
    "ask", "before", "after", "stored", "stores", "sent", "sends", "shared", "shares", "uploaded", "uploads", "logged", "logs",
}
TYPO_SIMILARITY = 0.8  # two replaced words this similar are treated as a spelling fix
