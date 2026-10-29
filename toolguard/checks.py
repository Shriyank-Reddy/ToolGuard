"""The five static checks. Each takes a Tool and returns a list of Findings.

(Check 6, rug pull, needs a lockfile and lives in lockfile.py.)
Detectors only look at the tool definition. They never read the labels.
"""
import base64
import re
import unicodedata
from urllib.parse import unquote

from . import config as C
from .intent import instruction_probability, split_sentences
from .models import Finding, Tool

I = re.IGNORECASE


# ---------------------------------------------------------------- helpers
def is_invisible(ch: str) -> bool:
    """Zero-width, bidi-control and other non-printing characters."""
    cat = unicodedata.category(ch)
    return cat == "Cf" or (cat == "Cc" and ch not in "\n\r\t")


def strip_invisible(text: str) -> str:
    return "".join(ch for ch in text if not is_invisible(ch))


def reveal(text: str) -> str:
    """Make invisible characters visible, e.g. '<U+200B>' (for display)."""
    return "".join(f"<U+{ord(ch):04X}>" if is_invisible(ch) else ch for ch in text)


def snippet(text: str, start: int, end: int, pad: int = 30) -> str:
    return text[max(0, start - pad): end + pad].strip()


# ---------------------------------------------------- check 1: instructions
def check_hidden_instructions(tool: Tool) -> list[Finding]:
    """Sentences that give orders to the AI instead of describing the tool."""
    findings = []
    for location, text in tool.texts():
        sentences = split_sentences(strip_invisible(text))
        unmatched = []
        for sentence in sentences:
            for pattern, why in C.INSTRUCTION_PATTERNS:
                if re.search(pattern, sentence, I):
                    findings.append(Finding(
                        "hidden_instructions", "high", tool.name,
                        f"The text {why}. Tool descriptions should say what a tool does, not give orders to the AI.",
                        sentence, location))
                    break
            else:
                # shadowing sentences belong to check 5; very short phrases are not orders
                if not re.search(C.OVERRIDE_PATTERN, sentence, I) and len(sentence.split()) >= 5:
                    unmatched.append(sentence)
        for sentence, prob in zip(unmatched, instruction_probability(unmatched)):
            if prob >= C.INTENT_THRESHOLD:
                findings.append(Finding(
                    "hidden_instructions", "high" if prob >= C.INTENT_HIGH else "medium", tool.name,
                    f"This sentence reads like an order to the AI model rather than a description "
                    f"(classifier confidence {prob:.0%}).", sentence, location))
    return findings


# ----------------------------------------------------- check 2: obfuscation
def _readable(text: str) -> bool:
    """Does decoded text look like human language (not random bytes)?"""
    if not text:
        return False
    printable = sum(ch.isprintable() or ch.isspace() for ch in text)
    wordlike = sum(ch.isalpha() or ch.isspace() for ch in text)
    return printable / len(text) > 0.9 and wordlike / len(text) > 0.6


def _decode_base64(blob: str) -> str | None:
    try:
        text = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True).decode("utf-8")
    except Exception:
        return None
    return text if _readable(text) else None


def _decode_hex(blob: str) -> str | None:
    try:
        text = bytes.fromhex(blob).decode("utf-8")
    except Exception:
        return None
    return text if _readable(text) else None


def _decode_percent(blob: str) -> str | None:
    text = unquote(blob)
    return text if _readable(text) else None


def _decode_escapes(blob: str) -> str | None:
    try:
        text = blob.encode("ascii").decode("unicode_escape")
    except Exception:
        return None
    return text if _readable(text) else None


def encoded_payloads(text: str) -> list[tuple[str, str, str | None]]:
    """Find encoded-looking blobs. Returns (kind, blob, decoded text or None)."""
    found = []
    for m in re.finditer(rf"[A-Za-z0-9+/]{{{C.MIN_BLOB_LENGTH},}}={{0,2}}", text):
        blob = m.group(0)
        if re.fullmatch(r"[0-9a-fA-F]+", blob) or not (re.search(r"[a-z]", blob) and re.search(r"[A-Z]", blob)):
            continue  # hex is handled below; all-lowercase text is just a long word or identifier
        found.append(("base64", blob, _decode_base64(blob)))
    for m in re.finditer(rf"\b(?:[0-9a-fA-F]{{2}}){{{C.MIN_HEX_LENGTH // 2},}}\b", text):
        blob = m.group(0)
        decoded = _decode_hex(blob)
        if decoded is None and (blob.isdigit() or len(blob) in C.HASH_LENGTHS):
            continue  # a long number or an ordinary hash, not a payload
        found.append(("hex", blob, decoded))
    for m in re.finditer(r"(?:%[0-9a-fA-F]{2}){8,}", text):
        found.append(("percent-encoded", m.group(0), _decode_percent(m.group(0))))
    for m in re.finditer(r"(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}){6,}", text):
        found.append(("escape-sequence", m.group(0), _decode_escapes(m.group(0))))
    return found


def _decoded_looks_hostile(decoded: str) -> bool:
    """Run the instruction and exfiltration checks on text that was hidden in an encoded blob."""
    probe = Tool("decoded-payload", decoded)
    return any(f.is_flag for f in check_hidden_instructions(probe) + check_exfiltration(probe))


def _mixed_script_words(text: str) -> list[str]:
    bad = []
    for word in re.findall(r"\w+", text):
        scripts = {unicodedata.name(ch, "?").split()[0] for ch in word if ch.isalpha()}
        if len(scripts & {"LATIN", "CYRILLIC", "GREEK"}) > 1:
            bad.append(word)
    return bad


def check_obfuscation(tool: Tool) -> list[Finding]:
    """Text that is hidden from a human reader but still visible to the model."""
    findings = []
    for location, text in tool.texts():
        def add(sev, why, evidence):
            findings.append(Finding("obfuscation", sev, tool.name, why, evidence, location))

        hidden = [(i, ch) for i, ch in enumerate(text) if is_invisible(ch)]
        if hidden:
            codes = ", ".join(sorted({f"U+{ord(ch):04X}" for _, ch in hidden}))
            add("high", f"Contains {len(hidden)} invisible character(s) ({codes}). Invisible characters can hide "
                        f"text from people while the model still reads it.", snippet(text, hidden[0][0], hidden[-1][0] + 1))
        for pattern, name in C.COMMENT_PATTERNS:
            for m in re.finditer(pattern, text, re.S | re.I):
                add("high", f"Contains {name}. People reading a rendered description never see it, but the model does.",
                    m.group(0))
        for kind, blob, decoded in encoded_payloads(text):
            if decoded is None:
                add("medium", f"Contains a long {kind} blob that has no place in a description.", blob)
            elif _decoded_looks_hostile(decoded):
                add("high", f"Contains a {kind} blob that decodes to a hidden instruction: \"{decoded[:80]}\".", blob)
            else:
                add("medium", f"Contains a {kind} blob that decodes to hidden text: \"{decoded[:80]}\".", blob)
        gaps = list(re.finditer(rf"\s{{{C.WHITESPACE_GAP},}}(?=\S)", text)) + list(re.finditer(r"(?:\r?\n[ \t]*){5,}(?=\S)", text))
        for m in gaps:
            add("high", "A large run of blank space is followed by more text; this pushes text out of sight "
                        "in most viewers.", text[m.end(): m.end() + 70])
        for word in _mixed_script_words(text):
            add("medium", f"The word '{word}' mixes letters from different alphabets (a look-alike trick).", word)
    return findings


# ----------------------------------------------------- check 3: exfiltration
def name_tokens(name: str) -> set[str]:
    """'sessionInfo' / 'session_info' -> {'session', 'info'}"""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return set(re.split(r"[^a-zA-Z0-9]+", spaced.lower())) - {""}


def check_exfiltration(tool: Tool) -> list[Finding]:
    """Parameters or sentences that move secrets, files or chat history to someone else."""
    secret = re.compile(C.SECRET_WORDS, I)
    convo = re.compile(C.CONVERSATION_WORDS, I)
    paths = re.compile(C.SENSITIVE_PATHS, I)
    fill = re.compile(rf"\b({C.FILL_VERBS})(?:s|es|ed|d|ing)?\b", I)
    transfer = re.compile(rf"\b({C.TRANSFER_VERBS})(?:s|es|ed|d|ing)?\b", I)
    data_noun = re.compile(rf"\b({C.DATA_NOUNS})", I)
    side_effect = re.compile(rf"\b({C.SIDE_EFFECT_WORDS})\b", I)
    sensitive = lambda s: secret.search(s) or convo.search(s) or paths.search(s)  # noqa: E731
    findings = []

    for pname, schema in tool.parameters().items():
        pdesc = schema.get("description", "") if isinstance(schema, dict) else ""
        if name_tokens(pname) & C.SENSITIVE_PARAM_TOKENS:
            related = [pdesc] + [s for s in split_sentences(tool.description) if re.search(rf"\b{re.escape(pname)}\b", s, I)]
            hit = next((s for s in related if sensitive(s)), None)
            if hit:
                findings.append(Finding(
                    "exfiltration", "high", tool.name,
                    f"Parameter '{pname}' looks like a free-text side channel, but it is described as carrying "
                    f"secrets, files or conversation data.", hit, f"param:{pname}"))
                continue
        if pdesc and sensitive(pdesc) and fill.search(pdesc):
            findings.append(Finding("exfiltration", "medium", tool.name,
                                    f"Parameter '{pname}' is meant to be filled with sensitive data.", pdesc, f"param:{pname}"))

    first_sentence = (split_sentences(strip_invisible(tool.description)) or [""])[0]
    can_send = bool({"network:write", "email:send"} & set(tool.permissions))
    for location, text in tool.texts():
        for sentence in split_sentences(strip_invisible(text)):
            if re.search(r"https?://\S+", sentence) and transfer.search(sentence) and data_noun.search(sentence):
                # Sending is fine when it is the tool's declared main job; hidden extras are not.
                primary = location == "description" and sentence == first_sentence and can_send and not side_effect.search(sentence)
                findings.append(Finding("exfiltration", "low" if primary else "high", tool.name,
                                        "Says that data is sent to an outside web address"
                                        + (" (this looks like the tool's declared main job)." if primary else "."),
                                        sentence, location))
            elif paths.search(sentence) and fill.search(sentence):
                findings.append(Finding("exfiltration", "high", tool.name,
                                        "Asks for a sensitive file to be attached or passed along.", sentence, location))
            elif (secret.search(sentence) or convo.search(sentence)) and fill.search(sentence) and re.search(
                    r"\b(parameter|argument|field|request|answer|reply|response|message|forward|call)\b", sentence, I):
                findings.append(Finding("exfiltration", "high", tool.name,
                                        "Asks for secrets or private conversation data to be copied into a request or reply.",
                                        sentence, location))
    return _dedupe(findings)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in findings:
        key = (f.check, f.evidence)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


# --------------------------------------------------- check 4: over-permission
def allowed_permissions(tool: Tool) -> tuple[set[str] | None, list[str]]:
    """Permissions the tool's stated purpose justifies, plus the purposes matched.

    Returns (None, []) when no purpose is recognised.
    """
    first_sentence = (split_sentences(strip_invisible(tool.description)) or [""])[0]
    text = (tool.name.replace("_", " ") + " " + first_sentence).lower()
    allowed, matched = set(), []
    for purpose, (keywords, perms) in C.PURPOSES.items():
        if any(re.search(r"\b" + re.escape(k.strip()), text) for k in keywords):
            allowed |= perms
            matched.append(purpose)
    return (allowed if matched else None), matched


def check_over_permission(tool: Tool) -> list[Finding]:
    """Flag clear mismatches; mention borderline ones at low severity (shown, not counted)."""
    allowed, matched = allowed_permissions(tool)
    purpose = " / ".join(matched) if matched else "unclear"
    if allowed is None:
        clear = [p for p in tool.permissions if p not in C.UNKNOWN_PURPOSE_TOLERATED]
        borderline = []
    else:
        extra = [p for p in tool.permissions if p not in allowed]
        borderline = [p for p in extra if p in C.LOW_RISK_PERMISSIONS]
        clear = [p for p in extra if p not in C.LOW_RISK_PERMISSIONS]
    findings = []
    if clear:
        severe = any(p in C.HIGH_RISK_PERMISSIONS for p in clear)
        findings.append(Finding(
            "over_permission", "high" if severe else "medium", tool.name,
            f"Asks for {', '.join(clear)} but its stated purpose ({purpose}) does not need it. "
            f"Extra permissions give a compromised tool more power to cause harm.", ", ".join(clear), "permissions"))
    if borderline:
        findings.append(Finding(
            "over_permission", "low", tool.name,
            f"Also asks for {', '.join(borderline)}, which its stated purpose ({purpose}) does not obviously need. "
            f"Worth a look, but read-level access is common.", ", ".join(borderline), "permissions"))
    return findings


# ------------------------------------------------------ check 5: look-alikes
def normalize_name(name: str) -> str:
    """Lowercase, undo look-alike characters (1->l, Cyrillic а->a ...), drop separators."""
    mapped = "".join(C.HOMOGLYPHS.get(ch, ch) for ch in name.lower())
    return re.sub(r"[^a-z]", "", mapped)


def edit_distance(a: str, b: str) -> int:
    """Levenshtein distance: the minimum number of single-letter edits to turn a into b."""
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def check_lookalike(tool: Tool) -> list[Finding]:
    findings = []
    raw = tool.name.lower()
    if raw not in C.WELL_KNOWN_TOOLS:
        norm = normalize_name(tool.name)
        for known in C.WELL_KNOWN_TOOLS:
            kn = normalize_name(known)
            if norm == kn:
                findings.append(Finding("lookalike_names", "high", tool.name,
                                        f"The name '{tool.name}' is the well-known tool '{known}' written with look-alike "
                                        f"characters or different separators.", tool.name, "name"))
                break
            if max(len(norm), len(kn)) >= 7:
                similarity = 1 - edit_distance(norm, kn) / max(len(norm), len(kn))
                if similarity >= C.SIMILARITY_THRESHOLD:
                    findings.append(Finding("lookalike_names", "medium", tool.name,
                                            f"The name '{tool.name}' is {similarity:.0%} similar to the well-known tool "
                                            f"'{known}'. It may be trying to be mistaken for it.", tool.name, "name"))
                    break
    for sentence in split_sentences(strip_invisible(tool.description)):
        if re.search(C.OVERRIDE_PATTERN, sentence, I):
            findings.append(Finding("lookalike_names", "high", tool.name,
                                    "The description tries to replace or override another tool (shadowing).",
                                    sentence, "description"))
    return findings


CHECKS = {
    "hidden_instructions": check_hidden_instructions,
    "obfuscation": check_obfuscation,
    "exfiltration": check_exfiltration,
    "over_permission": check_over_permission,
    "lookalike_names": check_lookalike,
}


def run_static_checks(tool: Tool) -> list[Finding]:
    """Run checks 1-5 on one tool."""
    findings = []
    for fn in CHECKS.values():
        findings.extend(fn(tool))
    return findings
