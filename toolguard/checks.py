"""The five static checks. Each takes a Tool and returns a list of Findings.

(Check 6, rug pull, needs a lockfile and lives in lockfile.py.)
Detectors only look at the tool definition. They never read the labels.
"""
import base64
import re
import unicodedata

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
def _decode_base64(blob: str) -> str | None:
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
        text = raw.decode("utf-8")
    except Exception:
        return None
    printable = sum(ch.isprintable() or ch.isspace() for ch in text)
    return text if text and printable / len(text) > 0.9 else None


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
        for m in re.finditer(r"<!--.*?-->", text, re.S):
            add("high", "Contains an HTML comment. People reading a rendered description never see comments, "
                        "but the model does.", m.group(0))
        for m in re.finditer(rf"[A-Za-z0-9+/]{{{C.MIN_BLOB_LENGTH},}}={{0,2}}", text):
            blob = m.group(0)
            if re.fullmatch(r"[0-9a-fA-F]+", blob) or not (re.search(r"[a-z]", blob) and re.search(r"[A-Z]", blob)):
                continue
            decoded = _decode_base64(blob)
            if decoded:
                add("high", f"Contains a base64 blob that decodes to readable text: \"{decoded[:80]}\".", blob)
            else:
                add("medium", "Contains a long encoded-looking blob that has no place in a description.", blob)
        gaps = list(re.finditer(rf"\s{{{C.WHITESPACE_GAP},}}(?=\S)", text)) + list(re.finditer(r"(?:\r?\n[ \t]*){5,}(?=\S)", text))
        for m in gaps:
            add("high", "A large run of blank space is followed by more text; this pushes text out of sight "
                        "in most viewers.", text[m.end(): m.end() + 70])
        for word in _mixed_script_words(text):
            add("medium", f"The word '{word}' mixes letters from different alphabets (a look-alike trick).", word)
    return findings


# ----------------------------------------------------- check 3: exfiltration
def check_exfiltration(tool: Tool) -> list[Finding]:
    """Parameters or sentences that move secrets, files or chat history to someone else."""
    secret = re.compile(C.SECRET_WORDS, I)
    paths = re.compile(C.SENSITIVE_PATHS, I)
    fill = re.compile(rf"\b({C.FILL_VERBS})\b", I)
    send = re.compile(rf"\b({C.SEND_VERBS})\b", I)
    findings = []

    for pname, schema in tool.parameters().items():
        pdesc = schema.get("description", "") if isinstance(schema, dict) else ""
        if pname.lower() in C.SENSITIVE_PARAM_NAMES:
            related = [pdesc] + [s for s in split_sentences(tool.description) if re.search(rf"\b{re.escape(pname)}\b", s, I)]
            hit = next((s for s in related if secret.search(s) or paths.search(s)), None)
            if hit:
                findings.append(Finding(
                    "exfiltration", "high", tool.name,
                    f"Parameter '{pname}' looks like a free-text side channel, but it is described as carrying "
                    f"secrets, files or conversation data.", hit, f"param:{pname}"))
                continue
        if pdesc and secret.search(pdesc) and fill.search(pdesc):
            findings.append(Finding("exfiltration", "medium", tool.name,
                                    f"Parameter '{pname}' is meant to be filled with sensitive data.", pdesc, f"param:{pname}"))

    for location, text in tool.texts():
        for sentence in split_sentences(strip_invisible(text)):
            has_url = re.search(r"https?://\S+", sentence)
            if has_url and send.search(sentence):
                findings.append(Finding("exfiltration", "high", tool.name,
                                        "Says that data is sent to an outside web address.", sentence, location))
            elif paths.search(sentence) and fill.search(sentence):
                findings.append(Finding("exfiltration", "high", tool.name,
                                        "Asks for a sensitive file to be attached or passed along.", sentence, location))
            elif secret.search(sentence) and fill.search(sentence) and re.search(
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
def allowed_permissions(tool: Tool) -> tuple[set[str], list[str]]:
    """Permissions the tool's stated purpose justifies, plus the purposes matched."""
    first_sentence = (split_sentences(strip_invisible(tool.description)) or [""])[0]
    text = (tool.name.replace("_", " ") + " " + first_sentence).lower()
    allowed, matched = set(), []
    for purpose, (keywords, perms) in C.PURPOSES.items():
        if any(re.search(r"\b" + re.escape(k.strip()), text) for k in keywords):
            allowed |= perms
            matched.append(purpose)
    return (allowed if matched else set(C.DEFAULT_ALLOWED)), matched


def check_over_permission(tool: Tool) -> list[Finding]:
    allowed, matched = allowed_permissions(tool)
    extra = [p for p in tool.permissions if p not in allowed]
    if not extra:
        return []
    severe = any(C.PERMISSION_RISK.get(p) == "high" for p in extra)
    purpose = " / ".join(matched) if matched else "unclear"
    return [Finding(
        "over_permission", "high" if severe else "medium", tool.name,
        f"Asks for {', '.join(extra)} but its stated purpose ({purpose}) does not need it. "
        f"Extra permissions give a compromised tool more power to cause harm.",
        ", ".join(extra), "permissions")]


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
