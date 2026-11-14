"""Upload validation: extension whitelist AND magic bytes (never trust the extension alone)."""
import codecs
import os
import re
import unicodedata

# extension -> (label, list of (offset, signature)); None signature list => must be text.
_ZIP = [(0, b"PK\x03\x04")]
ALLOWED = {
    "pdf":  [(0, b"%PDF-")],
    "png":  [(0, b"\x89PNG\r\n\x1a\n")],
    "jpg":  [(0, b"\xff\xd8\xff")],
    "jpeg": [(0, b"\xff\xd8\xff")],
    "gif":  [(0, b"GIF87a"), (0, b"GIF89a")],
    "zip":  _ZIP,
    "docx": _ZIP,   # OOXML files are ZIP containers
    "xlsx": _ZIP,
    "pptx": _ZIP,
    "mp4":  [(4, b"ftyp")],
    "txt":  None,
    "csv":   None,
}


class UploadRejected(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def clean_filename(raw: str) -> str:
    """Display name only (the stored file is a random UUID). Strips paths and control chars."""
    name = unicodedata.normalize("NFC", raw or "")
    name = name.replace("\\", "/").split("/")[-1]
    name = re.sub(r"[\x00-\x1f\x7f]", "", name).strip().strip(".")
    return name[:200]


def get_extension(name: str) -> str:
    return os.path.splitext(name)[1].lstrip(".").lower()


def check_extension(name: str) -> str:
    if not name:
        raise UploadRejected("Missing file name.")
    ext = get_extension(name)
    if ext not in ALLOWED:
        raise UploadRejected(
            f"File type '.{ext or '?'}' is not allowed. Allowed: {', '.join(sorted(ALLOWED))}.", 415
        )
    return ext


def check_magic(ext: str, head: bytes) -> None:
    """`head` is the first chunk of the upload (>= 1 MiB unless the file is smaller)."""
    sigs = ALLOWED[ext]
    if sigs is None:  # plain text: no NUL bytes and valid UTF-8
        if b"\x00" in head:
            raise UploadRejected("Content does not look like a text file.", 415)
        try:
            codecs.getincrementaldecoder("utf-8")().decode(head, final=False)
        except UnicodeDecodeError:
            raise UploadRejected("Text files must be UTF-8 encoded.", 415)
        return
    if not any(head[off:off + len(sig)] == sig for off, sig in sigs):
        raise UploadRejected(f"File content does not match the '.{ext}' type (magic bytes mismatch).", 415)
