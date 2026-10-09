"""Turn an uploaded file into searchable text.

Supported inputs
    text  UTF-8 (an optional BOM is stripped). The stored plaintext is the text itself.
    pdf   Detected by its "%PDF-" header. The stored plaintext is the original PDF bytes;
          the text layer is extracted with pypdf for indexing and for display on decrypt.

Scanned PDFs without a text layer are rejected (no OCR), as are password-protected
PDFs. Error messages never include document content.
"""
from __future__ import annotations

import io
import logging
from dataclasses import dataclass

MAX_PDF_PAGES = 500

# pypdf logs parser warnings; keep them quiet so nothing derived from a document reaches the console.
logging.getLogger("pypdf").setLevel(logging.ERROR)


class DocumentError(ValueError):
    """The file cannot be read. The message is safe to show to the user."""


@dataclass(frozen=True)
class Document:
    kind: str          # "text" or "pdf"
    text: str          # what gets indexed and shown on decrypt
    stored: bytes      # what gets encrypted and uploaded
    pages: int | None = None


def is_pdf(data: bytes) -> bool:
    return data.lstrip(b"\x00\t\n\r\f ")[:5] == b"%PDF-"


def extract_pdf_text(data: bytes) -> tuple[str, int]:
    """Return (text, page_count) for a PDF. Raises DocumentError."""
    from pypdf import PdfReader
    from pypdf.errors import PdfReadError

    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        if reader.is_encrypted:
            raise DocumentError("password-protected PDFs are not supported; remove the password and try again")
        pages = len(reader.pages)
        if pages > MAX_PDF_PAGES:
            raise DocumentError(f"the PDF has more than {MAX_PDF_PAGES} pages")
        text = "\n\n".join((page.extract_text() or "") for page in reader.pages)
    except DocumentError:
        raise
    except (PdfReadError, ValueError, KeyError, TypeError, OSError, RecursionError, AttributeError):
        raise DocumentError("this PDF could not be read; it may be damaged") from None
    return text, pages


def read_document(data: bytes) -> Document:
    if is_pdf(data):
        text, pages = extract_pdf_text(data)
        if not text.strip():
            raise DocumentError("this PDF has no text layer (it may be a scan); OCR is not supported")
        return Document("pdf", text, data, pages)
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise DocumentError("only UTF-8 text files and PDFs are supported") from None
    return Document("text", text, text.encode("utf-8"))


def text_from_stored(kind: str, stored: bytes) -> str:
    """Recover the searchable text from decrypted stored bytes."""
    if kind == "pdf":
        return extract_pdf_text(stored)[0]
    return stored.decode("utf-8")
