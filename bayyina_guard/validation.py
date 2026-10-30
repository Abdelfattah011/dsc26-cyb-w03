from __future__ import annotations

import unicodedata
import uuid
import re
from dataclasses import dataclass

MAX_BYTES = 25 * 1024 * 1024


class ValidationError(Exception):
    def __init__(self, errors: dict[str, str]):
        super().__init__(", ".join(sorted(errors)))
        self.errors = errors


@dataclass(frozen=True)
class CleanUpload:
    stored_name: str
    display_name: str
    extension: str
    content_type: str
    size_bytes: int
    matter_id: str


def validate_upload(meta: dict) -> CleanUpload:
    errors: dict[str, str] = {}
    
    filename = meta.get("filename")
    content_type = meta.get("content_type")
    size_bytes = meta.get("size_bytes")
    matter_id = meta.get("matter_id")
    first_bytes = meta.get("first_bytes")
    
    display_name = None
    ext = None
    if not isinstance(filename, str):
        errors["filename"] = "Filename must be a string."
    else:
        display_name = unicodedata.normalize("NFC", filename)
        
        if not (1 <= len(display_name) <= 120):
            errors["filename"] = "Filename length must be between 1 and 120 characters."
        else:
            bidi_controls = {"\u061C", "\u200E", "\u200F", "\u202A", "\u202B", "\u202C", "\u202D", "\u202E", "\u2066", "\u2067", "\u2068", "\u2069"}
            has_control_or_bidi = any(unicodedata.category(c) == "Cc" or c in bidi_controls for c in display_name)
            
            if has_control_or_bidi:
                errors["filename"] = "Filename contains forbidden control or bidi characters."
            elif "/" in display_name or "\\" in display_name or ".." in display_name:
                errors["filename"] = "Filename contains forbidden path traversal sequences."
            elif display_name.startswith("."):
                errors["filename"] = "Filename must not start with a dot."
            else:
                parts = display_name.rsplit(".", 1)
                if len(parts) < 2 or not parts[0].strip():
                    errors["filename"] = "Filename must have a non-blank name before the extension."
                else:
                    ext = parts[1].lower()
                    if ext not in ("pdf", "docx"):
                        errors["filename"] = "Extension must be pdf or docx."

    if filename is not None and isinstance(filename, str) and not errors.get("filename"):
        expected_ct = "application/pdf" if ext == "pdf" else "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        if content_type != expected_ct:
            errors["content_type"] = f"Invalid content type for {ext}."
    else:
        if not isinstance(content_type, str):
            errors["content_type"] = "Content type must be a string."

    if not isinstance(first_bytes, bytes):
        errors["first_bytes"] = "First bytes must be of type bytes."
    elif filename is not None and isinstance(filename, str) and not errors.get("filename"):
        if ext == "pdf" and not first_bytes.startswith(b"%PDF-"):
            errors["first_bytes"] = "PDF file must start with %PDF-."
        elif ext == "docx" and not first_bytes.startswith(b"PK\x03\x04"):
            if "first_bytes" not in errors:
                errors["first_bytes"] = "DOCX file must start with PK\\x03\\x04."

    if isinstance(size_bytes, bool) or not isinstance(size_bytes, int):
        errors["size_bytes"] = "Size must be an integer."
    elif not (1 <= size_bytes <= MAX_BYTES):
        errors["size_bytes"] = "Size out of allowed range."

    if not isinstance(matter_id, str):
        errors["matter_id"] = "Matter ID must be a string."
    else:
        is_ascii = all(ord(c) < 128 for c in matter_id)
        # تم تصحيح الشرطة لتكون بافن `-` بدلاً من الشرطة السفلية `_` مطابقة للمواصفات
        pattern = re.compile(r"^MAT-\d{4}-\d{5}$")
        if not is_ascii or not pattern.match(matter_id):
            errors["matter_id"] = "Invalid matter ID format."

    if errors:
        raise ValidationError(errors)

    stored_name = f"{uuid.uuid4().hex}.{ext}"

    return CleanUpload(
        stored_name=stored_name,
        display_name=display_name,
        extension=ext,
        content_type=content_type,
        size_bytes=size_bytes,
        matter_id=matter_id
    )
