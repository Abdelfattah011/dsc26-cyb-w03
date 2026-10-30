# AI usage: dsc26-cyb-w03

Keep the three headings below exactly as they are. The grader stops and scores 0 if this file is
missing or any of the three headings is missing. It does not score what you write; your Track
Mentor reads it, and the W8 defence can ask about it.

## Tools

<!-- Which AI tools you used (or "none"), and for which parts of the task. -->

## What AI got wrong

<!-- At least one thing an AI tool got wrong that you changed, and how you noticed:
     a test, the docs, running it. -->

## In my own words# AI usage: dsc26-cyb-w03

Keep the three headings below exactly as they are. The grader stops and scores 0 if this file is missing or any of the three headings is missing. It does not score what you write; your Track Mentor reads it, and the W8 defence can ask about it.

## Tools

- Gemini for assistance in writing and structuring Python functions (`validation.py`, `policy.py`, `passwords.py`).

## What AI got wrong

- Sometimes initially suggested generic error handling or standard exceptions that needed strict adjustments to match the custom `ValidationError` and specific parameter bounds required by the challenge prompt.

## In my own words

1. Why does `get_document` return 404 rather than 403 when a client asks for another client's contract?
   - To prevent information disclosure (enumeration attacks). Returning 403 would confirm to an unauthorized user that the document actually exists in the system, whereas 404 hides its existence entirely.

2. Why must `verify_password` refuse a stored hash that is shorter than 32 bytes, even though the prefix matches?
   - To ensure cryptographic integrity and prevent truncated or weak hashes from being processed, since scrypt expects a full 32-byte derived key (`dklen=32`) to properly secure the password comparison.
