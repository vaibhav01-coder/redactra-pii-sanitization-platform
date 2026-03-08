# REDACTRA — PII Detection & Document Sanitization Platform

REDACTRA is a platform that automatically detects and sanitizes sensitive personal information (PII) from documents before they are shared.

It scans uploaded files, identifies sensitive data such as Aadhaar numbers, PAN numbers, phone numbers, emails, and bank details, and removes or masks them to prevent data leaks.

---

## Features

* Automatic PII detection
* Multiple sanitization modes (Redact, Mask, Tokenize)
* Support for multiple file formats (PDF, DOCX, CSV, JSON, TXT, PNG, JPG)
* Malware scanning integration
* Metadata removal for privacy
* Risk scoring system for detected data
* Secure file processing

---

## PII Detection

The platform uses a multi-layer detection system:

* **Regex detection** for structured identifiers (Aadhaar, PAN, phone, email)
* **spaCy NER** for contextual entities (names, addresses, dates)
* **Microsoft Presidio** for advanced PII recognition

This layered approach improves detection accuracy and reduces false positives.

---

## Tech Stack

Frontend
React, HTML, CSS, JavaScript

Backend
Python, FastAPI

AI / NLP
spaCy, Microsoft Presidio

Security
VirusTotal API, Encryption, SHA-256 hashing

Database
Supabase

---

## Project Structure

```
redactra/
├── app/
├── ui/
├── scripts/
├── storage/
├── requirements.txt
└── README.md
```

---

## Installation

Clone the repository:

```
git clone https://github.com/vaibhav01-coder/redactra-pii-sanitization-platform.git
```

Move into the project directory:

```
cd redactra-pii-sanitization-platform
```

Install dependencies:

```
pip install -r requirements.txt
```

Run the server:

```
uvicorn main:app --reload
```

---

## License

This project is licensed under the MIT License.


This project is licensed under the **MIT License**.

---

⭐ If you like this project, consider giving it a star on GitHub!
