# REDACTRA — PII Detection & Document Sanitization Platform

🚀 AI-powered platform that automatically detects and sanitizes sensitive personal information (PII) from documents before they are shared.

Built during the **Nirma University Hackathon** by team **Cipher-Knights**.

---

## 📌 Problem Statement

Sensitive information is present in many documents shared daily such as:

* Aadhaar Numbers
* PAN Numbers
* Phone Numbers
* Email Addresses
* Bank Details
* Addresses

Manual redaction of such data is **slow, inconsistent, and prone to human error**.
Many existing tools rely only on regex detection and fail to understand **contextual information** like names and addresses.

As a result, organizations frequently risk **data leaks and regulatory violations (DPDP / GDPR)**.

---

## 💡 Solution

**REDACTRA** is an automated platform that detects and sanitizes sensitive data from uploaded documents using a multi-layer PII detection engine.

Workflow:

Upload Document → Malware Scan → PII Detection → Sanitization → Download Clean File

The system ensures that documents are **cleaned of sensitive data before they leave an organization**.

---

## ✨ Key Features

* 🔍 **Advanced PII Detection**

  * Regex pattern detection
  * spaCy Named Entity Recognition
  * Microsoft Presidio integration

* 🧾 **Multiple File Format Support**

  * PDF
  * DOCX
  * CSV
  * JSON
  * TXT
  * PNG
  * JPG

* 🛡 **Security Layer**

  * Malware scanning using VirusTotal
  * Metadata stripping
  * File validation
  * Encryption
  * Audit logs

* 🔄 **Three Sanitization Modes**

  * Redact
  * Mask
  * Tokenize

* 📊 **Risk Scoring System**

  * Low
  * Moderate
  * High
  * Critical

* 🔐 **Privacy-First Design**

  * Files automatically deleted after 24 hours

* 👤 **Role-Based Access**

  * Admin
  * User

---

## 🧠 PII Detection Engine

REDACTRA uses a **3-layer detection pipeline** to improve accuracy.

### Layer 1 — Regex Detection

Detects structured identifiers such as:

* Aadhaar
* PAN
* Phone numbers
* Email addresses
* Bank accounts
* UPI IDs
* IFSC codes

### Layer 2 — spaCy Named Entity Recognition

Detects contextual information such as:

* Names
* Addresses
* Dates
* Locations

### Layer 3 — Microsoft Presidio

* Combines results
* Removes duplicates
* Detects additional entities

This layered architecture significantly reduces **false positives**.

---

## 📊 Detected PII Entities

REDACTRA detects **15+ sensitive data types**, including:

* Aadhaar Number
* PAN Card
* Passport
* Voter ID
* Phone Numbers
* Email Addresses
* Bank Accounts
* Card Numbers
* IFSC Codes
* UPI IDs
* IP Address
* Date of Birth
* Full Name
* Address

---

## 🏗 System Architecture

The platform consists of multiple components:

Frontend → Document Upload Interface
Backend → FastAPI Processing Server
Detection Engine → Regex + spaCy + Presidio
Security Layer → Malware scan & metadata stripping
Database → Supabase storage
File Processing → Sanitization & export

---

## 🛠 Tech Stack

### Frontend

* HTML
* CSS
* JavaScript
* React

### Backend

* FastAPI
* Python

### AI / NLP

* spaCy
* Microsoft Presidio

### Security

* VirusTotal API
* SHA-256 hashing
* Fernet Encryption

### Database

* Supabase

---

## 📂 Project Structure

```
redactra/
│
├── app/                # Backend application
├── ui/                 # Frontend interface
├── scripts/            # Utility scripts
├── storage/            # Processed files storage
├── docs/               # Hackathon presentation
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation

Clone the repository:

```
git clone https://github.com/vaibhav01-coder/redactra-pii-sanitization-platform.git
```

Move into the project folder:

```
cd redactra-pii-sanitization-platform
```

Install dependencies:

```
pip install -r requirements.txt
```

Run the application:

```
uvicorn main:app --reload
```

---

## 🚧 Limitations

* Handwritten documents are not supported
* Low-quality scanned PDFs may reduce OCR accuracy
* VirusTotal free tier limits daily scans
* English-first detection (limited regional language support)
* Batch processing may take longer for large datasets

---

## 📄 Hackathon Presentation

The project presentation can be found in:

```
docs/redactra-hackathon-presentation.pdf
```

---

## 👨‍💻 Team Cipher-Knights

* Aljan
* Vaibhav
* Jeet
* Tarun
* Naimish

Built for **Nirma University Hackathon – Tribastion Track**

---

## 📜 License

This project is licensed under the **MIT License**.

---

⭐ If you like this project, consider giving it a star on GitHub!
