# 🛡️ AI-Powered Data Loss Prevention (DLP) System

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Security](https://img.shields.io/badge/Security-DLP-red)
![AI](https://img.shields.io/badge/Model-BERT__NER-green)
![Compliance](https://img.shields.io/badge/Compliance-GDPR%2FDPDP-orange)

An enterprise-grade **Privacy Engineering tool** designed to detect, classify, and redact Personally Identifiable Information (PII) from unstructured documents (PDFs & Text). 

This system employs a **Hybrid Detection Engine** combining Deep Learning (Transformer models) with strict RegEx patterns to achieve high-precision Data Loss Prevention (DLP) while maintaining document usability.

---

## 🚀 Key Features

*   **🧠 Hybrid Intelligence Engine:**
    *   **Deep Learning (BERT):** Uses `dslim/bert-base-NER` for context-aware entity recognition (e.g., distinguishing names in complex sentences).
    *   **Pattern Matching (Regex):** Custom-engineered patterns for high-confidence structured data (Banking PINs, Student IDs, Phone Numbers, Emails).
*   **👁️ Visual PDF Redaction:** Instead of text replacement, this tool calculates exact coordinate bounding boxes and overlays physical black masks using `PyMuPDF`, ensuring data is irretrievable.
*   **🛡️ "Stateless" Privacy Design:** Processes all data in-memory (RAM) without database retention, adhering to **Privacy by Design** principles.
*   **⚖️ Conflict Resolution Logic:** Custom algorithm to resolve overlapping detection signals (e.g., when AI and Regex detect different boundaries), prioritizing high-confidence Regex to prevent data corruption.
*   **📂 Multi-Format Support:** Bulk processing capabilities for `.txt` logs and `.pdf` documents with Optical Character Recognition (OCR) compatibility.

---

## 🛠️ Tech Stack

*   **Core Logic:** Python 3.x
*   **ML & NLP:** Hugging Face Transformers, BERT (Bidirectional Encoder Representations from Transformers)
*   **Computer Vision/PDF:** PyMuPDF (`fitz`), PyPDF2
*   **Frontend Interface:** Streamlit (React-based wrapper)
*   **Data Handling:** Pandas, Regular Expressions (Re)

---

## 🏗️ Architecture

1.  **Ingestion:** User uploads documents (Bulk/Single). Windows/Unix newline normalization is applied to prevent index shifting.
2.  **Detection Layer (Parallel Processing):**
    *   *Path A:* Regex Engine scans for structured PII (IDs, PINs, Emails, Addresses).
    *   *Path B:* BERT Transformer scans for unstructured entities (Names, Organizations).
3.  **Validation Layer:** Post-processing logic filters false positives (e.g., lowercase "basically" vs capitalized Name).
4.  **Sanitization:**
    *   *Text:* Character-replacement masking (maintaining format length).
    *   *PDF:* Coordinate mapping and visual overlay application.
5.  **Output:** Secure artifact generation (Downloadable sanitized files).

---

## 💻 Installation & Usage

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/Aditee-18/Data-Loss-Prevention-tool-PII-.git
    cd Data-Loss-Prevention-tool-PII-
    ```

2.  **Set up Virtual Environment (Recommended)**
    ```bash
    python -m venv venv
    # Windows
    .\venv\Scripts\activate
    # Mac/Linux
    source venv/bin/activate
    ```

3.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Run the System**
    ```bash
    streamlit run app.py
    ```

---

## 🔌 Enterprise Integration Guide

To integrate this DLP logic into a larger Microservices Architecture (e.g., a Bank's Document Upload Pipeline), follow this decoupling strategy:

### 1. Extract the Core Logic
The file `analyzer.py` is written as a pure Python module. It is decoupled from the UI. You can import `detect_pii` directly into a backend service.

### 2. Containerization (Docker)
Wrap the logic in a Docker container to deploy as a REST API (using FastAPI or Flask).

**Example `Dockerfile`:**
```dockerfile
FROM python:3.9-slim
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY analyzer.py .
COPY pdf_redactor.py .
# Expose API port...
