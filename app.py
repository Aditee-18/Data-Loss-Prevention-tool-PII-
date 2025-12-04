import streamlit as st
from analyzer import detect_pii, redact_text_block
from pdf_redactor import redact_pdf_with_boxes
import PyPDF2
import pandas as pd

# Page Config
st.set_page_config(page_title="PII Redaction Tool", layout="wide", page_icon="🛡️")
st.markdown("<style>.stAppDeployButton {display:none !important;}</style>", unsafe_allow_html=True)

# THE HEADER YOU WANTED
st.title("AI-Powered PII Data Loss Prevention (DLP) Tool")
st.markdown("### Intelligent Sensitive Data Detection & Redaction Pipeline")

# --- SIDEBAR ---
with st.sidebar:
    st.header("⚙️ Configuration")
    
    st.markdown("**Entities to Redact:**")
    chk_names = st.checkbox("Names", value=True)
    chk_ids = st.checkbox("IDs & PINs", value=True)
    chk_addr = st.checkbox("Addresses", value=True)
    chk_contacts = st.checkbox("Phones & Emails", value=True)
    chk_orgs = st.checkbox("Organizations", value=False)
    
    # Removed "Locations" as requested

# --- UPLOAD ---
uploaded_file = st.file_uploader("Upload Document (PDF/TXT)", type=["pdf", "txt"])

if uploaded_file:
    # 1. READ FILE
    text = ""
    if uploaded_file.name.endswith(".pdf"):
        try:
            pdf = PyPDF2.PdfReader(uploaded_file)
            for page in pdf.pages: text += page.extract_text() or ""
            uploaded_file.seek(0)
        except: st.error("PDF Read Error")
    else:
        # Standardize newlines
        raw_bytes = uploaded_file.read()
        text = raw_bytes.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
        uploaded_file.seek(0)

    # 2. DETECT
    pii = detect_pii(text)
    
    # 3. FILTER
    active_pii = []
    
    for entity in pii:
        t = entity['type']
        if t == "PERSON" and chk_names: active_pii.append(entity)
        elif t == "ADDRESS" and chk_addr: active_pii.append(entity)
        elif t in ["STUDENT_ID", "PIN"] and chk_ids: active_pii.append(entity)
        elif t in ["PHONE", "EMAIL"] and chk_contacts: active_pii.append(entity)
        elif t == "ORG" and chk_orgs: active_pii.append(entity)
    
    # 4. REDACT (Blocks)
    redacted_text = redact_text_block(text, active_pii)
    
    # 5. DISPLAY
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("📄 Original Text")
        st.text_area("raw", text, height=400)
    with col2:
        st.subheader("🔒 Redacted Output")
        st.text_area("clean", redacted_text, height=400)
    
    # 6. DOWNLOADS
    st.divider()
    st.subheader("💾 Download Results")
    
    c1, c2 = st.columns(2)
    
    with c1:
        st.download_button(
            label="Download .txt File",
            data=redacted_text,
            file_name="redacted_output.txt"
        )
        
    with c2:
        if uploaded_file.name.endswith(".pdf"):
            if st.button("Generate Secure PDF"):
                try:
                    pdf_bytes = redact_pdf_with_boxes(uploaded_file, active_pii)
                    st.download_button(
                        label="Download Redacted PDF",
                        data=pdf_bytes,
                        file_name="redacted_output.pdf",
                        mime="application/pdf"
                    )
                except Exception as e:
                    st.error(f"Error: {e}")
        else:
            st.info("Upload a PDF to download PDF output.")