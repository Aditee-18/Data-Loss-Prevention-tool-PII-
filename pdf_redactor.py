import fitz  # PyMuPDF
import io

def redact_pdf_with_boxes(uploaded_file, pii_entities):
    uploaded_file.seek(0)
    pdf_bytes = uploaded_file.read()
    uploaded_file.seek(0)
    
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    
    for page in doc:
        for entity in pii_entities:
            clean_text = entity['text'].strip()
            if not clean_text: continue
            
            # Search and Redact
            text_instances = page.search_for(clean_text)
            for rect in text_instances:
                annot = page.add_redact_annot(rect)
                annot.set_colors(stroke=(0, 0, 0), fill=(0, 0, 0))
                annot.update()
        page.apply_redactions()
        
    output_buffer = io.BytesIO()
    doc.save(output_buffer)
    output_buffer.seek(0)
    
    return output_buffer