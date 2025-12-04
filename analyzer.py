import re
from transformers import pipeline

# Load the AI Model
print("Loading Security Model...")
nlp = pipeline("token-classification", model="dslim/bert-base-NER", aggregation_strategy="simple")

# 1. BLOCKLIST (Strict ignore list)
BLOCKLIST = {
    "basically", "actually", "person", "student", "candidate", "engineer", "manager", 
    "developer", "analyst", "i", "am", "an", "ai", "what", "is", "do", "of", "multiple", 
    "interests", "work", "role", "bank", "pin", "is", "report", "lab", "semester"
}

def detect_pii(text):
    raw = []
    
    # --- STEP 1: REGEX (Specific patterns that ALWAYS work) ---
    
    # 1. Headers (Name: X, Submitted by: X, Dr. X)
    # Fixed to include 'Submitted by', 'Dr.', 'Prof.' and newlines
    header_pattern = r"(?i)(?:Name|Candidate|Student|Submitted\s+by|Submitted\s+to|Prof\.?|Dr\.?)\s*[:\-]?\s*((?:Mr\.|Ms\.|Mrs\.|Dr\.)?\s*[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)"
    
    for m in re.finditer(header_pattern, text):
        raw.append({"text": m.group(1), "type": "PERSON", "start": m.start(1), "end": m.end(1), "prio": 1})

    # 2. Names with Context (I am Aditee...)
    for m in re.finditer(r"(?:[Ii]\s+am|[Mm]y\s+name\s+is)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)", text):
        raw.append({"text": m.group(1), "type": "PERSON", "start": m.start(1), "end": m.end(1), "prio": 1})

    # 3. Student ID (VIT format) & Class IDs
    # Catches 23BCE11417 and also BL2025...
    for m in re.finditer(r"\b(?:[A-Z0-9]{2,})\d{4,}\b", text):
        # Filter: Must look like an ID (letters + numbers) or long number
        word = m.group()
        if any(c.isalpha() for c in word) and any(c.isdigit() for c in word):
             raw.append({"text": word, "type": "STUDENT_ID", "start": m.start(), "end": m.end(), "prio": 1})

    # 4. PIN / OTP / Passwords
    for m in re.finditer(r"(?i)\b(?:pin|otp|code|pass|pwd)\s*(?:is|:|h|-)?\s*(\d{4,8})\b", text):
        raw.append({"text": m.group(1), "type": "PIN", "start": m.start(1), "end": m.end(1), "prio": 1})

    # 5. Phones (10 digits)
    for m in re.finditer(r"\b\d{10}\b|\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", text):
        raw.append({"text": m.group(), "type": "PHONE", "start": m.start(), "end": m.end(), "prio": 1})
    
    # 6. Emails
    for m in re.finditer(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}", text):
         raw.append({"text": m.group(), "type": "EMAIL", "start": m.start(), "end": m.end(), "prio": 1})

    # 7. Addresses (Explicit word 'Address')
    for m in re.finditer(r"(?i)\baddress\s+[:\-]?\s*([0-9A-Za-z\s,\-\/]{5,})", text):
        if len(m.group(1)) > 5:
            raw.append({"text": m.group(1), "type": "ADDRESS", "start": m.start(1), "end": m.end(1), "prio": 2})

    # 8. Addresses (Sector/Street style)
    for m in re.finditer(r"\b\d{1,4}[/\-]\d{1,4}[\s,]+(?:sector|pkt|pocket)[-\s]?\d+\b", text, flags=re.IGNORECASE):
        raw.append({"text": m.group(), "type": "ADDRESS", "start": m.start(), "end": m.end(), "prio": 2})

    # --- STEP 2: AI MODEL (Context) ---
    try:
        results = nlp(text)
        for e in results:
            word = e['word'].strip()
            label = e['entity_group']
            
            # --- FILTERS (Fixing the mistakes) ---
            if len(word) < 2: continue
            if word.lower() in BLOCKLIST: continue
            
            # CAPITALIZATION RULE:
            # "basically" is lowercase -> Ignore. "Aditee" is Uppercase -> Keep.
            if label == "PER" and not word[0].isupper(): continue
            
            if label == "PER": t = "PERSON"
            elif label == "LOC": t = "LOCATION"
            elif label == "ORG": t = "ORG"
            else: t = "MISC"
            
            raw.append({
                "text": word,
                "type": t,
                "start": e['start'],
                "end": e['end'],
                "prio": 3 
            })
    except:
        pass

    # --- STEP 3: CLEANUP & MERGE ---
    if not raw: return []
    
    # Sort by Priority (Regex first), then Position
    # This ensures "Submitted by Aditee Srivastava" (Prio 1) wins over "Ad" (Prio 3)
    raw.sort(key=lambda x: (x['prio'], x['start']))
    
    final = []
    char_map = [False] * len(text)
    
    for ent in raw:
        start, end = ent['start'], ent['end']
        end = min(end, len(text))
        
        # Check overlap
        is_overlap = any(char_map[i] for i in range(start, end))
        
        if not is_overlap:
            final.append(ent)
            # Mark characters as taken
            for i in range(start, end):
                char_map[i] = True
            
    return final

def redact_text_block(text, pii_entities):
    """
    Replaces sensitive text with ████ blocks.
    Preserves exact length so formatting doesn't break.
    """
    chars = list(text)
    
    for ent in pii_entities:
        start = ent['start']
        end = ent['end']
        
        if start < len(chars) and end <= len(chars):
            length = end - start
            block = "█" * length
            
            for i in range(length):
                chars[start + i] = block[i]
                
    return "".join(chars)