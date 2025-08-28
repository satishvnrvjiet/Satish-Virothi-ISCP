import sys
import re
import json
import pandas as pd

PHONE_PATTERN = re.compile(r"\b\d{10}\b")
AADHAR_PATTERN = re.compile(r"\b\d{12}\b")
PASSPORT_PATTERN = re.compile(r"\b[A-PR-WYa-pr-wy][1-9]\d{6}\b")
UPI_PATTERN = re.compile(r"[\w.-]+@[a-zA-Z]+")
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def mask_phone(value):
    return value[:2] + "XXXXXX" + value[-2:]

def mask_aadhar(value):
    return "XXXX XXXX " + value[-4:]

def mask_passport(value):
    return value[0] + "XXXXXXX"

def mask_upi(value):
    return "XXX@upi"

def mask_name(value):
    parts = value.split()
    masked = []
    for p in parts:
        if len(p) > 1:
            masked.append(p[0] + "XXX")
        else:
            masked.append(p)
    return " ".join(masked)

def mask_email(value):
    try:
        local, domain = value.split("@")
        return local[:2] + "XXX@" + domain
    except:
        return "XXX@domain.com"

def redact_address(value):
    return "[REDACTED_PII]"

def detect_and_redact(record_dict):
    is_pii = False
    redacted = {}


    has_name = False
    has_email = False
    has_address = False

    for k, v in record_dict.items():
        if not isinstance(v, str):
            redacted[k] = v
            continue

        value = v.strip()

        if PHONE_PATTERN.fullmatch(value):
            is_pii = True
            redacted[k] = mask_phone(value)
        
        elif AADHAR_PATTERN.fullmatch(value):
            is_pii = True
            redacted[k] = mask_aadhar(value)
        
        elif PASSPORT_PATTERN.fullmatch(value):
            is_pii = True
            redacted[k] = mask_passport(value)
        
        elif UPI_PATTERN.fullmatch(value):
            is_pii = True
            redacted[k] = mask_upi(value)
        
        elif k == "name":
            has_name = True
            redacted[k] = mask_name(value)
        
        elif re.match(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
            has_email = True
            redacted[k] = mask_email(value)
        
        elif k == "address":
            has_address = True
            redacted[k] = redact_address(value)
        
        elif IP_PATTERN.fullmatch(value) or k in ["device_id", "ip_address"]:
            redacted[k] = "[REDACTED_PII]"
            is_pii = True
        else:
            redacted[k] = value

    
    if (has_name and has_email) or (has_name and has_address) or (has_email and has_address):
        is_pii = True

    return redacted, is_pii


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 redacted_Satish_Virothi.py iscp_pii_dataset.csv")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = "redacted_output_Satish_Virothi.csv"

    
    df = pd.read_csv(input_file)

    results = []
    for _, row in df.iterrows():
        record_id = row["record_id"]
        try:
            data_dict = json.loads(row["data_json"])
        except:
            data_dict = {}

        redacted_dict, is_pii = detect_and_redact(data_dict)
        results.append({
            "record_id": record_id,
            "redacted_data_json": json.dumps(redacted_dict),
            "is_pii": is_pii
        })

    out_df = pd.DataFrame(results)
    out_df.to_csv(output_file, index=False)
    print(f"Redacted output written to {output_file}")
