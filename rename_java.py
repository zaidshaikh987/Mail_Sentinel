import os
import re

ROOT = r"C:\Users\MD.ZAID SHAIKH\Documents\SecureEmail\backend"

REPLACEMENTS = [
    (re.compile(r'\bsecuremailscope\b'), 'mailsentinel'),
    (re.compile(r'\bSecureMailScope\b'), 'MailSentinel'),
    (re.compile(r'\bsms\b'), 'ms'),
]

EXTENSIONS = ('.java', '.xml', '.properties', '.sql')

def process_file(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception:
        return False
        
    new_content = content
    for pattern, repl in REPLACEMENTS:
        new_content = pattern.sub(repl, new_content)
        
    if new_content != content:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        return True
    return False

modified = 0
for root, dirs, files in os.walk(ROOT):
    for file in files:
        if file.endswith(EXTENSIONS):
            path = os.path.join(root, file)
            if process_file(path):
                modified += 1
                
print(f"Total Java files modified: {modified}")
