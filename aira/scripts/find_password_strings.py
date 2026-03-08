import re

with open('F:/Nouveau dossier (10)/data/uploads/crackme.exe', 'rb') as f:
    data = f.read()

strings = re.findall(rb'[ -~]{4,}', data)
keywords = [b'pass', b'correct', b'wrong', b'invalid', b'success', b'flag', b'win', b'lose', b'enter', b'key', b'secret', b'congratul', b'good', b'bad', b'well done', b'bravo', b'try', b'nope', b'yes!', b'no!']
print("=== Strings avec mots-cles ===")
for s in strings:
    sl = s.lower()
    if any(k in sl for k in keywords):
        print(repr(s.decode('ascii', errors='replace')))

print("\n=== Strings courtes potentiellement mot de passe (4-20 chars, alphanumeric+special) ===")
for s in strings:
    if 4 <= len(s) <= 20 and re.match(rb'^[A-Za-z0-9_!\-@#\$\^]{4,20}$', s):
        print(repr(s.decode('ascii', errors='replace')))
