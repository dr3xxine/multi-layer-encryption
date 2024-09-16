# Multi layer encryption idea

## Usage
encrypt:
```bash
python3 app.py e -i input.file -k key.file -o encrypted.file -t encryption_layers_count
```
decrypt:
```bash
python3 app.py d -i encrypted.file -k key.file -o decrypted.file
```
Result:
```
\dir
  |-app.py
  |-input.file
  |-key.file
  |-encrypted.file
  |-decrypted.file (same content as input.file)
```