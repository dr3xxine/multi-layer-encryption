# Multi layer encryption idea
This code uses random multiple methods for encoding with `fernet`, `aes`, `aes_gcm`, `chacha20`, `blowfish` methods.

## install
```bash
git clone https://github.com/dr3xxine/multi-layer-encryption.git
cd multi_layer_encryption
pip install -r requirements.txt
```
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