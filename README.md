# Aegis Export Reader (aer)

A minimal, fast terminal-based tool for reading Aegis Authenticator vault exports. Perfect for accessing your 2FA codes when your phone isn't nearby.

### Installation

#### From source
```bash
git clone https://github.com/steveljko/aegis-export-reader.git
cd aegis-export-reader
make
sudo mv bin/aer /usr/local/bin/
```

### Usage
```bash
# Read Aegis export file
aer -vault /path/to/export.json
aer -v /path/to/export.json

# Interactive password prompt
aer -v export.json
Enter vault password: ********
```
