```ruby
 ██████╗  ██████╗ ██╗  ██╗████████╗ ██████╗  ██████╗ ██╗
 ██╔══██╗██╔════╝ ██║  ██║╚══██╔══╝██╔═══██╗██╔═══██╗██║
 ██████╔╝███████╗ ███████║   ██║   ██║   ██║██║   ██║██║
 ██╔══██╗██╔═══██╗╚════██║   ██║   ██║   ██║██║   ██║██║
 ██████╔╝╚██████╔╝     ██║   ██║   ╚██████╔╝╚██████╔╝███████╗
 ╚═════╝  ╚═════╝      ╚═╝   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
```

* **Multi format encoding/decoding CLI with recursive layer detection for security analysis.** 

## Features

- **Encode/Decode** across Base64, Base64URL, Base32, Hex, and URL encoding formats
- **Auto-detect** encoding format with confidence scoring
- **Peel** recursively through multi-layered encoding (the kind attackers use to evade WAFs and IDS)
- **Chain** multiple encoding steps together for testing obfuscation patterns
- **Pipeline-friendly** output for integration into security workflows

## Quick Start

```bash
uv sync
uv run b64tool encode "Hello World"
uv run b64tool decode "SGVsbG8gV29ybGQ="
uv run b64tool detect "SGVsbG8gV29ybGQ="
uv run b64tool peel "NjQ0ODY1NmM2YzZmMjA1NzZmNzI2YzY0"
uv run b64tool chain "secret" --steps base64,hex,url
```

## Installation

```bash
uv sync --all-extras
```

## Usage

### Encode

```bash
b64tool encode "Hello World"                        # Base64 (default)
b64tool encode "Hello World" --format hex            # Hex
b64tool encode "Hello World" --format base32         # Base32
b64tool encode "hello world&foo=bar" --format url    # URL encoding
echo "piped input" | b64tool encode                  # Stdin
b64tool encode --file secret.txt                     # File input
```

### Decode

```bash
b64tool decode "SGVsbG8gV29ybGQ="                   # Base64 (default)
b64tool decode "48656c6c6f" --format hex             # Hex
b64tool decode "JBSWY3DP" --format base32            # Base32
```

### Detect

Identifies the encoding format with confidence scoring:

```bash
b64tool detect "SGVsbG8gV29ybGQ="
```

### Peel (Recursive Layer Detection)

The signature feature. Automatically peels back multiple encoding layers, the way real malware and attack payloads obfuscate data:

```bash
b64tool peel "NjQ0ODY1NmM2YzZmMjA1NzZmNzI2YzY0"
```

### Chain

Build multi-layered encodings for testing WAF rules, IDS signatures, or understanding obfuscation:

```bash
b64tool chain "alert('xss')" --steps base64,hex,url
```

## Security Context

Encoding layering is a real attack technique:

- **WAF Bypass**: Double-encoding payloads to slip past web application firewalls (OWASP)
- **Malware Obfuscation**: DARKGATE malware uses custom Base64 alphabets with randomized shuffling
- **Data Exfiltration**: Base64-encoded data hidden in DNS queries and HTTP headers
- **IDS Evasion**: Multi-layer encoding to avoid signature-based detection

This tool helps security professionals analyze and understand these patterns.

## License

MIT
