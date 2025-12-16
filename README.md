# jsecret

A simple, fast, and concurrent tool to detect sensitive data (API keys, tokens, passwords, etc.) in source code files like JavaScript.

## Installation

### Via Go (`@latest`)
Install the latest release directly from GitHub:
```bash
go install github.com/jjardel-infosec/jsecret@latest
```

Make sure your Go bin directory is in `PATH`:
- Linux/macOS: `$(go env GOPATH)/bin`
- Windows: `%USERPROFILE%\\go\\bin`

### From Source
1. Clone the repository:
   ```bash
   git clone https://github.com/jjardel-infosec/jsecret.git
   cd jsecret
   ```

2. Build the project:
   ```bash
   go build
   ```

3. (Optional) Move the binary to your path to use it globally:
   ```bash
   sudo mv jsecret /usr/local/bin/
   ```

## Usage

`jsecret` supports input via stdin (pipes), single URL via flag, or file input.

### Flags
- `-u`: Scan a single URL.
- `-f`: Scan a list of URLs from a file.
- `-t`: Set the number of concurrent threads (default: 50).
- `-h`: Show help message.

### Examples

**1. Standard Input (Pipe)**
Great for chaining with other tools like `waybackurls`, `gau`, or `cat`.
```bash
cat urls.txt | jsecret
echo "http://example.com/app.js" | jsecret
```

**2. Single URL**
```bash
jsecret -u http://example.com/config.js
```

**3. File Input**
```bash
jsecret -f urls.txt
```

**4. Directory Scan (Recursive)**
Scan all `.js` files in a directory (and subdirectories).
```bash
jsecret -d /path/to/js/files
# Or scan current directory
jsecret -d .
```

**5. Save Output to File**
Save the results to a file while still seeing them in the console.
```bash
jsecret -f urls.txt -o results.txt
```

Scan the current directory recursively and write findings to a file:
```bash
jsecret -d . -o secrets_found.txt
```

The output file is plain text (no colors) and uses the same format as stdout:
```text
[target] Signature Name : match
```

**6. High Concurrency**
Increase threads for faster scanning (default is 50).
```bash
jsecret -f urls.txt -t 100
```
