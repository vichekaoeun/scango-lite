# scango-lite

A lightweight static analyzer for Go security issues.

## Installation

```bash
curl -sSL https://raw.githubusercontent.com/vichekaoeun/scango-lite/main/install.sh | bash
```
**NOTE**: Alternatively if that doesn't works, run this command instead.
```bash
go install github.com/vichekaoeun/scango-lite@latest
```

## Usage

Scan current directory for security issues
```
scango-lite run
```
Show help
```
scango-lite help
```