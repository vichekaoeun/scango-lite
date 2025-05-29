# scango-lite

A lightweight static analyzer for Go security issues.

## Installation

```bash
go install github.com/vichekaoeun/scango-lite@latest
```
**NOTE**: If installation says any release <1.1.0 then run the latest release instead:
```bash
go install github.com/vichekaoeun/scango-lite@v1.1.0
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