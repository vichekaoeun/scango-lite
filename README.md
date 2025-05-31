# scango-lite

A lightweight static analyzer for Go security issues.

## Installation
**Go 1.23 version using Alpine Linux**:
```bash
curl -sSL https://raw.githubusercontent.com/vichekaoeun/scango-lite/main/install.sh | bash

**Go 1.21+ using your local OS**
```bash
go install github.com/vichekaoeun/scango-lite@latest

## Which Installation Method?

**For daily development:** Use `go install` (faster, simpler)
**For CI/CD pipelines:** Use Docker (consistent across environments)  
**For teams with mixed Go versions:** Use Docker (avoids conflicts)

## Usage

Scan current directory for security issues
```
scango run
```
Show help
```
scango help
```