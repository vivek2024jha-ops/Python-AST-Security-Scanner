# Python-AST-Security-Scanner
A Python-based static analysis security tool using AST parsing. Detects common insecure coding patterns such as eval(), exec(), hardcoded passwords, and shell=True. Built for educational and defensive security analysis.


A Python-based static analysis security tool using AST parsing.

## Features

- Detects `eval()` usage
- Detects `exec()` usage
- Detects possible hardcoded passwords
- Detects `subprocess` with `shell=True`
- Reports severity and source-code line number

## Technologies

- Python 3
- Python AST
- Static Analysis
- Secure Coding

## Usage

```bash
python scanner.py sample_vulnerable.py
