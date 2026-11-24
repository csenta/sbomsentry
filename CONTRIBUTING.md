# Contributing to SBOMsentry

We welcome contributions to SBOMsentry.

## Development Setup

1. Clone repository:
   ```bash
   git clone https://github.com/csenta/sbomsentry.git
   cd sbomsentry
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run tests before submitting pull requests:
   ```bash
   PYTHONPATH=. python3 -m unittest discover -s tests -v
   ```
4. Follow PEP 8 guidelines and write comprehensive unit tests for all new analyzers.
