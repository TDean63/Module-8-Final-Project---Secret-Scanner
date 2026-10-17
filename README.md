Module 8 Final Project - Secret Scanner

Author
Tylar Dean
Course
Security and Secure Coding OLCP


Python Secret Scanner

Project Description
Python Secret Scanners a command line security took that checks files and directories for possible hardcoded secrets. The goal is to help developers identify sensitive credentials that may have neem accidentally included in source code.

Technologies Used
•	Python 3
•	Argparse
•	Regular expressions
•	Pathlib
•	Logging

Features
•	Scans individual files or entire directories.
•	Uses seven regex patterns to detect possible secrets.
•	Displays the filename, line number, type, and matched string.
•	Provides error messages for invalid file paths.
•	Supports optional verbose logging.
•	Displays a summary of total findings.

Detection Logic
The scanner reads files one line at a time and compares their contents against seven regular expressions.

         Pattern                                             Description
•	Hardcoded Password         Detects password assignments containing quoted values.
•	GitHub Token                          Detects tokens beginning with ghp_.
•	GitLab Token                           Detects tokens beginning with glpat-.
•	Google API Key                      Detects API keys beginning with Alza.
•	AWS Access Key                   Detects potential AWS access key identifiers.
•	Private Key                              Detects PEM private key headers.
•	Stripe Secret Key                 Detects Stripe secret and restricted key formats.
The program reports matching strings and their locations.

How to Run
1.	Install Python 3.
2.	Download or clone this repository.
3.	Open the project folder in VS Code.
4.	Open the terminal.
5.	Run one of the following commands.

Scan a single file:
python scanner.py test_files/config.py
Scan an entire directory:
python scanner.py test_files
Enable detailed logging:
python scanner.py test_files –verbose
Display help:
python scanner.py –help

Limitations
This program uses regex pattern matching, which can produce false positives. It may flag fake or inactive credentials, and it may miss secrets with formats that are not included In its patterns.
The scanner reads text files and does not interpret or execute the Python code being scanned.
The tool displays full matched strings for educational reporting purposes. Reak credentials should be redacted before sharing results.

Testing
The test_files directory contains sample files with fake credentials and safe code. These are used to verify successful detection and confirm the program works when no secrets are present.

Regex References
Provider specific detection patterns were adapted from the regextokens project:
https://github.com/odomojuli/regextokens
