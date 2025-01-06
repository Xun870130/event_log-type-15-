# Event Log Analyzer 

A Python-based utility for analyzing event logs, extracting hexadecimal blocks, and detecting SMBIOS Type 15 entries. This project is designed for developers and system engineers who need detailed insights from event logs.

---

## Features 
- **Hex Block Extraction**: Extracts hex blocks from event logs for further analysis.
- **SMBIOS Type 15 Detection**: Identifies and parses Type 15 SMBIOS entries.
- **Configurable Parsing**: Utilizes an `.ini` file (`smbios_type15.ini`) for flexible configuration.
- **Comprehensive Output**: Logs results to a `.log` file for future reference.

---

## Project Structure 
```plaintext
.
├── EventLogAnalyzer.py      # Main script for event log analysis
├── SmbiosAnalyzer.py        # Handles SMBIOS-specific data processing
├── Log2matrix.py            # Converts log data into hex matrices
├── res_smbiosConfig.py      # Parses SMBIOS Type 15 configuration
├── smbios_type15.ini        # Configuration file for SMBIOS Type 15
├── run.bat                  # Batch file for quick execution
├── README.md                # Project documentation
```
## Requirements 
- **Python 3.10+**
- **Required modules:**
- os
- argparse
- configparser
- re

## Setup Instructions 
---
Clone the repository:

```bash
複製程式碼
git clone https://github.com/your-username/event-log-analyzer.git
cd event-log-analyzer
```
Install dependencies:

- Ensure you have Python 3.10+ installed.
- Install any missing modules using pip:
```bash
複製程式碼
pip install <module_name>
```
Update the smbios_type15.ini file if needed.
Place your log file in the appropriate directory.

## Usage 
1. Running the Analyzer
Run the script using the command below:

```bash
複製程式碼
python EventLogAnalyzer.py "D:\VScode\project\event_log\example\1224smbios.log"
```
2. Using the Batch File
A convenient run.bat is provided for quick execution:

Place the batch file (run.bat) in the project directory.
Update the file path in the .bat file if necessary.
Double-click run.bat to execute.
Example run.bat:

```plaintext
複製程式碼
@echo off
event_log_analyzer.exe D:\VScode\project\event_log\example\1224smbios.log
:WAIT
echo tap Q to esc
choice /c Q /n >nul
goto :EOF
```
## Output 
After running the script, results will be saved in a file named analysis_result.log in the current directory. This file contains:

Hex block analysis.
SMBIOS Type 15 detection results.
Summary of processed and skipped blocks.
Contributing 
Contributions are welcome! Feel free to open issues or submit pull requests.

Fork the repository.
Create a new branch for your feature/bug fix.
Submit a pull request.
## License 
This project is licensed under the MIT License. See the LICENSE file for details.

