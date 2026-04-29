# Sentinel SQL Scanner

Sentinal is a learning project and work in progress. It is not production-ready and should not be used as your only security tool.

Sentinel is a lightweight, offline static analysis tool designed to find potential SQL Injection vulnerabilities in Python codebases. It uses Abstract Syntax Trees (AST) to identify unsafe patterns where user input might be directly concatenated into SQL queries.

## 🚀 Features

- **Static Code Analysis**: Scans `.py` files without executing the code.
- **Deep Pattern Matching**: Detects unsafe f-strings, `.format()` calls, `%` formatting, and string concatenation in SQL queries.
- **Severity Ranking**: Categorizes findings as Critical, High, Medium, or Low based on the risk level.
- **Detailed Reporting**: Provides console summaries with file locations, code snippets, and remediation advice.
- **Smart CLI**: Handles file paths with spaces automatically.

## 🛠️ Installation

Ensure you have Python installed and the required dependencies:

```bash
pip install rich
```

## 📖 How to Use

Run the scanner from the project root directory.

### Basic Usage
Scan the current directory:
```bash
python -m sql_scanner
```

### Scan a Specific Folder
Specify a relative or absolute path:
```bash
python -m sql_scanner C:\path\to\your\python_project
```

### Handle Folders with Spaces
The scanner automatically joins arguments, so you don't need quotes for paths with spaces (though they still work):
```bash
python -m sql_scanner My Project Folder
# OR
python -m sql_scanner "C:\Users\Name\My Project"
```

## 🔍 What it Detects

Sentinel looks for common "Red Flags" in your database code:

1.  **Direct Concatenation**: `cursor.execute("SELECT * FROM users WHERE name = '" + user_input + "'")`
2.  **f-strings in Queries**: `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`
3.  **Unsafe Formatting**: `query.format(val)` or `query % val` used for SQL statements.
4.  **Injection Signatures**: Common attack patterns like `OR '1'='1'`, `UNION SELECT`, and `SLEEP()`.

## 📄 Output

The tool provides a structured table in your terminal showing:
- **Severity**: How dangerous the finding is.
- **Location**: The exact file and line number.
- **Reason**: Why it was flagged (e.g., "Unsafe f-string used in SQL query").
- **Remediation**: Actionable advice on how to fix the vulnerability (e.g., "Use parameterized queries").

---
*Stay secure. Scan before you deploy.*
