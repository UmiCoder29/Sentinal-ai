import ast
import os
import re
from typing import List, Dict, Any

class SQLScanner(ast.NodeVisitor):
    def __init__(self, filename: str):
        self.filename = filename
        self.vulnerabilities = []
        self.sql_keywords = {"select", "insert", "update", "delete", "from", "where", "drop", "alter", "union", "exec"}
        self.unsafe_methods = ["execute", "executemany", "raw"]
        
        # Regex for common injection keywords and symbols
        self.injection_regex = re.compile(
            r"(\s(OR|AND)\s+['\"].*['\"]=.*)|"  # Tautologies
            r"(--|#|\/\*)|"                      # Comments
            r"(UNION\s+SELECT)|"                 # Union
            r"(WAITFOR\s+DELAY)|"                # Time delay
            r"(SLEEP\(.*\))|"                    # Sleep
            r"(BENCHMARK\(.*\))",                 # Benchmark
            re.IGNORECASE
        )
        
        # Track variables that hold SQL-like strings
        self.query_vars = {}

    def visit_Assign(self, node):
        # Track if a variable is assigned a SQL query string
        if isinstance(node.value, (ast.Constant, ast.BinOp, ast.JoinedStr, ast.Call)):
            is_sql = False
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                if self.is_sql_query(node.value.value):
                    is_sql = True
            elif isinstance(node.value, (ast.BinOp, ast.JoinedStr, ast.Call)):
                # Heuristic: if it's dynamic, we check if it's likely SQL later
                is_sql = True 

            for target in node.targets:
                if isinstance(target, ast.Name):
                    if is_sql:
                        self.query_vars[target.id] = node.value

        self.generic_visit(node)

    def is_sql_query(self, s: str) -> bool:
        if not isinstance(s, str): return False
        s_lower = s.lower()
        return any(keyword in s_lower for keyword in self.sql_keywords)

    def visit_Call(self, node):
        # Look for calls to database execution methods
        method_name = None
        if isinstance(node.func, ast.Attribute):
            method_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            method_name = node.func.id

        if method_name in self.unsafe_methods:
            if node.args:
                query_node = node.args[0]
                
                # Case 1: Direct unsafe string in call
                self._check_query_node(query_node, node.lineno)
                
                # Case 2: Variable passed to call
                if isinstance(query_node, ast.Name) and query_node.id in self.query_vars:
                    self._check_query_node(self.query_vars[query_node.id], node.lineno)
        
        self.generic_visit(node)

    def _check_query_node(self, node, lineno):
        is_unsafe = False
        reason = ""
        severity = "Medium"

        # Check for dynamic string construction (Highest Risk)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            is_unsafe = True
            reason = "Unsafe string concatenation or % formatting in SQL query"
            severity = "High"
        elif isinstance(node, ast.JoinedStr):
            is_unsafe = True
            reason = "Unsafe f-string used in SQL query"
            severity = "High"
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                is_unsafe = True
                reason = "Unsafe .format() used in SQL query"
                severity = "High"

        # Check for injection patterns in constants
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if self.injection_regex.search(node.value):
                is_unsafe = True
                reason = "Common SQL injection pattern detected in string"
                severity = "Critical"

        if is_unsafe:
            # Avoid duplicate reports for the same line
            if any(v["line"] == lineno and v["file"] == self.filename for v in self.vulnerabilities):
                return

            try:
                with open(self.filename, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    code_line = lines[lineno - 1].strip() if lineno <= len(lines) else "Unknown"
            except Exception:
                code_line = "Unknown"

            self.vulnerabilities.append({
                "file": self.filename,
                "line": lineno,
                "code": code_line,
                "reason": reason,
                "severity": severity,
                "remediation": "Use parameterized queries (e.g., cursor.execute('SELECT... WHERE id = ?', (id,)))",
                "explanation": "Directly embedding user input into SQL strings allows attackers to bypass security logic."
            })

def scan_file(filepath: str) -> List[Dict[Any, Any]]:
    with open(filepath, "r", encoding="utf-8") as f:
        try:
            tree = ast.parse(f.read())
            scanner = SQLScanner(filepath)
            scanner.visit(tree)
            return scanner.vulnerabilities
        except SyntaxError:
            return []

def scan_directory(path: str) -> List[Dict[Any, Any]]:
    all_vulnerabilities = []
    if os.path.isfile(path):
        if path.endswith(".py"):
            return scan_file(path)
        return []
        
    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith(".py"):
                filepath = os.path.join(root, file)
                all_vulnerabilities.extend(scan_file(filepath))
    return all_vulnerabilities
