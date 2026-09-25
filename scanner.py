import ast
import sys


class SecurityScanner(ast.NodeVisitor):
    def __init__(self):
        self.findings = []

    def report(self, severity, message, node):
        self.findings.append({
            "severity": severity,
            "message": message,
            "line": node.lineno
        })

    # Detect eval()
    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):
            if node.func.id == "eval":
                self.report(
                    "HIGH",
                    "Use of eval() can allow arbitrary code execution",
                    node
                )

            elif node.func.id == "exec":
                self.report(
                    "HIGH",
                    "Use of exec() can allow arbitrary code execution",
                    node
                )

        # Detect subprocess(..., shell=True)
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ["run", "call", "Popen"]:
                for keyword in node.keywords:
                    if (
                        keyword.arg == "shell"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is True
                    ):
                        self.report(
                            "HIGH",
                            "subprocess used with shell=True",
                            node
                        )

        self.generic_visit(node)

    # Detect hardcoded passwords
    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name):
                variable = target.id.lower()

                if "password" in variable or "passwd" in variable:
                    if isinstance(node.value, ast.Constant):
                        self.report(
                            "MEDIUM",
                            "Possible hardcoded password detected",
                            node
                        )

        self.generic_visit(node)


def scan_file(filename):
    try:
        with open(filename, "r", encoding="utf-8") as file:
            source = file.read()

        tree = ast.parse(source, filename=filename)

        scanner = SecurityScanner()
        scanner.visit(tree)

        return scanner.findings

    except FileNotFoundError:
        print(f"[ERROR] File not found: {filename}")
        sys.exit(1)

    except SyntaxError as error:
        print(f"[ERROR] Syntax error at line {error.lineno}: {error.msg}")
        sys.exit(1)


def main():
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <python_file>")
        sys.exit(1)

    filename = sys.argv[1]

    print("=" * 60)
    print("       Python AST Security Scanner")
    print("=" * 60)
    print(f"\nScanning: {filename}\n")

    findings = scan_file(filename)

    if not findings:
        print("[+] No security issues detected.")
    else:
        for finding in findings:
            print(
                f"[{finding['severity']}] "
                f"Line {finding['line']}: "
                f"{finding['message']}"
            )

        print(f"\n[!] Scan completed: {len(findings)} issue(s) found.")

    print("=" * 60)


if __name__ == "__main__":
    main()