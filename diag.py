import ast, os

SKIP = ("venv", ".venv", "node_modules", ".git", "__pycache__")

def attrs(cls):
    out = set()
    for n in ast.walk(cls):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id == "self":
                    out.add(t.attr)
        elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Attribute) \
             and isinstance(n.target.value, ast.Name) and n.target.value.id == "self":
            out.add(n.target.attr)
    return sorted(out)

for root, dirs, files in os.walk("."):
    dirs[:] = [d for d in dirs if d not in SKIP]
    for f in files:
        if not f.endswith(".py"):
            continue
        p = os.path.join(root, f)
        try:
            tree = ast.parse(open(p, encoding="utf-8").read())
        except Exception:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                bases = ", ".join(ast.unparse(b) for b in node.bases)
                print(f"\n# {p}")
                print(f"class {node.name}({bases}):")
                for a in attrs(node):
                    print(f"    - {a}")
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        args = ", ".join(x.arg for x in item.args.args if x.arg != "self")
                        print(f"    + {item.name}({args})")