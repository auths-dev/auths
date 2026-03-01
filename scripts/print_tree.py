import os

EXCLUDE_DIRS = {
    "target", "build", "dist", "node_modules", ".git", ".idea", ".vscode", "__pycache__"
}

def print_tree(start_path='.', prefix='', output=[]):
    try:
        entries = sorted(os.listdir(start_path))
    except PermissionError:
        return

    entries = [e for e in entries if e not in EXCLUDE_DIRS]
    for index, entry in enumerate(entries):
        path = os.path.join(start_path, entry)
        connector = '└── ' if index == len(entries) - 1 else '├── '
        output.append(prefix + connector + entry)
        if os.path.isdir(path):
            extension = '    ' if index == len(entries) - 1 else '│   '
            print_tree(path, prefix + extension, output)

def main():
    output = []
    print_tree('.', '', output)
    with open('project_tree.txt', 'w') as f:
        f.write('\n'.join(output))
    print("✅ File structure written to project_tree.txt")

if __name__ == '__main__':
    main()
