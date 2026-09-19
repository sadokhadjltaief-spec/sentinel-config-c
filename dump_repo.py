import os

OUTPUT_FILE = "full_repo_dump.txt"

# Target directories matching your Sentinel repository structure
FOLDERS_TO_INCLUDE = [
    "starter-kits",
    "src/sentinel",
    "scenarios",
    "policies",
    "fixtures",
    "scripts",
    "docs",
    "tests",
]

# File types to aggregate
EXTENSIONS = (".py", ".yaml", ".yml", ".json", ".md", "Makefile")

with open(OUTPUT_FILE, "w", encoding="utf-8") as outfile:
    # Read top-level repository files first
    for top_file in ["Makefile", ".env.example", "README.md"]:
        if os.path.exists(top_file):
            outfile.write(f"\n{'='*60}\nFILE: {top_file}\n{'='*60}\n")
            try:
                with open(top_file, "r", encoding="utf-8") as infile:
                    outfile.write(infile.read())
            except Exception as e:
                outfile.write(f"<Error reading file: {e}>\n")

    # Recursively traverse target sub-folders
    for folder in FOLDERS_TO_INCLUDE:
        if not os.path.exists(folder):
            continue
        for root, _, files in os.walk(folder):
            for file in files:
                if file.endswith(EXTENSIONS) or file in EXTENSIONS:
                    filepath = os.path.join(root, file)
                    outfile.write(f"\n\n{'='*60}\nFILE: {filepath}\n{'='*60}\n")
                    try:
                        with open(filepath, "r", encoding="utf-8") as infile:
                            outfile.write(infile.read())
                    except Exception as e:
                        outfile.write(f"<Error reading file: {e}>\n")

print(f"Success! Created '{OUTPUT_FILE}'. Upload this file to the chat.")