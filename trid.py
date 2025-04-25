import subprocess
import os

def run_trid_and_clean(root_dir, output_log):
    with open(output_log, 'w', encoding='utf-8') as outlog:
        # Walk through all files
        for dirpath, _, filenames in os.walk(root_dir):
            for filename in filenames:
                full_path = os.path.join(dirpath, filename)
                
                try:
                    # Run trid with LC_ALL=C to avoid locale crash(idk what hell happened)
                    result = subprocess.run(
                        ["./trid", full_path],
                        env={**os.environ, "LC_ALL": "C"},
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        encoding='utf-8',
                        errors='ignore'
                    )

                    # Parse and keep only the result lines
                    lines = result.stdout.splitlines()
                    relevant_lines = []
                    capture = False

                    for line in lines:
                        if line.strip().startswith("Collecting data from file:"):
                            capture = True
                            continue

                        if capture:
                            if line.strip() == "":
                                break  # End of relevant block
                            if not line.startswith("TrID") and not line.startswith("Definitions") and not line.startswith("Analyzing"):
                                relevant_lines.append(line.strip())

                    # Write results if found
                    if relevant_lines:
                        outlog.write("\n".join(relevant_lines) + "\n\n")

                except Exception as e:
                    print(f"Failed to process {full_path}: {e}")

# Example usage
run_trid_and_clean(
    root_dir='/home/user01/Downloads/go-fuzz-corpus-master',
    output_log='/home/user01/Downloads/trid_cleaned.txt'
)
