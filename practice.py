import os
import subprocess

def run_trid_and_clean(root_path, output_log):
    
    with open(output_log, 'w', encoding='utf-8') as outlog:

        # Helper function to run trid and extract relevant lines
        def process_file(full_path):
            try:
                result = subprocess.run(
                    ["./trid", full_path],
                    env={**os.environ, "LC_ALL": "C"},
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    encoding='utf-8',
                    errors='ignore'
                )
                lines = result.stdout.splitlines()
                relevant_lines = []
                capture = False

                for line in lines:
                    if line.strip().startswith("Collecting data from file:"):
                        capture = True
                        continue
                    if capture:
                        if line.strip() == "":
                            break
                        if not line.startswith("Trid") and not line.startswith("Definitions") and not line.startswith("Analyzing") and not line.startswith("Warning"):
                            relevant_lines.append(line.strip())
                        

                if relevant_lines:
                    outlog.write("\n".join(relevant_lines) + "\n\n")

            except Exception as e:
                print(f"Failed to process {full_path}: {e}")

        # Check if root_path is a file
        if os.path.isfile(root_path):
            if root_path.endswith(('.txt')):
                        print("Trid doesnt not work well wirh txt files")
            process_file(root_path)
        else:
            for dirpath, _, filenames in os.walk(root_path):
                for filename in filenames:
                    full_path = os.path.join(dirpath, filename)
                    if full_path.endswith(('.txt')):
                        print("Trid doesnt not work well wirh txt files")
                    process_file(full_path)

# Example usage
run_trid_and_clean(
    root_path='/home/user01/Downloads/go-fuzz-corpus-master',
    output_log='/home/user01/Downloads/trid_cleaned2.txt'
)
