import os
import json
import time
import ollama

# ── Configuration ──────────────────────────────────────────────────────────────
MODEL_NAME  = "qwen2.5:14b" 
DATASET_DIR = "removed"
# ───────────────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a Kubernetes security auditor. Your task is to analyse \
a set of Kubernetes manifest files that together form a single cluster configuration \
and assess whether the cluster contains a security misconfiguration.

In this context, a misconfiguration is a security weakness that only becomes apparent \
when multiple manifest files are read together, for example, a permission granted in \
one file that becomes dangerous because of how another resource is configured. You \
should focus on cross resource relationships, not just the contents of any single \
file in isolation.

Your objective is to look for security issues belonging to one of the following six \
categories:

1. Overly Broad RBAC Bindings, a RoleBinding or ClusterRoleBinding that grants \
permissions to system:authenticated or system:unauthenticated
2. Overly Permissive Service Accounts, a ServiceAccount bound to a Role granting \
excessive permissions beyond what the workload requires
3. Ineffective Network Policies, a NetworkPolicy whose podSelector does not match \
the labels of any Pod, making it silently ineffective
4. RBAC Privilege Escalation Verbs, a Role or ClusterRole granting the escalate, \
bind, or impersonate verbs on RBAC resources
5. Unnecessary Secret Access, a ServiceAccount mounted by a workload that has no \
legitimate need for secret access, granted read permissions on secrets
6. ClusterRoleBinding Scope Misconfiguration, a ClusterRoleBinding granting \
cluster wide scope to a subject or role that only requires namespace scoped access, \
where a Role/RoleBinding would have sufficed

If you are uncertain, still return a verdict rather than refusing to answer.

Only flag a misconfiguration if the evidence is clearly present in the provided files. \
Do not speculate about what a service might or might not need based on its name or type \
alone, base your verdict strictly on what the files explicitly show.

For your response, return only a valid JSON object using the schema below. Do not \
include any text, explanation, or markdown outside the JSON object.

Output format:
{
  "verdict": "misconfigured" or "clean",
  "category": "short phrase describing the type of misconfiguration, or null if clean",
  "relevant_files": ["list of filenames relevant to the finding, or empty list if clean"],
  "justification": "explanation of the cross-resource reasoning that led to this verdict"
}"""


def load_example(folder, example):
    path = os.path.join(DATASET_DIR, folder, example)
    files = {}
    for filename in sorted(os.listdir(path)):
        if filename.endswith(".yaml"):
            filepath = os.path.join(path, filename)
            with open(filepath, "r", encoding="utf-8") as f:
                files[filename] = f.read()
    return files


def build_user_prompt(files):
    sections = []
    for filename, contents in files.items():
        sections.append(f"--- FILE: {filename} ---\n{contents}")
    file_block = "\n\n".join(sections)
    return (
        "Below are the Kubernetes manifest files for a single cluster. "
        "Analyse them together as a complete cluster configuration and "
        "return your verdict in the JSON schema specified.\n\n"
        + file_block
    )


def evaluate_example(folder, example):
    files = load_example(folder, example)
    user_prompt = build_user_prompt(files)

    for attempt in range(3):
        try:
            response = ollama.chat(
                model=MODEL_NAME,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt}
                ],
                options={"temperature": 0},
                format="json"
            )
            raw = response["message"]["content"].strip()
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
                raw = raw.strip()
            return json.loads(raw)
        except Exception as e:
            if attempt < 2:
                time.sleep(3)
            else:
                return {"verdict": "ERROR", "raw": str(e)}


if __name__ == "__main__":
    # Misconfigured: examples 01-50 and 76-100
    misconfigured = [f"example_{i:02d}" for i in range(1, 51)] + \
                    [f"example_{i}" for i in range(76, 101)] + \
                    [f"example_{i}" for i in range(101, 116)]

    # Clean: examples 51-75
    clean = [f"example_{i:02d}" for i in range(51, 76)] + \
            [f"example_{i}" for i in range(116, 121)]

    # ── Misconfigured examples ─────────────────────────────────────────────────
    print("\nRunning category-aware evaluation on misconfigured examples...\n")
    print(f"{'Example':<14} {'Verdict':<15} {'Category'}")
    print("-" * 70)

    misc_results = {}
    for example in misconfigured:
        result = evaluate_example("Misconfigured_Files", example)
        verdict = result.get("verdict", "ERROR")
        category = result.get("category") or "-"
        misc_results[example] = result
        print(f"{example:<14} {verdict:<15} {category[:40]}")

    print("-" * 70)
    correct_misc = sum(1 for r in misc_results.values() if r.get("verdict") == "misconfigured")
    total_misc = len(misconfigured)
    print(f"\nCorrect (misconfigured): {correct_misc}/{total_misc}")
    print(f"False negatives: {total_misc - correct_misc}/{total_misc}")

    # ── Clean examples ─────────────────────────────────────────────────────────
    print("\n\nRunning category-aware evaluation on clean examples...\n")
    print(f"{'Example':<14} {'Verdict':<15} {'Category'}")
    print("-" * 70)

    clean_results = {}
    for example in clean:
        result = evaluate_example("Clean_Files", example)
        verdict = result.get("verdict", "ERROR")
        category = result.get("category") or "-"
        clean_results[example] = result
        print(f"{example:<14} {verdict:<15} {category[:40]}")

    print("-" * 70)
    correct_clean = sum(1 for r in clean_results.values() if r.get("verdict") == "clean")
    total_clean = len(clean)
    print(f"\nCorrect (clean): {correct_clean}/{total_clean}")
    print(f"False positives: {total_clean - correct_clean}/{total_clean}")

    # ── Overall summary ────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print(f"OVERALL: {correct_misc + correct_clean}/{total_misc + total_clean}")
    print("=" * 70)

    # Save full results
    all_results = {**misc_results, **clean_results}
    with open("full_results_aware.json", "w") as f:
        json.dump(all_results, f, indent=2)
    print("\nFull results saved to full_results_aware.json")
