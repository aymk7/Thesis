import os
import json
import time
import ollama

# ── Configuration ──────────────────────────────────────────────────────────────
MODEL_NAME       = "qwen2.5:14b"  
DATASET_DIR      = "removed"
DEMO_DIR         = "removed"
# ───────────────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a Kubernetes security auditor. Your task is to analyse \
a set of Kubernetes manifest files that together form a single cluster configuration \
and assess whether the cluster contains a security misconfiguration.

In this context, a misconfiguration is a security weakness that only becomes apparent \
when multiple manifest files are read together, for example, a permission granted in \
one file that becomes dangerous because of how another resource is configured. You \
should focus on cross resource relationships, not just the contents of any single \
file in isolation.

Your objective is to look for security issues involving RBAC, service accounts, \
network policies, and secret access. Pay particular attention to how permissions \
and policies interact across different resources and files.

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


def load_folder(folder_path, strip=False):
    files = {}
    for filename in sorted(os.listdir(folder_path)):
        if filename.endswith(".yaml"):
            with open(os.path.join(folder_path, filename), "r", encoding="utf-8") as f:
                files[filename] = f.read()
    return files


def format_cluster(files):
    sections = []
    for filename, contents in files.items():
        sections.append(f"--- FILE: {filename} ---\n{contents}")
    return "\n\n".join(sections)


def build_prompt(test_files):
    demo_misc_01 = load_folder(os.path.join(DEMO_DIR, "demonstration_misconfigured_01"))
    demo_misc_02 = load_folder(os.path.join(DEMO_DIR, "demonstration_misconfigured_02"))
    demo_clean_01 = load_folder(os.path.join(DEMO_DIR, "demonstration_clean_01"))
    demo_clean_02 = load_folder(os.path.join(DEMO_DIR, "demonstration_clean_02"))

    prompt = """The following are demonstration examples showing how to analyse Kubernetes manifest files and return a verdict.

--- DEMONSTRATION 1 (Misconfigured) ---
{demo_misc_01}

Expected output:
{{"verdict": "misconfigured", "category": "Overly broad RBAC binding to unauthenticated users", "relevant_files": ["role.yaml", "rolebinding.yaml"], "justification": "The role.yaml grants get, list, and watch permissions on nodes and pods. The rolebinding.yaml binds this Role to system:unauthenticated, meaning any unauthenticated user, with no credentials at all, can enumerate all nodes and pods in the infrastructure namespace. The misconfiguration is only visible by reading both files together: the role file alone does not reveal the dangerous subject, and the binding file alone does not reveal the sensitive permissions being granted."}}

--- DEMONSTRATION 2 (Misconfigured) ---
{demo_misc_02}

Expected output:
{{"verdict": "misconfigured", "category": "Unnecessary secret access for static web server", "relevant_files": ["deployment.yaml", "role.yaml", "rolebinding.yaml", "serviceaccount.yaml"], "justification": "The deployment.yaml defines a metrics-dashboard workload running nginx:1.25.3 and explicitly states in its annotation that it serves pre-built HTML charts with no backend API calls or credential access required. However, the role.yaml grants get, list, and watch permissions on all secrets in the observability namespace, and the rolebinding.yaml binds this role to the metrics-dashboard-sa ServiceAccount, which is the same ServiceAccount mounted by the deployment. The misconfiguration only becomes visible by reading all four files together, the deployment establishes the workload has no legitimate need for secret access, while the role and binding establish it has been granted exactly that."}}

--- DEMONSTRATION 3 (Clean) ---
{demo_clean_01}

Expected output:
{{"verdict": "clean", "category": null, "relevant_files": [], "justification": "The role.yaml grants read-only access to deployments in the cicd namespace. The rolebinding.yaml binds this role to the ci-status-checker-sa ServiceAccount within the cicd namespace only. The permissions are appropriately scoped, a CI pipeline status checker legitimately needs to read deployment status, and the binding correctly restricts this access to the cicd namespace. No cross-resource permission relationships create unnecessary risk."}}

--- DEMONSTRATION 4 (Clean) ---
{demo_clean_02}

Expected output:
{{"verdict": "clean", "category": null, "relevant_files": [], "justification": "The deployment.yaml defines an SMTP email service and its annotation explicitly states it requires access to the smtp-credentials secret for authenticated email delivery. The role.yaml grants get access to only the smtp-credentials secret via resourceNames scoping. The rolebinding.yaml binds this role to the smtp-mailer-sa ServiceAccount which is the same ServiceAccount mounted by the deployment. Reading all four files together confirms the secret access is both necessary and appropriately scoped, the workload legitimately needs credentials for email delivery and access is restricted to exactly that one secret."}}

--- NOW ANALYSE THE FOLLOWING CLUSTER ---
Below are the Kubernetes manifest files for a single cluster. Before giving your verdict, reason through the following steps:
Step 1: Identify all resources defined across the files and their types
Step 2: Map the relationships between resources: which subjects are bound to which \
roles, which pods use which service accounts, which network policies select which pods
Step 3: Assess whether any cross-resource relationship creates a security weakness \
belonging to one of the six categories above
Step 4: Give your verdict in the JSON schema below

{test_cluster}""".format(
        demo_misc_01=format_cluster(demo_misc_01),
        demo_misc_02=format_cluster(demo_misc_02),
        demo_clean_01=format_cluster(demo_clean_01),
        demo_clean_02=format_cluster(demo_clean_02),
        test_cluster=format_cluster(test_files)
    )
    return prompt


def evaluate_example(folder, example):
    path = os.path.join(DATASET_DIR, folder, example)
    files = load_folder(path)
    user_prompt = build_prompt(files)

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
    misconfigured = [f"example_{i:02d}" for i in range(1, 51)] + \
                    [f"example_{i}" for i in range(76, 101)] + \
                    [f"example_{i}" for i in range(101, 116)]
    clean = [f"example_{i:02d}" for i in range(51, 76)] + \
            [f"example_{i}" for i in range(116, 121)]

    print("\nRunning CoT + Few-shot blind evaluation on misconfigured examples...\n")
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

    print("\n\nRunning CoT + Few-shot blind evaluation on clean examples...\n")
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

    print("\n" + "=" * 70)
    print(f"OVERALL (CoT + Few-shot Blind): {correct_misc + correct_clean}/{total_misc + total_clean}")
    print("=" * 70)

    all_results = {**misc_results, **clean_results}
    with open("full_results_cot_few_shot_blind.json", "w") as f:
        json.dump(all_results, f, indent=2)
    print("\nFull results saved to full_results_cot_few_shot_blind.json")
