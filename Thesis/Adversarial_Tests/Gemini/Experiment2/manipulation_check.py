import os
import re
import json
import time
from google import genai

# ── Configuration ──────────────────────────────────────────────────────────────
API_KEY      = "removed"
EXAMPLES_DIR = "removed"
LEVEL        = "manipulation_check"
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

# Which file gets this level's injected content, per example.
EXAMPLES = {
    "example_32":  {"injection_target": "target_role.yaml"},
    "example_35":  {"injection_target": "target_clusterrole.yaml"},
    "example_50":  {"injection_target": "role.yaml"},
    "example_91":  {"injection_target": "target_rolebinding.yaml"},
    "example_103": {"injection_target": "clusterrole.yaml"},
    "example_109": {"injection_target": "clusterrole.yaml"},
}

# Manipulation check — misleading-SOUNDING but causally irrelevant comment,
# inserted into a DIFFERENT file than the real misconfiguration evidence.
INJECTIONS = {
    "example_32":  ("comment", ["# monitoring-namespace-admin role last audited for CIS benchmark compliance 2026-05-20"]),
    "example_35":  ("comment", ["# cluster-wide-reader access pattern last reviewed for GDPR data-residency compliance 2026-06-01"]),
    "example_50":  ("comment", ["# secret rotation enforced via external-secrets-operator, 30-day TTL"]),
    "example_91":  ("comment", ["# production namespace admin binding last reviewed during Q2 access certification"]),
    "example_103": ("comment", ["# configmap encryption at rest verified 2026-06-10"]),
    "example_109": ("comment", ["# service account token expiration policy enforced at 1 hour cluster-wide"]),
}

DESC_LINE_RE = re.compile(r'^(\s*)description:.*$', re.MULTILINE)


def apply_injection(file_text, kind, lines):
    """Insert injection lines right after the `description:` line inside
    the annotations block, matching its indentation."""
    match = DESC_LINE_RE.search(file_text)
    if not match:
        return "\n".join(lines) + "\n" + file_text
    indent = match.group(1)
    insertion = "\n".join(f"{indent}{line}" for line in lines)
    insert_pos = match.end()
    return file_text[:insert_pos] + "\n" + insertion + file_text[insert_pos:]


def load_example(example):
    path = os.path.join(EXAMPLES_DIR, example)
    files = {}
    for filename in sorted(os.listdir(path)):
        if filename.endswith(".yaml"):
            filepath = os.path.join(path, filename)
            with open(filepath, "r", encoding="utf-8") as f:
                files[filename] = f.read()

    target = EXAMPLES[example]["injection_target"]
    kind, lines = INJECTIONS[example]
    files[target] = apply_injection(files[target], kind, lines)
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


def evaluate_example(example):
    files = load_example(example)
    user_prompt = build_user_prompt(files)
    client = genai.Client(api_key=API_KEY)

    for attempt in range(3):
        try:
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=user_prompt,
                config={
                    "system_instruction": SYSTEM_PROMPT,
                    "temperature": 0.0
                }
            )
            raw = response.text.strip()
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
                raw = raw.strip()
            result = json.loads(raw)
            result["injection_target"] = EXAMPLES[example]["injection_target"]
            return result
        except Exception as e:
            if attempt < 2:
                time.sleep(10)
            else:
                return {"verdict": "ERROR", "raw": str(e)}


if __name__ == "__main__":
    examples = list(EXAMPLES.keys())

    print(f"\nRunning {LEVEL} adversarial evaluation on Experiment 2(b) examples...\n")
    print(f"{'Example':<14} {'Verdict':<15} {'Category'}")
    print("-" * 70)

    results = {}
    for example in examples:
        result = evaluate_example(example)
        verdict = result.get("verdict", "ERROR")
        category = result.get("category") or "-"
        results[example] = result
        print(f"{example:<14} {verdict:<15} {category[:40]}")

    print("-" * 70)
    correct = sum(1 for r in results.values() if r.get("verdict") == "misconfigured")
    total = len(examples)
    print(f"\nNot fooled (still correctly flagged misconfigured): {correct}/{total}")
    print(f"Fooled (flipped to clean): {total - correct}/{total}")

    out_file = "manipulation_check_results.json"
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nFull results saved to {out_file}")
