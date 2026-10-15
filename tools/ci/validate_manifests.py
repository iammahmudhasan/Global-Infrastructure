#!/usr/bin/env python3
"""
NexusEdge Infrastructure Manifest Validator (CI Gate)
Validates that all Kubernetes & custom resource manifests in infra/ conform to standard
metadata schema, match CRD specifications, and enforce RFC documentation boundaries.
"""

import os
import sys
import re

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
INFRA_DIR = os.path.join(REPO_ROOT, "infra", "regions")
CRD_DIR = os.path.join(REPO_ROOT, "infra", "crds")

def simple_yaml_parse(filepath):
    """Simple parser to extract key properties without third-party dependencies."""
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    lines = content.splitlines()
    data = {}
    current_section = None
    metadata_fields = []
    in_metadata = False
    in_spec = False

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip())

        if indent == 0 and ":" in stripped:
            key, val = stripped.split(":", 1)
            key = key.strip()
            val = val.strip().strip('"\'')
            data[key] = val
            current_section = key
            in_metadata = (key == "metadata")
            in_spec = (key == "spec")
            continue

        if in_metadata and indent == 2 and ":" in stripped:
            m_key = stripped.split(":", 1)[0].strip()
            metadata_fields.append(m_key)

    data["_raw"] = content
    data["_metadata_fields"] = metadata_fields
    return data

def validate_file(filepath):
    filename = os.path.relpath(filepath, REPO_ROOT)
    data = simple_yaml_parse(filepath)
    raw = data.get("_raw", "")

    api_version = data.get("apiVersion")
    kind = data.get("kind")

    if not api_version or not kind:
        raise ValueError(f"{filename}: Missing apiVersion or kind")

    if kind in ("PeeringPolicy", "EdgeNodeSpecification"):
        if api_version != "infrastructure.nexusedge.io/v1alpha1":
            raise ValueError(f"{filename}: Invalid apiVersion {api_version}")

        # Metadata hygiene: reject direct non-standard fields in metadata
        allowed_metadata = {"name", "namespace", "labels", "annotations"}
        for field in data.get("_metadata_fields", []):
            if field not in allowed_metadata:
                raise ValueError(
                    f"{filename}: Invalid metadata field '{field}'. Custom attributes must be under labels or spec."
                )

        # RFC truthfulness check: if RFC 5737 (198.51.100), RFC 3849 (2001:db8), or RFC 6996 (64512) is used,
        # the manifest MUST be marked as SIMULATION_TESTBED or PROPOSED_SPECIFICATION
        has_rfc_testbed_data = (
            "198.51.100." in raw or
            "2001:db8" in raw or
            "64512" in raw
        )
        if has_rfc_testbed_data:
            if "SIMULATION_TESTBED" not in raw and "PROPOSED_SPECIFICATION" not in raw:
                raise ValueError(
                    f"{filename}: Uses reserved documentation IPs/ASNs but is not explicitly declared as SIMULATION_TESTBED."
                )

        if kind == "PeeringPolicy":
            if "local_asn" not in raw:
                raise ValueError(f"{filename}: PeeringPolicy must specify local_asn")
            if "advertised_prefixes" not in raw:
                raise ValueError(f"{filename}: PeeringPolicy must specify advertised_prefixes")
            if "tier:" not in raw:
                raise ValueError(f"{filename}: PeeringPolicy must specify spec.tier")

        if kind == "EdgeNodeSpecification":
            if "hostname" not in raw:
                raise ValueError(f"{filename}: EdgeNodeSpecification must specify hostname")
            if "role" not in raw:
                raise ValueError(f"{filename}: EdgeNodeSpecification must specify role")
            if "tier:" not in raw:
                raise ValueError(f"{filename}: EdgeNodeSpecification must specify spec.tier")

    return True

def main():
    print("Validating NexusEdge Infrastructure Resource Manifests...")
    count = 0

    target_dirs = [INFRA_DIR, CRD_DIR]
    for d in target_dirs:
        if not os.path.exists(d):
            continue
        for root, _, files in os.walk(d):
            for f in sorted(files):
                if f.endswith(".yaml") or f.endswith(".yml"):
                    full_path = os.path.join(root, f)
                    try:
                        validate_file(full_path)
                        rel_path = os.path.relpath(full_path, REPO_ROOT)
                        print(f"  OK: {rel_path}")
                        count += 1
                    except Exception as e:
                        print(f"  ERROR: {e}", file=sys.stderr)
                        sys.exit(1)

    print(f"All {count} infrastructure manifests verified valid.")

if __name__ == "__main__":
    main()
