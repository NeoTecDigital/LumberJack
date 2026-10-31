# Written by Richard Christopher, Copyright 2026 NeoTec, LLC
"""Write the labelled workload test profile from the real business profile builder.

Run with the backend's interpreter:
  backend/.venv/bin/python -I embedded/testdata/workload_profile.py BACKEND embedded/testdata/workload_profile.json

Labelled relations only. It carries the real ceilings and field masks, so the test holds the same
shape an installation does, and it runs with no Python at test time.
"""
import argparse
import base64
import json
import sys
import uuid

MESSAGES = "resource:png.messages"
FAMILIES = (MESSAGES, "resource:png.conversations", "resource:png_source.messaging.contacts")
CONTACT_COLUMNS = ("full_name", "phone_number", "email_address", "last_seen_at")


def contacts_table(specs):
    keys = (specs.ColumnSpec("id", "uuid"), specs.ColumnSpec("federation_id", "uuid"))
    columns = tuple(specs.ColumnSpec(name, "text") for name in CONTACT_COLUMNS)
    return specs.TableSpec("messaging.contacts", (*keys, *columns), ("id",), tenant_column="federation_id")


def administrator_grants(profile):
    controls = {"manifest.scope.provision", "manifest.scope.read.grant", "manifest.scope.read.revoke"}
    selected = set(profile["layout"]["profiles"]) - controls
    result = {}
    for kind, values in profile["ownerGrants"].items():
        operations = {name: grant for name, grant in values.items() if name in selected}
        if operations:
            result[kind] = operations
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("backend")
    parser.add_argument("output")
    args = parser.parse_args()
    sys.path.insert(0, args.backend)
    from services.manifest.migration import png_snapshot as specs
    from services.retained.business.profile import builder, png

    install = str(uuid.uuid5(uuid.NAMESPACE_URL, "labelled-workload"))
    value = png.extend(builder.build(install, "labelled-workload-approval"), (*png.feature_tables(), contacts_table(specs)))
    profile = value["provisioningProfile"]
    masks = {item["family"]: item["fields"] for item in value["fieldMasks"]
             if item["action"] == png.IMPORT_ACTION and item["family"] in FAMILIES}
    if set(masks) != set(FAMILIES):
        raise SystemExit("the real builder did not give all three families a mask")
    catalog = json.dumps(value["roleCatalog"], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    columns = [name for name in masks[MESSAGES] if name not in ("id", "account_id")]
    artifact = {"provisioningProfile": profile, "roleCatalog": base64.b64encode(catalog).decode(),
                "administrationGrants": administrator_grants(profile), "family": MESSAGES,
                "columns": columns, "workloadFamilies": masks}
    with open(args.output, "w") as stream:
        json.dump(artifact, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")


if __name__ == "__main__":
    main()
