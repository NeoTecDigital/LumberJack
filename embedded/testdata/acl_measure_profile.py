# Written by Richard Christopher, Copyright 2026 NeoTec, LLC
"""Write a measuring artifact from the real business profile builder, labelled relations only.

Run with the backend's interpreter:
  backend/.venv/bin/python embedded/testdata/acl_measure_profile.py BACKEND OUTPUT [--scope-bytes N]

The labelled relation pads the generic record's access list to the field count the P&G capture
reported (432). --scope-bytes lifts the byte bounds for a before-the-change run past the real
refusal; it is a measuring profile with its own digest and never reaches an installation.
"""
import argparse
import base64
import json
import sys
import uuid

TARGET_FIELDS = 432
FAMILY = "resource:png_source.labelled.relation"


def labelled_table(specs, columns):
    names = tuple(specs.ColumnSpec("c%03d" % index, "text") for index in range(columns))
    keys = (specs.ColumnSpec("id", "uuid"), specs.ColumnSpec("federation_id", "uuid"))
    return specs.TableSpec("labelled.relation", (*keys, *names), ("id",), tenant_column="federation_id")


def extended(png, builder, specs, columns):
    install = str(uuid.uuid5(uuid.NAMESPACE_URL, "labelled-s1-measure"))
    value = builder.build(install, "labelled-s1-approval")
    return png.extend(value, (*png.feature_tables(), labelled_table(specs, columns)))


def record_field_count(value):
    return len(value["provisioningProfile"]["ownerGrants"]["png_record"]["png.store.read"]["fields"])


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
    parser.add_argument("--scope-bytes", type=int)
    args = parser.parse_args()
    sys.path.insert(0, args.backend)
    from services.manifest.enrollment import profile_digest
    from services.manifest.migration import png_snapshot as specs
    from services.retained.business.profile import builder, png

    columns = TARGET_FIELDS - record_field_count(extended(png, builder, specs, 0))
    value = extended(png, builder, specs, columns)
    if record_field_count(value) != TARGET_FIELDS:
        raise SystemExit("labelled padding did not reach the reported field count")
    profile = value["provisioningProfile"]
    if args.scope_bytes:
        profile["bounds"]["maxScopeBytes"] = args.scope_bytes
        profile["bounds"]["maxSnapshotBytes"] = args.scope_bytes * 2
        profile["profileRef"]["profileRevision"] = "labelled-measure-only"
        profile["profileRef"]["profileDigest"] = profile_digest(profile)
    catalog = json.dumps(value["roleCatalog"], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    artifact = {"provisioningProfile": profile, "roleCatalog": base64.b64encode(catalog).decode(),
                "administrationGrants": administrator_grants(profile), "family": FAMILY,
                "columns": ["c%03d" % index for index in range(columns)]}
    with open(args.output, "w") as stream:
        json.dump(artifact, stream, sort_keys=True)


if __name__ == "__main__":
    main()
