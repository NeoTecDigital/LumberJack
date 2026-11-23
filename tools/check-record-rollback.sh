# Written by Richard Christopher, Copyright 2026 NeoTec, LLC
# Called from the repository root. Use immutable previous engine source, not this reader.
set -euo pipefail
scratch=$(mktemp -d "$PWD/build/record-rollback.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
mkdir -m 700 "$scratch/source" "$scratch/fixtures"
export LJ_FIXTURE_OLD_READER="$scratch/fixtures"
git archive 67d19ea -- . | tar -x -C "$scratch/source"
cp embedded/testdata/prior_reader.go.txt "$scratch/source/embedded/prior_reader_test.go"
go test ./embedded -run '^TestWritePriorRecordFixture$' -count=1
(cd "$LJ_FIXTURE_OLD_READER"; sha256sum -- * > "$scratch/before")
(cd "$scratch/source"; go test ./embedded -run '^TestPriorRecordReader$' -count=1)
(cd "$LJ_FIXTURE_OLD_READER"; sha256sum --quiet --check "$scratch/before")
