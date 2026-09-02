package internal

// Version is the ONE place this build says what it is.
//
// THE DEFECT: /health reported a version out of a constant in api_health.go, the CLI stamped a
// different literal into every config it wrote, and the release tag was a third value maintained by
// hand. They drifted, which is the only thing three copies of one fact ever do — the engine
// answered 0.2.0-alpha while 0.3.0-alpha was being tagged, so the version the service reported
// could not confirm or contradict anything and a tag asserting it was unfalsifiable.
//
// It is the same shape as the 23h/1h TTL written in two places and the "engine has no /health"
// comment left beside a /health route: a value RESTATED where it is used instead of read from where
// it is owned. Everything that names a version now reads this, and version_test.go binds it to the
// git tag on HEAD, so a tag that disagrees with what the service answers fails the suite that gates
// the tag.
//
// Not derived from debug.ReadBuildInfo: for a repository build that reports "(devel)" or a
// VCS-stamped pseudo-version, so the service would answer something no release is called. The
// declared value is the release's name; the test is what makes it true.
const Version = "0.3.1-alpha"
