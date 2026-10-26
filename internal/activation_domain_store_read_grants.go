// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

// PNG read never aliases the legacy graph read or grants mutation authority.
func grantPNGEnrollmentRead(entry *domainEntry, acl *domainACL, kind, target string) {
	fields := entry.owned.Layout.Profiles["png.store.read"][kind]
	if len(fields) == 0 {
		return
	}
	revision := *entry.enrollment.actor.PrincipalReference.TargetGrantRevision
	acl.Principals[target]["png.store.read"] = domainGrant{Fields: append([]string(nil), fields...), Reference: domainContains(fields, "reference"), TargetGrantRevision: revision}
}
func currentEnrollmentReadPins(entry *domainEntry, acl domainACL, kind string, target *DomainPrincipalReference) bool {
	if acl.Principals[target.PrincipalID]["read"].TargetGrantRevision != *target.TargetGrantRevision {
		return false
	}
	fields := entry.owned.Layout.Profiles["png.store.read"][kind]
	return len(fields) == 0 || acl.Principals[target.PrincipalID]["png.store.read"].TargetGrantRevision == *target.TargetGrantRevision
}
