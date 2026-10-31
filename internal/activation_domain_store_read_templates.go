// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

// Protected per-account templates are changed only within the paired enrollment ACL delta.
func updateEnrollmentReadTemplates(entry *domainEntry, acl *domainACL, target string) {
	for kind, template := range acl.CreateACLs {
		updateEnrollmentTemplateTarget(entry, &template, kind, target)
		acl.CreateACLs[kind] = template
	}
}
func updateEnrollmentTemplateTarget(entry *domainEntry, template *domainACL, kind, target string) {
	if len(entry.owned.Layout.Profiles["read"][kind]) == 0 {
		return
	}
	if entry.enrollment.actor.Request.Operation == EnrollmentReadRevoke {
		revokeEnrollmentRead(template, target)
		return
	}
	if template.Principals[target] == nil {
		template.Principals[target] = map[string]domainGrant{}
	}
	fields := entry.owned.Layout.Profiles["read"][kind]
	revision := *entry.enrollment.actor.PrincipalReference.TargetGrantRevision
	template.Principals[target]["read"] = domainGrant{Fields: append([]string(nil), fields...), Reference: domainContains(fields, "reference"), TargetGrantRevision: revision}
	grantPNGEnrollmentRead(entry, template, kind, target)
}
func currentEnrollmentTemplatePins(entry *domainEntry, acl domainACL, target *DomainPrincipalReference) bool {
	for kind, template := range acl.CreateACLs {
		if len(entry.owned.Layout.Profiles["read"][kind]) == 0 {
			continue
		}
		if !currentEnrollmentReadPins(entry, template, kind, target) {
			return false
		}
	}
	return true
}
