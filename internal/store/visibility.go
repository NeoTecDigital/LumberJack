// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package store

// The owner grants latest indexed reads by kind. A grant conveys no writes,
// no inherited data access through an edge and no authority in other stores.
func (d *draft) readGrant(e framedEdit) error {
	if !token(e.Principal) || !token(e.Kind) || e.Principal == d.f.Issuer {
		return ErrInvalid
	}
	if _, err := d.expect(Root, false); err != nil {
		return err
	}
	principal := e.Principal
	m := d.s.grants[principal]
	if m == nil {
		m = map[string]bool{}
	}
	add := e.Op == "grant_read"
	if m[e.Kind] == add {
		return ErrConflict
	}
	set := func(on bool) {
		if on {
			m[e.Kind] = true
			d.s.grants[principal] = m
		} else {
			delete(m, e.Kind)
			if len(m) == 0 {
				delete(d.s.grants, principal)
			}
		}
	}
	gen := d.s.access[principal]
	d.change(func() { set(add); d.s.access[principal] = gen + 1 }, func() {
		set(!add)
		if gen == 0 {
			delete(d.s.access, principal)
		} else {
			d.s.access[principal] = gen
		}
	})
	return nil
}
func (s *Store) visible(issuer, kind string) bool {
	return issuer == s.m.Owner || s.s.grants[issuer][kind]
}
