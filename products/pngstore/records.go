// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package pngstore

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	engine "github.com/NeoTecDigital/LumberJack/internal"
	"sort"
	"strings"
)

func field(owned engine.DomainOwnedScope, name string) string { return owned.Layout.Fields[name] }
func records(owned engine.DomainOwnedScope, view engine.DomainView) ([]Record, error) {
	if err := validateAssociateCarrier(owned, view.ACLMetadataKey); err != nil {
		return nil, err
	}
	out := []Record{}
	seen := map[string]bool{}
	for _, native := range view.Records {
		included, err := storeRecordKind(native, owned)
		if err != nil {
			return nil, err
		}
		if !included {
			continue
		}
		record, err := recordOf(native, owned)
		if err != nil {
			return nil, err
		}
		if err = validateAssociateRecord(record, native, owned, view); err != nil {
			return nil, err
		}
		key := record.Family + "\x00" + record.Key
		if seen[key] {
			return nil, fmt.Errorf("canonical/native alias ambiguity")
		}
		seen[key] = true
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Family+"\x00"+out[i].Key < out[j].Family+"\x00"+out[j].Key })
	return out, nil
}
func recordOf(native engine.DomainRecord, owned engine.DomainOwnedScope) (Record, error) {
	record := Record{NativeID: native.ID}
	record.Family, _ = native.Metadata[field(owned, "pngFamily")].(string)
	record.Key, _ = native.Metadata[field(owned, "pngKey")].(string)
	record.Version, _ = native.Metadata[field(owned, "pngVersion")].(string)
	record.Data, _ = native.Metadata[field(owned, "pngData")].(map[string]interface{})
	if record.Family == "" || record.Key == "" || record.Version == "" || record.Data == nil {
		return record, fmt.Errorf("invalid native retained record")
	}
	if !validIdentity(record.Family, owned.Bounds.MaxIdentifierBytes) || !validIdentity(record.Key, owned.Bounds.MaxIdentifierBytes) {
		return record, fmt.Errorf("invalid canonical native record identity")
	}
	if record.Data["account_id"] != owned.Binding.AccountID {
		return record, fmt.Errorf("native account binding mismatch")
	}
	return record, nil
}
func validIdentity(value string, maximum int) bool {
	return maximum > 0 && len(value) <= maximum && strings.TrimSpace(value) != "" && !strings.ContainsRune(value, 0)
}
func find(all []Record, family, key string) (Record, bool) {
	for _, record := range all {
		if record.Family == family && record.Key == key {
			return record, true
		}
	}
	return Record{}, false
}
func canonical(value interface{}) []byte { raw, _ := engine.CanonicalDomainJSON(value); return raw }
func hash(value interface{}) string {
	sum := sha256.Sum256(canonical(value))
	return hex.EncodeToString(sum[:])
}
func same(left, right interface{}) bool { return string(canonical(left)) == string(canonical(right)) }

func (Adapter) Command(input engine.DomainInput) (engine.DomainCommand, error) {
	request, err := decode(input)
	return engine.DomainCommand{CommandID: request.CommandID, ExpectedRevision: request.ExpectedRevision, Operation: request.Operation}, err
}
func (Adapter) PublicFields(kind string, keys []string, owned engine.DomainOwnedScope) ([]string, error) {
	associate := owned.Layout.AssociateCarrier != nil && kind == owned.Layout.Kinds["associate"]
	if kind != owned.Layout.Kinds["png_record"] && kind != owned.Layout.Kinds["root"] && !associate {
		return nil, fmt.Errorf("unknown native store resource kind")
	}
	out := []string{}
	for _, key := range keys {
		name := semanticField(owned, key)
		if name == "" && associate {
			name = associatePublicField(owned, key)
		}
		if name == "" {
			return nil, fmt.Errorf("store attempted private metadata change")
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}
func semanticField(owned engine.DomainOwnedScope, key string) string {
	if key == "children" {
		return key
	}
	for _, name := range []string{"pngKey", "pngFamily", "pngData", "pngVersion"} {
		if field(owned, name) == key {
			return name
		}
	}
	return ""
}
