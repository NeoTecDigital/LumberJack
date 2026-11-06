// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package pngstore

import (
	"fmt"
	engine "github.com/NeoTecDigital/LumberJack/internal"
	"math/big"
	"sort"
	"strings"
	"unicode"
)

func selectRecords(query Query, all []Record, maximum int) ([]Record, error) {
	if query.Family == "" || query.Limit <= 0 || query.Limit > maximum || len(query.Filters) > maximum {
		return nil, fmt.Errorf("explicit bounded account query required")
	}
	out := []Record{}
	for _, record := range all {
		selected, err := matchRecord(query, record)
		if err != nil {
			return nil, err
		}
		if selected {
			out = append(out, record)
		}
	}
	sortRecords(out, query.OrderBy)
	if len(out) > query.Limit {
		out = out[:query.Limit]
	}
	return out, nil
}
func sortRecords(all []Record, fields []string) {
	sort.SliceStable(all, func(i, j int) bool { return recordLess(all[i], all[j], fields) })
}
func recordLess(left, right Record, fields []string) bool {
	for _, key := range fields {
		descending := strings.HasPrefix(key, "-")
		key = strings.TrimPrefix(key, "-")
		a, b := recordValue(left, key), recordValue(right, key)
		if same(a, b) {
			continue
		}
		if descending {
			return compareValues(a, b) > 0
		}
		return compareValues(a, b) < 0
	}
	return left.Key < right.Key
}
func recordValue(record Record, key string) interface{} {
	if key == "id" {
		return record.Key
	}
	return record.Data[key]
}
func matchRecord(query Query, record Record) (bool, error) {
	if record.Family != query.Family || query.Key != "" && record.Key != query.Key {
		return false, nil
	}
	for _, filter := range query.Filters {
		matched, err := matchFilter(record, filter)
		if err != nil || !matched {
			return false, err
		}
	}
	return true, nil
}
func matchFilter(record Record, filter Filter) (bool, error) {
	if filter.Operator == "active_on" {
		if filter.Field != "assigned_date|end_date" {
			return false, fmt.Errorf("exact interval field binding required")
		}
		return activeOn(record, filter.Value), nil
	}
	if filter.Operator == "recoverable_claim" {
		if filter.Field != "state|claim_epoch" {
			return false, fmt.Errorf("exact claim field binding required")
		}
		return recoverableClaim(record, filter.Value), nil
	}
	value := recordValue(record, filter.Field)
	if value == nil && filter.Operator != "is_null" && filter.Operator != "eq" && filter.Operator != "any_contains" {
		return false, nil
	}
	switch filter.Operator {
	case "eq":
		return same(value, filter.Value), nil
	case "is_null":
		return (value == nil) == (filter.Value == nil || filter.Value == true), nil
	case "contains":
		return strings.Contains(strings.ToLower(fmt.Sprint(value)), strings.ToLower(fmt.Sprint(filter.Value))), nil
	case "digits_eq":
		return digits(fmt.Sprint(value)) == digits(fmt.Sprint(filter.Value)) && digits(fmt.Sprint(filter.Value)) != "", nil
	case "in":
		return member(value, filter.Value), nil
	case "any_contains":
		return anyContains(record, filter), nil
	case "gte":
		return compareValues(value, filter.Value) >= 0, nil
	case "lte":
		return compareValues(value, filter.Value) <= 0, nil
	}
	return false, fmt.Errorf("unsupported native filter")
}
func recoverableClaim(record Record, epoch interface{}) bool {
	state := record.Data["state"]
	return state == "pending" || state == "failed" || state == "processing" && !same(record.Data["claim_epoch"], epoch)
}
func compareValues(left, right interface{}) int {
	a, aok := new(big.Rat).SetString(fmt.Sprint(left))
	b, bok := new(big.Rat).SetString(fmt.Sprint(right))
	if aok && bok {
		return a.Cmp(b)
	}
	return strings.Compare(fmt.Sprint(left), fmt.Sprint(right))
}
func member(value, items interface{}) bool {
	list, ok := items.([]interface{})
	if !ok {
		return false
	}
	for _, item := range list {
		if same(value, item) {
			return true
		}
	}
	return false
}
func anyContains(record Record, filter Filter) bool {
	needle := strings.ToLower(fmt.Sprint(filter.Value))
	for _, field := range strings.FieldsFunc(filter.Field, func(char rune) bool { return char == ',' || char == '|' }) {
		value := recordValue(record, field)
		if value != nil && strings.Contains(strings.ToLower(fmt.Sprint(value)), needle) {
			return true
		}
	}
	return false
}
func digits(value string) string {
	return strings.Map(func(char rune) rune {
		if unicode.IsDigit(char) {
			return char
		}
		return -1
	}, value)
}

func (Adapter) Project(requestID string, intent engine.DomainIntent, owned engine.DomainOwnedScope, view engine.DomainView) ([]byte, error) {
	return nil, fmt.Errorf("typed query projection requires retained request")
}

func activeOn(record Record, day interface{}) bool {
	assigned := record.Data["assigned_date"]
	end := record.Data["end_date"]
	return assigned != nil && compareValues(assigned, day) <= 0 && (end == nil || compareValues(end, day) >= 0)
}
