package internal

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// The predicate evaluator. ONE implementation, two entry points: /query and /aggregate compile the
// same whereClause with compilePredicate and ask the same match.
//
// A where clause is COMPILED before it is used, not interpreted per candidate. Parsing "from" once
// instead of once per event is the difference between a scan and a scan times a parse; and a bad
// time is then a 400 answered before any work, rather than a filter that silently matched nothing.

// predicate is a compiled whereClause.
//
// An empty field matches everything. That is what makes the grammar composable: a caller sends the
// dimensions it cares about and leaves out the rest, instead of having to name a wildcard.
type predicate struct {
	statuses   map[string]bool
	categories map[string]bool
	userIDs    map[string]bool
	timeField  string
	from       time.Time
	to         time.Time
	hasFrom    bool
	hasTo      bool
	metadata   map[string]string
	text       string
}

// timeFieldsAllowed are the fields `where.time` and `sort` may name.
//
// A CLOSED set, checked: an unknown field used to be the same as no filter, so a caller that
// misspelled "start_time" was told everything matched rather than that it had asked for nothing.
var timeFieldsAllowed = map[string]bool{
	timeFieldStart:      true,
	timeFieldEnd:        true,
	timeFieldTimestamp:  true,
	timeFieldCreatedAt:  true,
	timeFieldModifiedAt: true,
}

// compilePredicate turns a where clause into something that can be asked about a candidate.
func compilePredicate(where *whereClause) (*predicate, error) {
	compiled := &predicate{timeField: timeFieldTimestamp}
	if where == nil {
		return compiled, nil
	}

	compiled.statuses = setOfLower(where.Status)
	compiled.categories = setOfLower(where.Category)
	compiled.userIDs = setOf(where.UserID)
	compiled.metadata = where.Metadata
	compiled.text = strings.ToLower(strings.TrimSpace(where.Text))

	if where.Time == nil {
		return compiled, nil
	}

	if where.Time.Field != "" {
		if !timeFieldsAllowed[where.Time.Field] {
			return nil, apiErrorf(http.StatusBadRequest, "unknown time field %q", where.Time.Field)
		}
		compiled.timeField = where.Time.Field
	}

	from, hasFrom, err := parseBound("from", where.Time.From)
	if err != nil {
		return nil, err
	}
	to, hasTo, err := parseBound("to", where.Time.To)
	if err != nil {
		return nil, err
	}

	if hasFrom && hasTo && to.Before(from) {
		return nil, apiErrorf(http.StatusBadRequest, "time range ends before it begins")
	}

	compiled.from, compiled.hasFrom = from, hasFrom
	compiled.to, compiled.hasTo = to, hasTo
	return compiled, nil
}

// parseBound reads one end of a time range. An empty bound is an open end, not an epoch.
func parseBound(name, value string) (time.Time, bool, error) {
	if strings.TrimSpace(value) == "" {
		return time.Time{}, false, nil
	}

	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, false, apiErrorf(http.StatusBadRequest,
			"time %s must be RFC3339: %v", name, err)
	}
	return parsed, true, nil
}

// match reports whether a candidate satisfies every dimension the caller named.
func (p *predicate) match(item candidate) bool {
	if len(p.statuses) > 0 && !p.statuses[strings.ToLower(item.Status)] {
		return false
	}
	if len(p.categories) > 0 && !p.categories[strings.ToLower(item.Category)] {
		return false
	}
	if len(p.userIDs) > 0 && !p.userIDs[item.UserID] {
		return false
	}
	if !p.matchTime(item) {
		return false
	}
	if !p.matchMetadata(item) {
		return false
	}
	return p.matchText(item)
}

// matchTime applies the half-open range [from, to).
//
// A candidate that does not carry the named field does NOT match a bounded range. An event with no
// end time has not ended before any date, and reporting it inside a range would put unfinished work
// in a report of finished work.
func (p *predicate) matchTime(item candidate) bool {
	if !p.hasFrom && !p.hasTo {
		return true
	}

	at := item.timeOf(p.timeField)
	if at.IsZero() {
		return false
	}
	if p.hasFrom && at.Before(p.from) {
		return false
	}
	// Half-open: the upper bound is excluded, so consecutive ranges tile without double-counting
	// whatever lands exactly on the boundary.
	return !p.hasTo || at.Before(p.to)
}

// matchMetadata requires every named key to be present and equal.
//
// The comparison is on the value's TEXT, because a metadata map comes off JSON: 3 arrives as
// float64 and would never equal the "3" a caller can put in a query string.
func (p *predicate) matchMetadata(item candidate) bool {
	for key, want := range p.metadata {
		value, exists := item.Metadata[key]
		if !exists || metadataText(value) != want {
			return false
		}
	}
	return true
}

// matchText is a case-insensitive substring search over whatever the candidate offered as its text.
func (p *predicate) matchText(item candidate) bool {
	if p.text == "" {
		return true
	}

	for _, field := range item.Text {
		if strings.Contains(strings.ToLower(field), p.text) {
			return true
		}
	}
	return false
}

// metadataText renders a metadata value for comparison. A string is itself; anything else is
// rendered the way Go's default formatting does, which round-trips the JSON scalars.
func metadataText(value interface{}) string {
	switch typed := value.(type) {
	case string:
		return typed
	case nil:
		return ""
	case float64:
		// %v on a float64 prints 3 as "3" and 3.5 as "3.5", which is what a caller typed.
		return strings.TrimSuffix(fmt.Sprintf("%v", typed), ".0")
	default:
		return fmt.Sprintf("%v", typed)
	}
}

// setOf builds a membership set. An empty list stays nil, which means "no constraint".
func setOf(values []string) map[string]bool {
	if len(values) == 0 {
		return nil
	}

	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	return set
}

// setOfLower is setOf for the fields whose values are names rather than identifiers: a status is
// "ongoing" however the caller capitalised it, but a user id is not.
func setOfLower(values []string) map[string]bool {
	if len(values) == 0 {
		return nil
	}

	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[strings.ToLower(value)] = true
	}
	return set
}
