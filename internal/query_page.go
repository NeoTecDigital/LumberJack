package internal

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Ordering and paging.
//
// The cursor is a KEYSET cursor, not an offset. An offset is a count of things that came before,
// and the number of things that came before changes every time anything is written: page two of an
// offset-paged feed silently repeats or skips whatever arrived while page one was being read. A
// keyset cursor carries the POSITION IN THE ORDER of the last row handed out, so the next page is
// "everything after this point" — an insert before that point does not move it, and an insert after
// it simply turns up in a later page.
//
// For that to hold, the order has to be TOTAL. Two candidates that compare equal on every field the
// caller sorted by would otherwise straddle the cursor and one of them would be lost, so every key
// ends with a tiebreak that no two candidates share.

// Paging limits. A limit is bounded because the caller cannot be trusted to bound it, and a page of
// the whole forest is the thing this layer exists to stop.
const (
	defaultPageLimit = 100
	maxPageLimit     = 1000
)

// The directions a sort can take.
const (
	sortAscending  = "asc"
	sortDescending = "desc"
)

// sortableFields are the fields a sort may name, mapped to how a candidate answers for them.
//
// A CLOSED set: an unnamed field used to sort by nothing, so a caller that misspelled one was
// silently handed an arbitrary order it would then page through incorrectly.
var sortableFields = map[string]func(candidate) string{
	timeFieldStart:      func(item candidate) string { return orderTime(item.timeOf(timeFieldStart)) },
	timeFieldEnd:        func(item candidate) string { return orderTime(item.timeOf(timeFieldEnd)) },
	timeFieldTimestamp:  func(item candidate) string { return orderTime(item.timeOf(timeFieldTimestamp)) },
	timeFieldCreatedAt:  func(item candidate) string { return orderTime(item.timeOf(timeFieldCreatedAt)) },
	timeFieldModifiedAt: func(item candidate) string { return orderTime(item.timeOf(timeFieldModifiedAt)) },
	"name":              func(item candidate) string { return item.NodePath },
	"path":              func(item candidate) string { return item.NodePath },
	"status":            func(item candidate) string { return item.Status },
	"category":          func(item candidate) string { return item.Category },
	"user_id":           func(item candidate) string { return item.UserID },
	"id":                func(item candidate) string { return item.ID },
	"duration":          func(item candidate) string { return orderDuration(item) },
}

// ordering is a compiled sort: the fields, their directions, and nothing else.
type ordering struct {
	fields []sortField
}

// compileOrdering validates a sort and supplies the default.
//
// The default is newest first. A feed, a log and a report all mean "what happened most recently"
// when they do not say.
func compileOrdering(fields []sortField) (*ordering, error) {
	if len(fields) == 0 {
		return &ordering{fields: []sortField{{Field: timeFieldTimestamp, Dir: sortDescending}}}, nil
	}

	compiled := &ordering{fields: make([]sortField, 0, len(fields))}
	for _, field := range fields {
		if _, known := sortableFields[field.Field]; !known {
			return nil, apiErrorf(http.StatusBadRequest, "cannot sort by %q", field.Field)
		}

		direction := strings.ToLower(strings.TrimSpace(field.Dir))
		switch direction {
		case "":
			direction = sortAscending
		case sortAscending, sortDescending:
		default:
			return nil, apiErrorf(http.StatusBadRequest,
				"sort direction must be %q or %q, not %q", sortAscending, sortDescending, field.Dir)
		}
		compiled.fields = append(compiled.fields, sortField{Field: field.Field, Dir: direction})
	}
	return compiled, nil
}

// key is a candidate's position in this order: one string per sort field, then the tiebreak.
func (o *ordering) key(item candidate) []string {
	key := make([]string, 0, len(o.fields)+1)
	for _, field := range o.fields {
		key = append(key, sortableFields[field.Field](item))
	}
	return append(key, tiebreak(item))
}

// before reports whether one key sorts ahead of another under this order.
func (o *ordering) before(left, right []string) bool {
	return o.compare(left, right) < 0
}

// compare is a three-way comparison of two keys, direction applied per field and the tiebreak
// always ascending.
func (o *ordering) compare(left, right []string) int {
	for index := range left {
		if index >= len(right) {
			return 1
		}
		if left[index] == right[index] {
			continue
		}

		ahead := -1
		if left[index] > right[index] {
			ahead = 1
		}
		if index < len(o.fields) && o.fields[index].Dir == sortDescending {
			ahead = -ahead
		}
		return ahead
	}
	if len(right) > len(left) {
		return -1
	}
	return 0
}

// tiebreak is what makes the order TOTAL. No two candidates share it: a node appears once per path,
// an event once per id per node, an entry once per index per event.
func tiebreak(item candidate) string {
	return fmt.Sprintf("%s\x1f%s\x1f%s\x1f%012d", item.NodePath, item.Kind, item.ID, item.Index+1)
}

// orderTime renders a time so that comparing the text compares the instants.
//
// FIXED WIDTH and UTC. time.RFC3339Nano trims trailing zeros from the fraction, so
// "…:05.1Z" and "…:05.05Z" compare in the wrong order as text; and two equal instants written at
// different offsets are different strings. The zero time renders empty and therefore sorts first,
// which is the right place for "this candidate does not have that time".
func orderTime(at time.Time) string {
	if at.IsZero() {
		return ""
	}
	return at.UTC().Format("2006-01-02T15:04:05.000000000Z")
}

// orderDuration renders a duration for ordering. A candidate with no duration sorts first, and the
// width is fixed for the same reason a time's is.
func orderDuration(item candidate) string {
	if !item.HasDuration {
		return ""
	}
	return fmt.Sprintf("1%019d", item.Duration.Milliseconds())
}

// cursor is the position of the last row a page handed out.
//
// It carries the SORT it was produced under. A cursor read back under a different order is
// meaningless — the position it names is a position in an order that no longer exists — and
// answering with a plausible wrong page is worse than refusing.
type cursor struct {
	Sort string   `json:"s"`
	Key  []string `json:"k"`
}

// encodeCursor renders a position opaquely. It is base64 of JSON: a client that decodes it and
// depends on the shape has taken a dependency this layer does not offer, and an opaque token says
// so at the point of contact.
func encodeCursor(order *ordering, item candidate) string {
	encoded, err := json.Marshal(cursor{Sort: order.signature(), Key: order.key(item)})
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

// decodeCursor reads a position back, and refuses one that does not belong to this query.
func decodeCursor(order *ordering, encoded string) ([]string, error) {
	if encoded == "" {
		return nil, nil
	}

	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, apiErrorf(http.StatusBadRequest, "malformed cursor")
	}

	var position cursor
	if err := json.Unmarshal(raw, &position); err != nil {
		return nil, apiErrorf(http.StatusBadRequest, "malformed cursor")
	}
	if position.Sort != order.signature() {
		return nil, apiErrorf(http.StatusBadRequest, "cursor belongs to a different sort order")
	}
	if len(position.Key) != len(order.fields)+1 {
		return nil, apiErrorf(http.StatusBadRequest, "malformed cursor")
	}
	return position.Key, nil
}

// signature identifies the order a cursor was produced under.
func (o *ordering) signature() string {
	parts := make([]string, 0, len(o.fields))
	for _, field := range o.fields {
		parts = append(parts, field.Field+":"+field.Dir)
	}
	return strings.Join(parts, ",")
}

// paginate sorts the matches and returns the page after the cursor.
//
// total is the number of MATCHES, not the size of the page: a client needs to know how much there
// is in order to say so, and it cannot learn that from a page.
func paginate(matches []candidate, order *ordering, page *pageRequest) ([]candidate, string, int, error) {
	limit := defaultPageLimit
	position := ""
	if page != nil {
		if page.Limit > 0 {
			limit = page.Limit
		}
		if page.Limit > maxPageLimit {
			return nil, "", 0, apiErrorf(http.StatusBadRequest, "page limit above the maximum of %d", maxPageLimit)
		}
		if page.Limit < 0 {
			return nil, "", 0, apiErrorf(http.StatusBadRequest, "page limit cannot be negative")
		}
		position = page.Cursor
	}

	after, err := decodeCursor(order, position)
	if err != nil {
		return nil, "", 0, err
	}

	// The key is computed ONCE per candidate. Computing it inside the comparison would format
	// every timestamp of every candidate log(n) times over.
	ranked := make([]ranking, len(matches))
	for index, item := range matches {
		ranked[index] = ranking{key: order.key(item), item: item}
	}
	sort.Slice(ranked, func(a, b int) bool {
		return order.before(ranked[a].key, ranked[b].key)
	})

	total := len(ranked)
	start := 0
	if after != nil {
		// Everything STRICTLY after the cursor. A binary search over an order the slice is already
		// in, so a page is found without walking the pages before it.
		start = sort.Search(total, func(index int) bool {
			return order.compare(ranked[index].key, after) > 0
		})
	}

	end := start + limit
	if end > total {
		end = total
	}

	pageOf := make([]candidate, 0, end-start)
	for _, entry := range ranked[start:end] {
		pageOf = append(pageOf, entry.item)
	}

	next := ""
	if end < total && len(pageOf) > 0 {
		next = encodeCursor(order, pageOf[len(pageOf)-1])
	}
	return pageOf, next, total, nil
}

// ranking is a candidate beside its position in the order, so the position is computed once.
type ranking struct {
	key  []string
	item candidate
}
