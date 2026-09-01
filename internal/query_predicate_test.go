package internal

import (
	"net/http"
	"testing"
	"time"
)

// The predicate evaluator, exhaustively.
//
// /query and /aggregate share this one implementation, so a hole here is a hole in both — and a
// filter that means something slightly different depending on which route parsed it is a filter
// nobody can trust.

// at is a fixed instant so a table can be read without arithmetic.
func at(day int) time.Time {
	return time.Date(2026, time.March, day, 12, 0, 0, 0, time.UTC)
}

// sample is the candidate every case starts from, so a case says only what it changes.
func sample() candidate {
	return candidate{
		Kind:     selectEvents,
		NodePath: "momentum/backend",
		ID:       "event-1",
		Index:    -1,
		Status:   "ongoing",
		Category: "inspection",
		UserID:   "user-123",
		Text:     []string{"corrosion on the third pipe"},
		Metadata: map[string]interface{}{"site": "north", "floor": float64(3), "ok": true},
		Times: map[string]time.Time{
			timeFieldStart:     at(10),
			timeFieldEnd:       at(12),
			timeFieldTimestamp: at(10),
		},
		Timestamp: at(10),
	}
}

func TestPredicateMatch(t *testing.T) {
	cases := []struct {
		name  string
		where *whereClause
		item  candidate
		want  bool
	}{
		{name: "no clause matches everything", where: nil, item: sample(), want: true},
		{name: "empty clause matches everything", where: &whereClause{}, item: sample(), want: true},

		{name: "status in set", where: &whereClause{Status: []string{"ongoing", "pending"}}, item: sample(), want: true},
		{name: "status out of set", where: &whereClause{Status: []string{"finished"}}, item: sample(), want: false},
		{name: "status ignores case", where: &whereClause{Status: []string{"ONGOING"}}, item: sample(), want: true},

		{name: "category in set", where: &whereClause{Category: []string{"inspection"}}, item: sample(), want: true},
		{name: "category out of set", where: &whereClause{Category: []string{"repair"}}, item: sample(), want: false},

		{name: "user in set", where: &whereClause{UserID: []string{"user-123", "user-9"}}, item: sample(), want: true},
		{name: "user out of set", where: &whereClause{UserID: []string{"user-9"}}, item: sample(), want: false},
		{
			name:  "user id is an identifier and does not ignore case",
			where: &whereClause{UserID: []string{"USER-123"}},
			item:  sample(),
			want:  false,
		},

		{
			name:  "every named dimension must hold",
			where: &whereClause{Status: []string{"ongoing"}, Category: []string{"repair"}},
			item:  sample(),
			want:  false,
		},

		{
			name:  "time inside the range",
			where: &whereClause{Time: &timeClause{Field: timeFieldStart, From: at(9).Format(time.RFC3339), To: at(11).Format(time.RFC3339)}},
			item:  sample(),
			want:  true,
		},
		{
			name:  "time before the range",
			where: &whereClause{Time: &timeClause{Field: timeFieldStart, From: at(11).Format(time.RFC3339)}},
			item:  sample(),
			want:  false,
		},
		{
			name:  "the upper bound is excluded so consecutive ranges tile",
			where: &whereClause{Time: &timeClause{Field: timeFieldStart, To: at(10).Format(time.RFC3339)}},
			item:  sample(),
			want:  false,
		},
		{
			name:  "the lower bound is included",
			where: &whereClause{Time: &timeClause{Field: timeFieldStart, From: at(10).Format(time.RFC3339)}},
			item:  sample(),
			want:  true,
		},
		{
			name:  "an open upper bound leaves the range open",
			where: &whereClause{Time: &timeClause{Field: timeFieldStart, From: at(1).Format(time.RFC3339)}},
			item:  sample(),
			want:  true,
		},
		{
			name:  "the field defaults to timestamp",
			where: &whereClause{Time: &timeClause{From: at(9).Format(time.RFC3339), To: at(11).Format(time.RFC3339)}},
			item:  sample(),
			want:  true,
		},
		{
			name:  "a candidate without the named time is outside every bounded range",
			where: &whereClause{Time: &timeClause{Field: timeFieldEnd, From: at(1).Format(time.RFC3339)}},
			item: func() candidate {
				item := sample()
				delete(item.Times, timeFieldEnd)
				return item
			}(),
			want: false,
		},
		{
			name:  "a candidate without the named time is still matched by an unbounded clause",
			where: &whereClause{Time: &timeClause{Field: timeFieldEnd}},
			item: func() candidate {
				item := sample()
				delete(item.Times, timeFieldEnd)
				return item
			}(),
			want: true,
		},

		{name: "metadata equal", where: &whereClause{Metadata: map[string]string{"site": "north"}}, item: sample(), want: true},
		{name: "metadata unequal", where: &whereClause{Metadata: map[string]string{"site": "south"}}, item: sample(), want: false},
		{name: "metadata key absent", where: &whereClause{Metadata: map[string]string{"depth": "3"}}, item: sample(), want: false},
		{
			name:  "a JSON number compares as the text a caller typed",
			where: &whereClause{Metadata: map[string]string{"floor": "3"}},
			item:  sample(),
			want:  true,
		},
		{
			name:  "a JSON boolean compares as the text a caller typed",
			where: &whereClause{Metadata: map[string]string{"ok": "true"}},
			item:  sample(),
			want:  true,
		},
		{
			name:  "every named metadata key must hold",
			where: &whereClause{Metadata: map[string]string{"site": "north", "floor": "4"}},
			item:  sample(),
			want:  false,
		},

		{name: "text substring", where: &whereClause{Text: "corrosion"}, item: sample(), want: true},
		{name: "text ignores case", where: &whereClause{Text: "CORROSION"}, item: sample(), want: true},
		{name: "text mid-word", where: &whereClause{Text: "rrosi"}, item: sample(), want: true},
		{name: "text absent", where: &whereClause{Text: "fracture"}, item: sample(), want: false},
		{
			name:  "text searches every field the candidate offered",
			where: &whereClause{Text: "third"},
			item:  sample(),
			want:  true,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			compiled, err := compilePredicate(testCase.where)
			if err != nil {
				t.Fatalf("Failed to compile: %v", err)
			}
			if got := compiled.match(testCase.item); got != testCase.want {
				t.Errorf("match: got %v, want %v", got, testCase.want)
			}
		})
	}
}

// A where clause that cannot mean anything is REFUSED, and refused as the caller's mistake.
//
// An unknown field used to be the same as no filter, so a caller that misspelled "start_time" was
// told everything matched rather than that it had asked for nothing.
func TestPredicateRefusesWhatCannotMeanAnything(t *testing.T) {
	cases := []struct {
		name  string
		where *whereClause
	}{
		{name: "unknown time field", where: &whereClause{Time: &timeClause{Field: "strat_time"}}},
		{name: "from is not RFC3339", where: &whereClause{Time: &timeClause{From: "yesterday"}}},
		{name: "to is not RFC3339", where: &whereClause{Time: &timeClause{To: "2026-03-10"}}},
		{
			name: "the range ends before it begins",
			where: &whereClause{Time: &timeClause{
				From: at(12).Format(time.RFC3339),
				To:   at(10).Format(time.RFC3339),
			}},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := compilePredicate(testCase.where)
			if err == nil {
				t.Fatal("Compiled a where clause that cannot mean anything")
			}

			var carried *apiError
			if !asAPIError(err, &carried) {
				t.Fatalf("Refusal carried no status: %v", err)
			}
			if carried.status != http.StatusBadRequest {
				t.Errorf("Refusal answered %d, want %d", carried.status, http.StatusBadRequest)
			}
		})
	}
}

// A sort that cannot mean anything is refused the same way.
func TestOrderingRefusesWhatCannotMeanAnything(t *testing.T) {
	cases := []struct {
		name  string
		sort  []sortField
		valid bool
	}{
		{name: "default", sort: nil, valid: true},
		{name: "known field", sort: []sortField{{Field: timeFieldStart, Dir: sortDescending}}, valid: true},
		{name: "direction defaults to ascending", sort: []sortField{{Field: "name"}}, valid: true},
		{name: "unknown field", sort: []sortField{{Field: "titel"}}, valid: false},
		{name: "unknown direction", sort: []sortField{{Field: "name", Dir: "sideways"}}, valid: false},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := compileOrdering(testCase.sort)
			if testCase.valid && err != nil {
				t.Fatalf("Refused a sort that means something: %v", err)
			}
			if !testCase.valid && err == nil {
				t.Fatal("Compiled a sort that cannot mean anything")
			}
		})
	}
}
