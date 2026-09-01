package internal

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/vaziolabs/lumberjack/internal/core"
)

// /aggregate against HAND-COMPUTED fixtures.
//
// The point of a report is that its numbers are right. A fixture whose expected values were
// produced by the code under test proves only that the code is consistent with itself, so every
// expectation here is written out by hand from the events the fixture plants.

// plantEvent puts a finished event on a node with times the test chose, so a duration is exact
// rather than however long the test took to run.
func plantEvent(t *testing.T, server *Server, path, eventID, category, userID string, start, end time.Time) {
	t.Helper()

	node, err := server.getNodeFromPath(path)
	if err != nil {
		t.Fatalf("Failed to find %s: %v", path, err)
	}

	startAt, endAt := start, end
	node.Events[eventID] = core.Event{
		StartTime: &startAt,
		EndTime:   &endAt,
		Status:    core.EventFinished,
		Category:  category,
		CreatedBy: userID,
		CreatedAt: startAt,
		Entries:   []core.Entry{{Content: "note", UserID: userID, Timestamp: startAt}},
	}
}

// aggregateOf runs POST /aggregate and decodes the answer.
func aggregateOf(t *testing.T, server *Server, userID string, body map[string]interface{}) aggregateResponse {
	t.Helper()

	recorder := post(t, server.handleAggregate, userID, body)
	if recorder.Code != http.StatusOK {
		t.Fatalf("POST /aggregate: got %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	var decoded aggregateResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("POST /aggregate did not answer JSON: %v", err)
	}
	return decoded
}

// bucketFor finds the bucket with a given key, so an assertion does not depend on bucket order.
func bucketFor(t *testing.T, answer aggregateResponse, key map[string]string) bucketView {
	t.Helper()

	for _, bucket := range answer.Buckets {
		matches := len(bucket.Key) == len(key)
		for name, want := range key {
			if bucket.Key[name] != want {
				matches = false
			}
		}
		if matches {
			return bucket
		}
	}
	t.Fatalf("No bucket for %v in %+v", key, answer.Buckets)
	return bucketView{}
}

// aggregateFixture plants five finished events across two categories and three days.
//
//	2026-03-02 Mon  inspection  600s   inspection  1200s
//	2026-03-03 Tue  repair       300s
//	2026-03-09 Mon  inspection  1800s
//	2026-04-01 Wed  repair       900s
func aggregateFixture(t *testing.T, server *Server, userID string) string {
	t.Helper()

	path := leafFor(t, server, userID, "reports/site")
	day := func(month time.Month, day, hour int) time.Time {
		return time.Date(2026, month, day, hour, 0, 0, 0, time.UTC)
	}

	plantEvent(t, server, path, "a", "inspection", userID, day(time.March, 2, 9), day(time.March, 2, 9).Add(600*time.Second))
	plantEvent(t, server, path, "b", "inspection", userID, day(time.March, 2, 14), day(time.March, 2, 14).Add(1200*time.Second))
	plantEvent(t, server, path, "c", "repair", userID, day(time.March, 3, 9), day(time.March, 3, 9).Add(300*time.Second))
	plantEvent(t, server, path, "d", "inspection", userID, day(time.March, 9, 9), day(time.March, 9, 9).Add(1800*time.Second))
	plantEvent(t, server, path, "e", "repair", userID, day(time.April, 1, 9), day(time.April, 1, 9).Add(900*time.Second))
	return path
}

func TestAggregateGroupsAndMetricsMatchHandComputedFixtures(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	aggregateFixture(t, server, userID)

	cases := []struct {
		name        string
		group       []string
		key         map[string]string
		count       int
		durationSum float64
		durationAvg float64
	}{
		{
			name: "by category, inspection", group: []string{"category"},
			key: map[string]string{"category": "inspection"},
			// 600 + 1200 + 1800
			count: 3, durationSum: 3600, durationAvg: 1200,
		},
		{
			name: "by category, repair", group: []string{"category"},
			key: map[string]string{"category": "repair"},
			// 300 + 900
			count: 2, durationSum: 1200, durationAvg: 600,
		},
		{
			name: "by day, the day with two events", group: []string{groupDay},
			key: map[string]string{groupDay: "2026-03-02"},
			// 600 + 1200
			count: 2, durationSum: 1800, durationAvg: 900,
		},
		{
			name: "by day, a day with one", group: []string{groupDay},
			key:   map[string]string{groupDay: "2026-03-03"},
			count: 1, durationSum: 300, durationAvg: 300,
		},
		{
			// The week beginning Monday 2026-03-02 holds Monday's two and Tuesday's one.
			name: "by week", group: []string{groupWeek},
			key: map[string]string{groupWeek: "2026-03-02"},
			// 600 + 1200 + 300
			count: 3, durationSum: 2100, durationAvg: 700,
		},
		{
			name: "by week, the following Monday alone", group: []string{groupWeek},
			key:   map[string]string{groupWeek: "2026-03-09"},
			count: 1, durationSum: 1800, durationAvg: 1800,
		},
		{
			name: "by month, March", group: []string{groupMonth},
			key: map[string]string{groupMonth: "2026-03"},
			// 600 + 1200 + 300 + 1800
			count: 4, durationSum: 3900, durationAvg: 975,
		},
		{
			name: "by month, April", group: []string{groupMonth},
			key:   map[string]string{groupMonth: "2026-04"},
			count: 1, durationSum: 900, durationAvg: 900,
		},
		{
			name: "by category and day together", group: []string{"category", groupDay},
			key:   map[string]string{"category": "inspection", groupDay: "2026-03-02"},
			count: 2, durationSum: 1800, durationAvg: 900,
		},
		{
			name: "no grouping is the whole selection", group: nil,
			key: map[string]string{},
			// 600 + 1200 + 300 + 1800 + 900
			count: 5, durationSum: 4800, durationAvg: 960,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			answer := aggregateOf(t, server, userID, map[string]interface{}{
				"select": "events",
				"scope":  "reports",
				"group":  testCase.group,
				"metric": []string{metricCount, metricDurationSum, metricDurationAvg},
			})

			bucket := bucketFor(t, answer, testCase.key)
			if bucket.Count != testCase.count {
				t.Errorf("count: got %d, want %d", bucket.Count, testCase.count)
			}
			if bucket.DurationSum == nil || *bucket.DurationSum != testCase.durationSum {
				t.Errorf("duration_sum: got %v, want %v", bucket.DurationSum, testCase.durationSum)
			}
			if bucket.DurationAverage == nil || *bucket.DurationAverage != testCase.durationAvg {
				t.Errorf("duration_avg: got %v, want %v", bucket.DurationAverage, testCase.durationAvg)
			}
		})
	}
}

// /aggregate filters with the SAME grammar /query does, because it is the same evaluator.
func TestAggregateSharesThePredicateWithQuery(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	aggregateFixture(t, server, userID)

	where := map[string]interface{}{
		"category": []string{"inspection"},
		"time": map[string]string{
			"field": "start_time",
			"from":  "2026-03-01T00:00:00Z",
			"to":    "2026-03-05T00:00:00Z",
		},
	}

	counted := aggregateOf(t, server, userID, map[string]interface{}{
		"select": "events", "scope": "reports", "where": where,
	})
	if len(counted.Buckets) != 1 || counted.Buckets[0].Count != 2 {
		t.Fatalf("Aggregate counted %+v, want one bucket of 2", counted.Buckets)
	}

	listed := queryOf(t, server, userID, map[string]interface{}{
		"select": "events", "scope": "reports", "where": where,
	})
	if listed.Total != counted.Buckets[0].Count {
		t.Errorf("The same where clause answered %d from /query and %d from /aggregate",
			listed.Total, counted.Buckets[0].Count)
	}
}

// An ONGOING event counts and contributes no duration.
//
// Summing "now minus start" would make the same report answer differently every time it is run,
// and averaging over things that contributed nothing reports an average of nothing.
func TestAggregateExcludesUnfinishedWorkFromDurations(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := aggregateFixture(t, server, userID)

	if code := post(t, server.handleStartEvent, userID, map[string]interface{}{
		"path": path, "event_id": "still-running", "metadata": map[string]interface{}{"category": "inspection"},
	}).Code; code != http.StatusOK {
		t.Fatalf("Start event: got %d", code)
	}

	answer := aggregateOf(t, server, userID, map[string]interface{}{
		"select": "events", "scope": "reports", "group": []string{"category"},
		"metric": []string{metricCount, metricDurationSum, metricDurationAvg},
	})

	bucket := bucketFor(t, answer, map[string]string{"category": "inspection"})
	if bucket.Count != 4 {
		t.Errorf("count: got %d, want 4 (the ongoing event counts)", bucket.Count)
	}
	if *bucket.DurationSum != 3600 {
		t.Errorf("duration_sum: got %v, want 3600 (the ongoing event adds nothing)", *bucket.DurationSum)
	}
	if *bucket.DurationAverage != 1200 {
		t.Errorf("duration_avg: got %v, want 1200 (averaged over the three that finished)", *bucket.DurationAverage)
	}
}

// A group or metric that cannot mean anything is refused as the caller's mistake.
func TestAggregateRefusesWhatCannotMeanAnything(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	aggregateFixture(t, server, userID)

	cases := []struct {
		name    string
		request map[string]interface{}
	}{
		{name: "unknown select", request: map[string]interface{}{"select": "nodes"}},
		{name: "unknown group", request: map[string]interface{}{"select": "events", "group": []string{"quarter"}}},
		{name: "unknown metric", request: map[string]interface{}{"select": "events", "metric": []string{"median"}}},
		{
			name: "unknown time field",
			request: map[string]interface{}{
				"select": "events",
				"where":  map[string]interface{}{"time": map[string]string{"field": "strat_time"}},
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if code := post(t, server.handleAggregate, userID, testCase.request).Code; code != http.StatusBadRequest {
				t.Errorf("got %d, want %d", code, http.StatusBadRequest)
			}
		})
	}
}

// Time spans are aggregated from the paired start/stop entries time tracking writes.
func TestAggregateOverTimeSpans(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "tracked/work")

	node, err := server.getNodeFromPath(path)
	if err != nil {
		t.Fatalf("Failed to find the node: %v", err)
	}
	base := time.Date(2026, time.March, 2, 9, 0, 0, 0, time.UTC)
	node.Entries = []core.Entry{
		{Content: core.TimeEntryStart, UserID: userID, Timestamp: base},
		{Content: core.TimeEntryStop, UserID: userID, Timestamp: base.Add(1800 * time.Second)},
		{Content: core.TimeEntryStart, UserID: userID, Timestamp: base.Add(2 * time.Hour)},
		{Content: core.TimeEntryStop, UserID: userID, Timestamp: base.Add(2*time.Hour + 600*time.Second)},
		// An unmatched start: a span still running has no duration to report.
		{Content: core.TimeEntryStart, UserID: userID, Timestamp: base.Add(5 * time.Hour)},
	}

	answer := aggregateOf(t, server, userID, map[string]interface{}{
		"select": "time", "scope": "tracked", "group": []string{groupDay},
		"metric": []string{metricCount, metricDurationSum},
	})

	bucket := bucketFor(t, answer, map[string]string{groupDay: "2026-03-02"})
	if bucket.Count != 2 {
		t.Errorf("count: got %d, want 2 (the unfinished span is not a span)", bucket.Count)
	}
	if *bucket.DurationSum != 2400 {
		t.Errorf("duration_sum: got %v, want 2400", *bucket.DurationSum)
	}
}

// A week is named by its Monday, whatever day of the week the instant falls on.
func TestWeekBucketsAreNamedByTheirMonday(t *testing.T) {
	cases := []struct {
		day  string
		want string
	}{
		{day: "2026-03-01T12:00:00Z", want: "2026-02-23"}, // a Sunday belongs to the week before
		{day: "2026-03-02T00:00:00Z", want: "2026-03-02"}, // the Monday itself
		{day: "2026-03-05T23:59:59Z", want: "2026-03-02"},
		{day: "2026-03-08T12:00:00Z", want: "2026-03-02"}, // the Sunday that closes it
		{day: "2026-03-09T00:00:00Z", want: "2026-03-09"},
	}

	for _, testCase := range cases {
		t.Run(testCase.day, func(t *testing.T) {
			at, err := time.Parse(time.RFC3339, testCase.day)
			if err != nil {
				t.Fatalf("Bad fixture: %v", err)
			}
			if got := timeBucket(at, groupWeek); got != testCase.want {
				t.Errorf("got %s, want %s", got, testCase.want)
			}
		})
	}
}

// A bucket is the same bucket wherever it is asked from: the boundary is UTC, not the server's zone.
func TestTimeBucketsAreUTC(t *testing.T) {
	eastern := time.FixedZone("UTC-5", -5*60*60)
	lateEvening := time.Date(2026, time.March, 2, 21, 30, 0, 0, eastern) // 2026-03-03T02:30Z

	for unit, want := range map[string]string{
		groupDay:   "2026-03-03",
		groupWeek:  "2026-03-02",
		groupMonth: "2026-03",
	} {
		if got := timeBucket(lateEvening, unit); got != want {
			t.Errorf("%s: got %s, want %s", unit, got, want)
		}
	}
}
