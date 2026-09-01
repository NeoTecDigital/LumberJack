package internal

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vaziolabs/lumberjack/internal/core"
)

// What a bucket KEY means, as opposed to what a bucket counts.
//
// One wire value — the empty string — used to stand for three unrelated facts: a time the record
// does not carry, a field the record carries and whose value really is empty, and a dimension the
// selected kind has no field for at all. A consumer reading only the answer could not tell them
// apart, and a chart drew all three as one blank axis label. These are the three, separated.

// keyFixture is a leaf carrying, deliberately, one of each ambiguous case:
//
//   - an event with NO category, whose one entry therefore has no category either;
//   - an entry recorded on the NODE itself, which is in no event at all;
//   - an ongoing event, which has a start and no end.
//
// It returns the path of the leaf and the scope that holds only it.
func keyFixture(t *testing.T, server *Server, userID string) (string, string) {
	t.Helper()

	path := leafFor(t, server, userID, "keys/site")
	start := time.Date(2026, time.March, 2, 9, 0, 0, 0, time.UTC)

	// A finished event whose category is present and EMPTY, with an entry inside it.
	plantEvent(t, server, path, "uncategorised", "", userID, start, start.Add(600*time.Second))
	// A finished event that has a category, so the empty one is not the only bucket.
	plantEvent(t, server, path, "inspected", "inspection", userID, start, start.Add(300*time.Second))

	node, err := server.getNodeFromPath(path)
	if err != nil {
		t.Fatalf("Failed to find the fixture node: %v", err)
	}

	// An event that has STARTED and not ended: it carries a start_time and no end_time.
	ongoing := start.Add(48 * time.Hour)
	node.Events["ongoing"] = core.Event{
		StartTime: &ongoing,
		Status:    core.EventOngoing,
		Category:  "inspection",
		CreatedBy: userID,
		CreatedAt: ongoing,
	}

	// An entry on the node itself, which is what time tracking and the activity log write. It is in
	// no event, so it has no event_id, no status and no category.
	node.Entries = append(node.Entries, core.Entry{
		Content: "logged on the node", UserID: userID, Timestamp: start, CreatedAt: start,
	})

	return path, "keys"
}

// keyOf returns the one bucket whose key is exactly the dimensions and values given, and fails
// naming what was there instead. An ABSENT dimension is named by leaving it out of want, which is
// the whole distinction under test: `{}` and `{"category": ""}` are different buckets.
func bucketWithKey(t *testing.T, answer aggregateResponse, want map[string]string) bucketView {
	t.Helper()

	for _, bucket := range answer.Buckets {
		if len(bucket.Key) != len(want) {
			continue
		}
		matched := true
		for name, value := range want {
			got, present := bucket.Key[name]
			if !present || got != value {
				matched = false
				break
			}
		}
		if matched {
			return bucket
		}
	}
	t.Fatalf("No bucket keyed exactly %v in %+v", want, answer.Buckets)
	return bucketView{}
}

// CASE ONE: a time the record does not carry is an ABSENT dimension, not an empty one.
//
// An ongoing event has a start and no end. Bucketed on end_time it used to land in a bucket keyed
// `{"day": ""}` — indistinguishable from a day whose name happened to be empty, which is not a
// thing, and from the two cases below, which are.
func TestAggregateOmitsATimeDimensionTheRecordDoesNotCarry(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	_, scope := keyFixture(t, server, userID)

	answer := aggregateOf(t, server, userID, map[string]interface{}{
		"select": "events", "scope": scope, "group": []string{groupDay},
		"bucket_field": timeFieldEnd,
	})

	for _, bucket := range answer.Buckets {
		if value, present := bucket.Key[groupDay]; present && value == "" {
			t.Fatalf("A bucket is keyed on the empty day: %+v", answer.Buckets)
		}
	}

	// The one event with no end time, in a bucket that says so by carrying no day at all.
	if count := bucketWithKey(t, answer, map[string]string{}).Count; count != 1 {
		t.Errorf("The bucket with no day counted %d, want 1 (the ongoing event)", count)
	}
	// The two that finished still name their day.
	if count := bucketWithKey(t, answer, map[string]string{groupDay: "2026-03-02"}).Count; count != 2 {
		t.Errorf("2026-03-02 counted %d, want 2", count)
	}
}

// The same fact about a NODE, which is the shape the live forest showed it in: the root node's
// created_at is the zero time, so a day bucketing over the whole forest produced a `{"day": ""}`
// bucket that meant "this node has no creation time on record".
func TestAggregateOmitsADayForANodeWithNoCreationTime(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	leafFor(t, server, userID, "keys/site")

	node, err := server.getNodeFromPath("keys")
	if err != nil {
		t.Fatalf("Failed to find the fixture node: %v", err)
	}
	node.CreatedAt = time.Time{}

	answer := aggregateOf(t, server, userID, map[string]interface{}{
		"select": "nodes", "scope": "keys", "group": []string{groupDay},
	})

	undated := bucketWithKey(t, answer, map[string]string{})
	if undated.Count != 1 {
		t.Errorf("The bucket with no day counted %d, want 1", undated.Count)
	}
	if _, present := undated.Key[groupDay]; present {
		t.Errorf("The undated bucket carries a day: %v", undated.Key)
	}
	if len(answer.Buckets) != 2 {
		t.Fatalf("Got %+v, want two buckets: the undated node and the dated one", answer.Buckets)
	}
}

// CASE TWO: a field the record CARRIES, whose value is empty, keeps its key.
//
// An event with no category is not an event with no category FIELD. The empty string is its real
// value, and dropping the key would report the opposite of case one.
//
// THIS ONE PASSED BEFORE THE FIX AND PASSES AFTER, deliberately: it is the control on the other
// five, which all failed first. A fix that made absence unambiguous by dropping every empty value
// would satisfy every test above and break this, which is the failure mode worth a test of its own.
func TestAggregateKeepsADimensionWhoseValueIsGenuinelyEmpty(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	_, scope := keyFixture(t, server, userID)

	answer := aggregateOf(t, server, userID, map[string]interface{}{
		"select": "events", "scope": scope, "group": []string{"category"},
	})

	empty := bucketWithKey(t, answer, map[string]string{"category": ""})
	if empty.Count != 1 {
		t.Errorf("The empty category counted %d, want 1", empty.Count)
	}
	if value, present := empty.Key["category"]; !present || value != "" {
		t.Errorf("The empty category's key is %v, want the dimension present and empty", empty.Key)
	}
}

// The two cases in ONE answer, which is the proof they are different buckets and not one.
//
// Among a node's entries, the one inside an uncategorised event carries an empty category, and the
// one recorded on the node itself is in no event and carries no category at all. They used to be
// summed into a single `{"category": ""}` bucket of 2, because bucketIdentity built the same text
// for both.
func TestAggregateSeparatesAnAbsentDimensionFromAnEmptyOne(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	_, scope := keyFixture(t, server, userID)

	answer := aggregateOf(t, server, userID, map[string]interface{}{
		"select": "entries", "scope": scope, "group": []string{"category"},
	})

	if count := bucketWithKey(t, answer, map[string]string{"category": ""}).Count; count != 1 {
		t.Errorf("The empty category counted %d, want 1 (the entry of the uncategorised event)", count)
	}
	if count := bucketWithKey(t, answer, map[string]string{}).Count; count != 1 {
		t.Errorf("The bucket with no category counted %d, want 1 (the entry on the node itself)", count)
	}
	if len(answer.Buckets) != 3 {
		t.Fatalf("Got %+v, want three: no category, the empty one, and \"inspection\"", answer.Buckets)
	}
}

// An entry recorded on the node itself has no event_id, which is not an event whose id is empty.
func TestAggregateOmitsTheEventOfAnEntryThatIsInNoEvent(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	_, scope := keyFixture(t, server, userID)

	answer := aggregateOf(t, server, userID, map[string]interface{}{
		"select": "entries", "scope": scope, "group": []string{"event_id"},
	})

	for _, bucket := range answer.Buckets {
		if value, present := bucket.Key["event_id"]; present && value == "" {
			t.Fatalf("A bucket is keyed on the empty event id: %+v", answer.Buckets)
		}
	}
	if count := bucketWithKey(t, answer, map[string]string{}).Count; count != 1 {
		t.Errorf("The bucket with no event counted %d, want 1", count)
	}
	if count := bucketWithKey(t, answer, map[string]string{"event_id": "uncategorised"}).Count; count != 1 {
		t.Errorf("The uncategorised event's entry counted %d, want 1", count)
	}
}

// CASE THREE: a dimension the selected kind has no field for is the CALLER'S MISTAKE, and is
// refused rather than answered.
//
// It cannot be a bucket key, empty or absent, because the request has no answer: a node has no
// status, so "how many nodes per status" is not a question about nodes. Answering it with one
// bucket of everything is a report that looks like data. The `event_id` row is the sharpest of
// them — grouping nodes by event_id returned the NODE's id under the name `event_id`, so the
// answer was not merely uninformative but wrong.
func TestAggregateRefusesADimensionTheSelectedKindHasNoFieldFor(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	keyFixture(t, server, userID)

	refused := []struct {
		selecting string
		dimension string
	}{
		{selectNodes, "status"},
		{selectNodes, "category"},
		{selectNodes, "event_id"},
		{selectTime, "status"},
		{selectTime, "category"},
		{selectTime, "event_id"},
	}
	for _, testCase := range refused {
		t.Run(testCase.selecting+" by "+testCase.dimension, func(t *testing.T) {
			recorder := post(t, server.handleAggregate, userID, map[string]interface{}{
				"select": testCase.selecting, "scope": "keys", "group": []string{testCase.dimension},
			})
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("got %d, want %d: %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
			}
			if body := recorder.Body.String(); !strings.Contains(body, testCase.dimension) {
				t.Errorf("The refusal does not name the dimension: %s", body)
			}
		})
	}

	// The dimensions every kind DOES carry are unaffected, so the refusal is about applicability
	// and not about the select.
	allowed := []struct {
		selecting string
		dimension string
	}{
		{selectNodes, "node_path"},
		{selectNodes, "user_id"},
		{selectNodes, groupDay},
		{selectTime, "node_path"},
		{selectTime, "user_id"},
		{selectEntries, "status"},
		{selectEntries, "category"},
		{selectEntries, "event_id"},
		{selectEvents, "status"},
	}
	for _, testCase := range allowed {
		t.Run(testCase.selecting+" by "+testCase.dimension+" is answered", func(t *testing.T) {
			if code := post(t, server.handleAggregate, userID, map[string]interface{}{
				"select": testCase.selecting, "scope": "keys", "group": []string{testCase.dimension},
			}).Code; code != http.StatusOK {
				t.Errorf("got %d, want %d", code, http.StatusOK)
			}
		})
	}
}

// The same rule for the time a bucketing READS: a node has no start_time, so bucketing nodes on one
// is a request with no answer rather than one whose every bucket is nameless.
func TestAggregateRefusesABucketFieldTheSelectedKindDoesNotCarry(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	keyFixture(t, server, userID)

	refused := []struct {
		selecting string
		field     string
	}{
		{selectNodes, timeFieldStart},
		{selectNodes, timeFieldEnd},
		{selectEntries, timeFieldStart},
		{selectEntries, timeFieldEnd},
		{selectTime, timeFieldCreatedAt},
		{selectTime, timeFieldModifiedAt},
	}
	for _, testCase := range refused {
		t.Run(testCase.selecting+" on "+testCase.field, func(t *testing.T) {
			recorder := post(t, server.handleAggregate, userID, map[string]interface{}{
				"select": testCase.selecting, "scope": "keys",
				"group": []string{groupDay}, "bucket_field": testCase.field,
			})
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("got %d, want %d: %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
			}
		})
	}

	// end_time on an EVENT is carried — by the ones that have ended — so it is answered, and the
	// ones still running fall in the bucket with no day. That is case one, not case three.
	if code := post(t, server.handleAggregate, userID, map[string]interface{}{
		"select": selectEvents, "scope": "keys",
		"group": []string{groupDay}, "bucket_field": timeFieldEnd,
	}).Code; code != http.StatusOK {
		t.Errorf("Bucketing events on end_time: got %d, want %d", code, http.StatusOK)
	}
}

// The tables that say what a dimension is and what kinds carry it are one table's two halves, and
// a dimension in one and not the other is either unreadable or unreachable.
func TestEveryGroupDimensionDeclaresTheKindsThatCarryIt(t *testing.T) {
	for dimension := range groupFields {
		kinds, declared := dimensionKinds[dimension]
		if !declared {
			t.Errorf("groupFields reads %q and dimensionKinds does not say which kinds carry it", dimension)
			continue
		}
		if len(kinds) == 0 {
			t.Errorf("%q is carried by no kind, so it can never be grouped by", dimension)
		}
	}
	for dimension := range dimensionKinds {
		if _, readable := groupFields[dimension]; !readable {
			t.Errorf("dimensionKinds declares %q, which groupFields cannot read", dimension)
		}
	}
}

// The default a select buckets on has to be a time that select's candidates carry, or the route's
// own default would be refused by the rule above.
func TestEveryDefaultBucketFieldIsATimeThatKindCarries(t *testing.T) {
	for _, selecting := range []string{selectNodes, selectEvents, selectEntries, selectTime} {
		field := defaultBucketField(selecting)
		if !carriesTimeField(selecting, field) {
			t.Errorf("%s defaults to bucketing on %q, which a %s does not carry", selecting, field, selecting)
		}
		if !timeFieldsAllowed[field] {
			t.Errorf("%s defaults to bucketing on %q, which is not a time field at all", selecting, field)
		}
	}
}
