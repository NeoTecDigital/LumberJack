package internal

import (
	"encoding/json"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"
)

// POST /aggregate — counts and totals over the same predicate grammar /query filters with.
//
// This is what every dashboard tile and every report is made of. It SHARES the evaluator with
// /query rather than restating it: two implementations of "ongoing inspections in March" is two
// places for them to disagree, and the one a caller checks is never the one that is wrong.

// The dimensions a bucket key can be built from. The three time bucketings are the reason this is a
// closed set rather than "any field": day, week and month are computed, not read.
const (
	groupDay   = "day"
	groupWeek  = "week"
	groupMonth = "month"
)

// absentDimension marks, inside a bucket's identity text, a dimension the bucket has no value for.
// It is never sent on the wire — the answer says the same thing by omitting the key.
const absentDimension = "\x1e"

// The metrics a bucket can carry.
const (
	metricCount       = "count"
	metricDurationSum = "duration_sum"
	metricDurationAvg = "duration_avg"
)

// groupFields are the dimensions read straight off a candidate, and WHETHER THE CANDIDATE CARRIES
// THEM. The second result is the whole difference between a value that is empty and no value at
// all: an entry recorded on the node itself is in no event, so its event_id, status and category
// are ABSENT, where an entry inside an uncategorised event has a category and it is "".
//
// node_path and user_id are fields of every kind and are always present; an empty user_id is a
// record that names no user, which is a value.
var groupFields = map[string]func(candidate) (string, bool){
	"node_path": func(item candidate) (string, bool) { return item.NodePath, true },
	"user_id":   func(item candidate) (string, bool) { return item.UserID, true },
	"status":    func(item candidate) (string, bool) { return item.Status, item.inEvent() },
	"category":  func(item candidate) (string, bool) { return item.Category, item.inEvent() },
	"event_id":  func(item candidate) (string, bool) { return item.ID, item.inEvent() },
}

// dimensionKinds names, for each dimension, the kinds of candidate that HAVE it as a field.
//
// It is the other half of groupFields: one says how a dimension is read, this says of what. A node
// has no status, no category and no event, so "how many nodes per status" is not a question about
// nodes — it is a category error, and compileGrouping refuses it rather than answering with one
// bucket of everything keyed on nothing. Grouping nodes by event_id was the sharpest case: the
// reader returns candidate.ID, which for a node is the NODE's id, so the answer came back labelled
// `event_id` and carrying something that is not one.
var dimensionKinds = map[string][]string{
	"node_path": {selectNodes, selectEvents, selectEntries, selectTime},
	"user_id":   {selectNodes, selectEvents, selectEntries, selectTime},
	"status":    {selectEvents, selectEntries},
	"category":  {selectEvents, selectEntries},
	"event_id":  {selectEvents, selectEntries},
}

// kindTimeFields names the times each kind of candidate CARRIES, which is what query_candidates.go
// puts in its Times map and nothing more.
//
// The same rule as dimensionKinds, for the field a day, week or month bucketing reads: a node has
// no start_time, so bucketing nodes on one is a request with no answer rather than one whose every
// bucket is nameless. An event's end_time IS carried — by the events that have ended — so it is
// allowed, and the ones still running fall in the bucket with no day. Absent on a RECORD and absent
// on a KIND are different facts and are answered differently.
var kindTimeFields = map[string][]string{
	selectNodes:   {timeFieldCreatedAt, timeFieldModifiedAt, timeFieldTimestamp},
	selectEvents:  {timeFieldCreatedAt, timeFieldModifiedAt, timeFieldTimestamp, timeFieldStart, timeFieldEnd},
	selectEntries: {timeFieldTimestamp, timeFieldCreatedAt, timeFieldModifiedAt},
	selectTime:    {timeFieldStart, timeFieldEnd, timeFieldTimestamp},
}

// kindNouns name a kind in a refusal, so the sentence reads as the statement about the data that it
// is: `cannot group nodes by "status": a node has no status`.
var kindNouns = map[string]string{
	selectNodes:   "a node",
	selectEvents:  "an event",
	selectEntries: "an entry",
	selectTime:    "a time span",
}

// carriesDimension reports whether a kind of candidate has a dimension as a field at all.
func carriesDimension(selecting, dimension string) bool {
	return slices.Contains(dimensionKinds[dimension], selecting)
}

// carriesTimeField reports whether a kind of candidate carries a named time at all.
func carriesTimeField(selecting, field string) bool {
	return slices.Contains(kindTimeFields[selecting], field)
}

// aggregateRequest is POST /aggregate.
//
// BucketField names the time the day, week and month groupings read. It is explicit because the two
// answers are different reports: an event PLANNED for November and entered in September belongs in
// November on a calendar and in September in a record of what was booked when.
type aggregateRequest struct {
	Select      string       `json:"select"`
	Scope       string       `json:"scope"`
	Depth       *int         `json:"depth"`
	Where       *whereClause `json:"where"`
	Group       []string     `json:"group"`
	Metric      []string     `json:"metric"`
	BucketField string       `json:"bucket_field"`
}

// bucketView is one group of the answer.
//
// Durations are in SECONDS, and the average is over the candidates that HAVE a duration rather than
// over all of them: an ongoing event counts, but dividing a total by things that contributed
// nothing to it reports an average that is not the average of anything.
// UNITS: duration_sum and duration_avg are SECONDS, as a fraction. One quantity is reported in
// three units across this API and the only defence is naming each of them where it is returned:
// SECONDS here, MILLISECONDS as `duration_ms` on a /query result, NANOSECONDS as `duration` on a
// /time session. None of the three is changed by this note; all three are now stated.
//
// Key CARRIES ONLY THE DIMENSIONS THE BUCKET HAS A VALUE FOR. A dimension the members do not carry
// is ABSENT from the map; a dimension whose value is genuinely the empty string is present and
// empty; and a dimension the selected kind has no field for is refused by compileGrouping and never
// reaches a bucket at all. Those are three different facts and used to be one empty string.
type bucketView struct {
	Key             map[string]string `json:"key"`
	Count           int               `json:"count"`
	DurationSum     *float64          `json:"duration_sum,omitempty"`
	DurationAverage *float64          `json:"duration_avg,omitempty"`
}

// aggregateResponse is what POST /aggregate answers.
type aggregateResponse struct {
	Buckets []bucketView `json:"buckets"`
}

func (server *Server) handleAggregate(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

	var request aggregateRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	response, err := server.runAggregate(userID, request)
	if err != nil {
		writeAPIError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// runAggregate is the route's body without the HTTP of it.
func (server *Server) runAggregate(userID string, request aggregateRequest) (*aggregateResponse, error) {
	if !validSelect(request.Select, selectNodes, selectEvents, selectEntries, selectTime) {
		return nil, apiErrorf(http.StatusBadRequest,
			"select must be %q, %q, %q or %q", selectNodes, selectEvents, selectEntries, selectTime)
	}

	group, err := compileGrouping(request.Group, request.BucketField, request.Select)
	if err != nil {
		return nil, err
	}
	metrics, err := compileMetrics(request.Metric)
	if err != nil {
		return nil, err
	}
	filter, err := compilePredicate(request.Where)
	if err != nil {
		return nil, err
	}

	matches, err := server.matching(userID, request.Select, request.Scope, request.Depth, filter)
	if err != nil {
		return nil, err
	}

	return &aggregateResponse{Buckets: bucketize(matches, group, metrics)}, nil
}

// grouping is a compiled group list: the dimensions, in the order the caller named them, and the
// time a day, week or month among them is read from.
type grouping struct {
	dimensions  []string
	bucketField string
}

// compileGrouping validates the dimensions and the time the bucketings read.
//
// An EMPTY group is the whole selection as one bucket, which is what "how many are there" asks for.
func compileGrouping(dimensions []string, bucketField, selecting string) (*grouping, error) {
	for _, dimension := range dimensions {
		if err := checkDimension(dimension, selecting); err != nil {
			return nil, err
		}
	}

	if bucketField == "" {
		return &grouping{dimensions: dimensions, bucketField: defaultBucketField(selecting)}, nil
	}
	if !timeFieldsAllowed[bucketField] {
		return nil, apiErrorf(http.StatusBadRequest, "cannot bucket on %q", bucketField)
	}
	if !carriesTimeField(selecting, bucketField) {
		return nil, apiErrorf(http.StatusBadRequest,
			"cannot bucket %s on %q: %s has no %s", selecting, bucketField, kindNouns[selecting], bucketField)
	}
	return &grouping{dimensions: dimensions, bucketField: bucketField}, nil
}

// checkDimension refuses a dimension that is not one, and a dimension the selected kind has no
// field for.
//
// THE SECOND REFUSAL IS THE POINT. Grouping nodes by status used to answer 200 with every node in
// one bucket keyed `{"status": ""}`, which is a report that looks like data; grouping them by
// event_id answered with the NODE's id under the name `event_id`, which is worse than
// uninformative. Neither is a question about nodes, and the request is refused where it is
// compiled — before the forest is read, so the answer does not depend on what happens to be in it.
func checkDimension(dimension, selecting string) error {
	if dimension == groupDay || dimension == groupWeek || dimension == groupMonth {
		return nil
	}
	if _, known := groupFields[dimension]; !known {
		return apiErrorf(http.StatusBadRequest, "cannot group by %q", dimension)
	}
	if !carriesDimension(selecting, dimension) {
		return apiErrorf(http.StatusBadRequest,
			"cannot group %s by %q: %s has no %s", selecting, dimension, kindNouns[selecting], dimension)
	}
	return nil
}

// defaultBucketField is the time a bucketing means when the caller does not name one.
//
// WHEN THE WORK HAPPENS, not when the record of it was made. An event's span is what a calendar
// draws and what a report of a period is about, so it is the event's start; an entry has no span —
// the thing that happened IS the entry — so it is the entry's own timestamp. A closed time span
// starts when the clock was started. A NODE has no span either and no timestamp of its own: it is
// a place work is recorded, and the only moment it has is the one it came into existence at.
func defaultBucketField(selecting string) string {
	switch selecting {
	case selectEntries:
		return timeFieldTimestamp
	case selectNodes:
		return timeFieldCreatedAt
	default:
		return timeFieldStart
	}
}

// key builds a candidate's bucket key, CARRYING ONLY THE DIMENSIONS THE CANDIDATE HAS A VALUE FOR.
//
// A dimension the record does not carry is left out of the map rather than written as "". The empty
// string is a value — an uncategorised event's category really is empty — so spending it as a
// sentinel for "no value" leaves a consumer no way to tell the two apart, and no way to render
// either: an empty key sorts first and draws as a blank axis label. Absence is the absence of the
// key, which is what JSON already has a way to say.
func (g *grouping) key(item candidate) map[string]string {
	key := make(map[string]string, len(g.dimensions))
	for _, dimension := range g.dimensions {
		if value, present := g.valueOf(item, dimension); present {
			key[dimension] = value
		}
	}
	return key
}

// valueOf reads one dimension off a candidate, and says whether the candidate has it.
//
// A TIME dimension is absent when the candidate carries no such instant: an event that has not
// ended has no end_time, so bucketing it on end_time places it in no day rather than in a nameless
// one. That is a fact about the RECORD; a kind that carries no such time at all is refused by
// compileGrouping before any of this runs.
func (g *grouping) valueOf(item candidate, dimension string) (string, bool) {
	if read, known := groupFields[dimension]; known {
		return read(item)
	}

	at := item.timeOf(g.bucketField)
	if at.IsZero() {
		return "", false
	}
	return timeBucket(at, dimension), true
}

// timeBucket names the day, week or month an instant falls in. The caller establishes that there IS
// an instant: naming the bucket of a time that was never set is the caller's question, not this
// function's, and answering it with "" here is what made three unrelated facts one wire value.
//
// UTC, so a bucket is the same bucket wherever it is asked from; and a WEEK starts on Monday and is
// named by that Monday's date, because ISO weeks are what every report in this domain means by a
// week and naming a week by its first day is the only naming that also sorts.
func timeBucket(at time.Time, unit string) string {
	moment := at.UTC()
	switch unit {
	case groupMonth:
		return moment.Format("2006-01")
	case groupWeek:
		weekday := (int(moment.Weekday()) + 6) % 7 // Monday is 0
		return moment.AddDate(0, 0, -weekday).Format("2006-01-02")
	default:
		return moment.Format("2006-01-02")
	}
}

// compileMetrics validates the metrics and supplies the default.
func compileMetrics(metrics []string) ([]string, error) {
	if len(metrics) == 0 {
		return []string{metricCount}, nil
	}

	for _, metric := range metrics {
		switch metric {
		case metricCount, metricDurationSum, metricDurationAvg:
		default:
			return nil, apiErrorf(http.StatusBadRequest, "unknown metric %q", metric)
		}
	}
	return metrics, nil
}

// accumulator is one bucket while it is being filled. order is its identity, which is what
// renderBuckets sorts on.
type accumulator struct {
	key           map[string]string
	order         string
	count         int
	durationTotal time.Duration
	durationCount int
}

// bucketize groups the matches and computes the metrics asked for.
func bucketize(matches []candidate, group *grouping, metrics []string) []bucketView {
	buckets := map[string]*accumulator{}

	for _, item := range matches {
		key := group.key(item)
		identity := bucketIdentity(group.dimensions, key)

		bucket, exists := buckets[identity]
		if !exists {
			bucket = &accumulator{key: key, order: identity}
			buckets[identity] = bucket
		}

		bucket.count++
		if item.HasDuration {
			bucket.durationTotal += item.Duration
			bucket.durationCount++
		}
	}

	return renderBuckets(buckets, metrics)
}

// bucketIdentity is the text that identifies a bucket: `name=value` for each dimension, in the
// order the caller named them.
//
// It is the map key AND the sort key. There used to be a SECOND identity for the same concept —
// one built from the values alone in the caller's order to key the map, another from `name=value`
// in alphabetical order to sort the answer — which is two ways to say what a bucket is, and no
// reason for them to stay in step.
//
// An ABSENT dimension is marked rather than written as `name=`, so that a bucket with no value for
// a dimension is a different bucket from one whose value is the empty string. Ranging `key` alone
// would give them the same text and sum them together, which is the same conflation the wire had.
// The marker sorts before "=", so the bucket with no value comes first among that dimension's.
func bucketIdentity(dimensions []string, key map[string]string) string {
	parts := make([]string, 0, len(dimensions))
	for _, dimension := range dimensions {
		if value, present := key[dimension]; present {
			parts = append(parts, dimension+"="+value)
			continue
		}
		parts = append(parts, dimension+absentDimension)
	}
	return strings.Join(parts, "\x1f")
}

// renderBuckets turns the accumulators into the answer, ordered and carrying only what was asked.
func renderBuckets(buckets map[string]*accumulator, metrics []string) []bucketView {
	wants := map[string]bool{}
	for _, metric := range metrics {
		wants[metric] = true
	}

	// Ordered by the identity the bucket was keyed on, so an answer comes back the same way every
	// time: ranging the map alone is deliberately randomized.
	ordered := make([]*accumulator, 0, len(buckets))
	for _, bucket := range buckets {
		ordered = append(ordered, bucket)
	}
	sort.Slice(ordered, func(a, b int) bool { return ordered[a].order < ordered[b].order })

	rendered := make([]bucketView, 0, len(ordered))
	for _, bucket := range ordered {
		view := bucketView{Key: bucket.key, Count: bucket.count}

		if wants[metricDurationSum] {
			total := bucket.durationTotal.Seconds()
			view.DurationSum = &total
		}
		if wants[metricDurationAvg] {
			average := 0.0
			if bucket.durationCount > 0 {
				average = bucket.durationTotal.Seconds() / float64(bucket.durationCount)
			}
			view.DurationAverage = &average
		}
		rendered = append(rendered, view)
	}
	return rendered
}
