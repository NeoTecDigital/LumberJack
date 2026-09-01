package internal

import (
	"encoding/json"
	"net/http"
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

// The metrics a bucket can carry.
const (
	metricCount       = "count"
	metricDurationSum = "duration_sum"
	metricDurationAvg = "duration_avg"
)

// groupFields are the dimensions read straight off a candidate.
var groupFields = map[string]func(candidate) string{
	"node_path": func(item candidate) string { return item.NodePath },
	"status":    func(item candidate) string { return item.Status },
	"category":  func(item candidate) string { return item.Category },
	"user_id":   func(item candidate) string { return item.UserID },
	"event_id":  func(item candidate) string { return item.ID },
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
		if _, known := groupFields[dimension]; known {
			continue
		}
		if dimension == groupDay || dimension == groupWeek || dimension == groupMonth {
			continue
		}
		return nil, apiErrorf(http.StatusBadRequest, "cannot group by %q", dimension)
	}

	if bucketField == "" {
		return &grouping{dimensions: dimensions, bucketField: defaultBucketField(selecting)}, nil
	}
	if !timeFieldsAllowed[bucketField] {
		return nil, apiErrorf(http.StatusBadRequest, "cannot bucket on %q", bucketField)
	}
	return &grouping{dimensions: dimensions, bucketField: bucketField}, nil
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

// key builds a candidate's bucket key.
func (g *grouping) key(item candidate) map[string]string {
	key := make(map[string]string, len(g.dimensions))
	for _, dimension := range g.dimensions {
		if read, known := groupFields[dimension]; known {
			key[dimension] = read(item)
			continue
		}
		key[dimension] = timeBucket(item.timeOf(g.bucketField), dimension)
	}
	return key
}

// timeBucket names the day, week or month an instant falls in.
//
// UTC, so a bucket is the same bucket wherever it is asked from; and a WEEK starts on Monday and is
// named by that Monday's date, because ISO weeks are what every report in this domain means by a
// week and naming a week by its first day is the only naming that also sorts.
func timeBucket(at time.Time, unit string) string {
	if at.IsZero() {
		return ""
	}

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
func bucketIdentity(dimensions []string, key map[string]string) string {
	parts := make([]string, 0, len(dimensions))
	for _, dimension := range dimensions {
		parts = append(parts, dimension+"="+key[dimension])
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
