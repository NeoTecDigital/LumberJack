package internal

import (
	"encoding/json"
	"fmt"
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
type aggregateRequest struct {
	Select string       `json:"select"`
	Scope  string       `json:"scope"`
	Depth  *int         `json:"depth"`
	Where  *whereClause `json:"where"`
	Group  []string     `json:"group"`
	Metric []string     `json:"metric"`
}

// bucketView is one group of the answer.
//
// Durations are in SECONDS, and the average is over the candidates that HAVE a duration rather than
// over all of them: an ongoing event counts, but dividing a total by things that contributed
// nothing to it reports an average that is not the average of anything.
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
	if !validSelect(request.Select, selectEvents, selectEntries, selectTime) {
		return nil, apiErrorf(http.StatusBadRequest,
			"select must be %q, %q or %q", selectEvents, selectEntries, selectTime)
	}

	group, err := compileGrouping(request.Group)
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

// grouping is a compiled group list: the dimensions, in the order the caller named them.
type grouping struct {
	dimensions []string
}

// compileGrouping validates the dimensions.
//
// An EMPTY group is the whole selection as one bucket, which is what "how many are there" asks for.
func compileGrouping(dimensions []string) (*grouping, error) {
	for _, dimension := range dimensions {
		if _, known := groupFields[dimension]; known {
			continue
		}
		if dimension == groupDay || dimension == groupWeek || dimension == groupMonth {
			continue
		}
		return nil, apiErrorf(http.StatusBadRequest, "cannot group by %q", dimension)
	}
	return &grouping{dimensions: dimensions}, nil
}

// key builds a candidate's bucket key.
func (g *grouping) key(item candidate) map[string]string {
	key := make(map[string]string, len(g.dimensions))
	for _, dimension := range g.dimensions {
		if read, known := groupFields[dimension]; known {
			key[dimension] = read(item)
			continue
		}
		key[dimension] = timeBucket(item.Timestamp, dimension)
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

// accumulator is one bucket while it is being filled.
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

// bucketIdentity is the text that identifies a bucket, in the order the caller named the
// dimensions. It doubles as the sort key, so an answer comes back in the same order every time.
func bucketIdentity(dimensions []string, key map[string]string) string {
	parts := make([]string, 0, len(dimensions))
	for _, dimension := range dimensions {
		parts = append(parts, key[dimension])
	}
	return strings.Join(parts, "\x1f")
}

// renderBuckets turns the accumulators into the answer, ordered and carrying only what was asked.
func renderBuckets(buckets map[string]*accumulator, metrics []string) []bucketView {
	wants := map[string]bool{}
	for _, metric := range metrics {
		wants[metric] = true
	}

	rendered := make([]bucketView, 0, len(buckets))
	for _, bucket := range buckets {
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

	sort.Slice(rendered, func(a, b int) bool {
		return bucketIdentityOf(rendered[a]) < bucketIdentityOf(rendered[b])
	})
	return rendered
}

// bucketIdentityOf orders a rendered bucket. The keys are sorted so the order does not depend on
// which dimension a map happened to hand back first.
func bucketIdentityOf(view bucketView) string {
	names := make([]string, 0, len(view.Key))
	for name := range view.Key {
		names = append(names, name)
	}
	sort.Strings(names)

	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, fmt.Sprintf("%s=%s", name, view.Key[name]))
	}
	return strings.Join(parts, "\x1f")
}
