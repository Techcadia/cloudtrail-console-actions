// Package collector aggregates emitted CloudTrail records between file reads
// and flushes them as alerts. With deduplication enabled (the default),
// records sharing a (userName, eventName, errorCode) tuple collapse into one
// grouped alert with a count and a time window; disabled, every record
// alerts individually.
package collector

import (
	"time"

	"github.com/Techcadia/cloudtrail-console-actions/internal/event"
)

// Entry is one emitted record with everything the sinks need.
type Entry struct {
	Record    map[string]any // the raw CloudTrail record
	Outputs   map[string]any // the policy's outputs projection
	UserName  string         // preprocess.userName — part of the group key
	EventName string         // preprocess.eventName — part of the group key
	ErrorCode string         // raw errorCode, "" when absent
	EventID   string
	Time      time.Time
	Source    event.Record // the S3 object the record came from
}

// Group is one alert: a single record, or several deduplicated ones.
type Group struct {
	Entry
	Count int
	First time.Time
	Last  time.Time
}

type key struct {
	userName  string
	eventName string
	errorCode string
	eventID   string // only set when deduplication is disabled
}

// Collector groups entries until Flush. Not safe for concurrent use; the
// Lambda handler is single-threaded per invocation.
type Collector struct {
	dedupe bool
	alert  func(*Group)
	groups map[key]*Group
	order  []key
}

// New returns a collector that hands each flushed group to alert.
func New(alert func(*Group), dedupe bool) *Collector {
	return &Collector{
		dedupe: dedupe,
		alert:  alert,
		groups: make(map[key]*Group),
	}
}

// Add records one emitted CloudTrail record.
func (c *Collector) Add(e Entry) {
	k := key{userName: e.UserName, eventName: e.EventName, errorCode: e.ErrorCode}
	if !c.dedupe {
		// A unique key per record disables grouping while keeping one code path.
		k.eventID = e.EventID
	}

	if g, ok := c.groups[k]; ok {
		g.Count++
		g.Last = e.Time
		// The most recent record wins but the first source is kept, matching v1.
		g.Record, g.Outputs = e.Record, e.Outputs
		return
	}
	c.groups[k] = &Group{Entry: e, Count: 1, First: e.Time, Last: e.Time}
	c.order = append(c.order, k)
}

// Flush alerts every group in insertion order and resets the collector.
func (c *Collector) Flush() {
	for _, k := range c.order {
		c.alert(c.groups[k])
	}
	c.groups = make(map[key]*Group)
	c.order = nil
}
