package collector

import (
	"time"

	"github.com/Techcadia/cloudtrail-console-actions/pkg/handler"
)

// GroupKey uniquely identifies a group of related CloudTrail events
type GroupKey struct {
	UserName  string
	EventName string
	ErrorCode string
}

// GroupedRecord represents a collection of similar CloudTrail events
type GroupedRecord struct {
	Record         map[string]interface{}
	UserName       string
	EventName      string
	ErrorCode      string
	Count          int
	FirstEventTime time.Time
	LastEventTime  time.Time
}

// EventCollector aggregates and groups CloudTrail events for alerting
type EventCollector struct {
	groups       map[GroupKey]*GroupedRecord
	eventRecords map[GroupKey]handler.Record
	alertFunc    func(*GroupedRecord, handler.Record)
}

// NewEventCollector creates a new EventCollector instance
func NewEventCollector(alertFunc func(*GroupedRecord, handler.Record)) *EventCollector {
	return &EventCollector{
		groups:       make(map[GroupKey]*GroupedRecord),
		eventRecords: make(map[GroupKey]handler.Record),
		alertFunc:    alertFunc,
	}
}

// AddRecord adds a CloudTrail record to the collector, grouping similar events
func (ec *EventCollector) AddRecord(record map[string]interface{}, userName, eventName, errorCode string, eventTime time.Time, eventRecord handler.Record) {
	key := GroupKey{
		UserName:  userName,
		EventName: eventName,
		ErrorCode: errorCode,
	}

	if existing, ok := ec.groups[key]; ok {
		existing.Count++
		existing.LastEventTime = eventTime
		existing.Record = record
	} else {
		ec.groups[key] = &GroupedRecord{
			Record:         record,
			UserName:       userName,
			EventName:      eventName,
			ErrorCode:      errorCode,
			Count:          1,
			FirstEventTime: eventTime,
			LastEventTime:  eventTime,
		}
		ec.eventRecords[key] = eventRecord
	}
}

// SendAllAlerts sends alerts for all collected event groups
func (ec *EventCollector) SendAllAlerts() {
	for key, group := range ec.groups {
		ec.alertFunc(group, ec.eventRecords[key])
	}
}
