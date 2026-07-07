package collector

import (
	"testing"
	"time"
)

func entry(user, name, errCode, id string, ts time.Time) Entry {
	return Entry{
		Record:    map[string]any{"eventID": id},
		Outputs:   map[string]any{"user_name": user, "event_name": name},
		UserName:  user,
		EventName: name,
		ErrorCode: errCode,
		EventID:   id,
		Time:      ts,
	}
}

func TestDedupeGroupsIdenticalEvents(t *testing.T) {
	var alerts []*Group
	c := New(func(g *Group) { alerts = append(alerts, g) }, true)

	t0 := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	c.Add(entry("jane", "PutUserPolicy", "", "e1", t0))
	c.Add(entry("jane", "PutUserPolicy", "", "e2", t0.Add(time.Minute)))
	c.Add(entry("jane", "PutUserPolicy", "", "e3", t0.Add(2*time.Minute)))
	c.Flush()

	if len(alerts) != 1 {
		t.Fatalf("alerts = %d, want 1", len(alerts))
	}
	g := alerts[0]
	if g.Count != 3 {
		t.Errorf("count = %d, want 3", g.Count)
	}
	if !g.First.Equal(t0) || !g.Last.Equal(t0.Add(2*time.Minute)) {
		t.Errorf("window = %v..%v", g.First, g.Last)
	}
	// The most recent record wins, matching v1.
	if g.Record["eventID"] != "e3" {
		t.Errorf("record = %v, want latest", g.Record["eventID"])
	}
}

func TestDedupeKeySeparatesGroups(t *testing.T) {
	var alerts []*Group
	c := New(func(g *Group) { alerts = append(alerts, g) }, true)

	t0 := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	c.Add(entry("jane", "PutUserPolicy", "", "e1", t0))
	c.Add(entry("jane", "PutUserPolicy", "AccessDenied", "e2", t0))
	c.Add(entry("bob", "PutUserPolicy", "", "e3", t0))
	c.Add(entry("jane", "DeleteTrail", "", "e4", t0))
	c.Flush()

	if len(alerts) != 4 {
		t.Fatalf("alerts = %d, want 4 (distinct user/event/error tuples)", len(alerts))
	}
}

func TestFlushPreservesInsertionOrder(t *testing.T) {
	var alerts []*Group
	c := New(func(g *Group) { alerts = append(alerts, g) }, true)

	t0 := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	c.Add(entry("jane", "DeleteTrail", "", "e1", t0))
	c.Add(entry("bob", "RunInstances", "", "e2", t0))
	c.Add(entry("jane", "DeleteTrail", "", "e3", t0))
	c.Flush()

	if len(alerts) != 2 {
		t.Fatalf("alerts = %d, want 2", len(alerts))
	}
	if alerts[0].EventName != "DeleteTrail" || alerts[1].EventName != "RunInstances" {
		t.Errorf("order = %s, %s", alerts[0].EventName, alerts[1].EventName)
	}
}

func TestDedupeDisabledAlertsPerRecord(t *testing.T) {
	var alerts []*Group
	c := New(func(g *Group) { alerts = append(alerts, g) }, false)

	t0 := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	c.Add(entry("jane", "PutUserPolicy", "", "e1", t0))
	c.Add(entry("jane", "PutUserPolicy", "", "e2", t0.Add(time.Minute)))
	c.Add(entry("jane", "PutUserPolicy", "", "e3", t0.Add(2*time.Minute)))
	c.Flush()

	if len(alerts) != 3 {
		t.Fatalf("alerts = %d, want 3 (dedupe disabled)", len(alerts))
	}
	for i, g := range alerts {
		if g.Count != 1 {
			t.Errorf("alerts[%d].Count = %d, want 1", i, g.Count)
		}
	}
	if alerts[0].Record["eventID"] != "e1" || alerts[2].Record["eventID"] != "e3" {
		t.Errorf("per-record order lost: %v, %v", alerts[0].Record["eventID"], alerts[2].Record["eventID"])
	}
}

func TestFlushResets(t *testing.T) {
	var alerts []*Group
	c := New(func(g *Group) { alerts = append(alerts, g) }, true)

	t0 := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	c.Add(entry("jane", "DeleteTrail", "", "e1", t0))
	c.Flush()
	c.Flush()

	if len(alerts) != 1 {
		t.Fatalf("alerts = %d, want 1 (second flush must be a no-op)", len(alerts))
	}
}
