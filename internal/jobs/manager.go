package jobs

import (
	"sync"
	"time"
)

type State string

const (
	StateRunning State = "running"
	StateDone    State = "done"
	StateError   State = "error"
)

type Event = map[string]any

type Job struct {
	ID        string
	State     State
	CreatedAt time.Time

	mu      sync.RWMutex
	events  []Event
	subs    map[int]chan Event
	nextSub int
}

func (j *Job) Publish(ev Event) {
	j.mu.Lock()
	defer j.mu.Unlock()

	j.events = append(j.events, ev)
	for _, ch := range j.subs {
		select {
		case ch <- ev:
		default:
		}
	}
	t, _ := ev["type"].(string)
	if t == "done" || t == "error" {
		if t == "done" {
			j.State = StateDone
		} else {
			j.State = StateError
		}
		for _, ch := range j.subs {
			close(ch)
		}
		j.subs = nil
	}
}

func (j *Job) Subscribe() (<-chan Event, func()) {
	j.mu.Lock()
	defer j.mu.Unlock()

	ch := make(chan Event, len(j.events)+128)
	for _, ev := range j.events {
		ch <- ev
	}

	if j.State != StateRunning {
		close(ch)
		return ch, func() {}
	}

	id := j.nextSub
	j.nextSub++
	if j.subs == nil {
		j.subs = make(map[int]chan Event)
	}
	j.subs[id] = ch

	return ch, func() {
		j.mu.Lock()
		delete(j.subs, id)
		j.mu.Unlock()
	}
}

type Manager struct {
	mu   sync.RWMutex
	jobs map[string]*Job
}

func NewManager() *Manager {
	m := &Manager{jobs: make(map[string]*Job)}
	go m.gc()
	return m
}

func (m *Manager) Create(id string) *Job {
	job := &Job{
		ID:        id,
		State:     StateRunning,
		CreatedAt: time.Now(),
		subs:      make(map[int]chan Event),
	}
	m.mu.Lock()
	m.jobs[id] = job
	m.mu.Unlock()
	return job
}

func (m *Manager) Get(id string) *Job {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.jobs[id]
}

func (m *Manager) gc() {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-time.Hour)
		m.mu.Lock()
		for id, job := range m.jobs {
			job.mu.RLock()
			expired := job.State != StateRunning && job.CreatedAt.Before(cutoff)
			job.mu.RUnlock()
			if expired {
				delete(m.jobs, id)
			}
		}
		m.mu.Unlock()
	}
}
