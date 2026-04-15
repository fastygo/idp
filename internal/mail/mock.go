package mail

import (
	"context"
	"log"
	"sync"
	"time"
)

type MockSender struct {
	mu      sync.Mutex
	entries []LogEntry
}

func NewMockSender() *MockSender {
	return &MockSender{}
}

func (m *MockSender) Send(_ context.Context, msg Message) error {
	log.Printf("[MOCK MAIL] to=%s subject=%q", msg.To, msg.Subject)

	m.mu.Lock()
	defer m.mu.Unlock()

	m.entries = append(m.entries, LogEntry{
		To:      msg.To,
		Subject: msg.Subject,
		SentAt:  time.Now().UTC().Format("2006-01-02 15:04:05"),
		Status:  "mock",
	})
	return nil
}

func (m *MockSender) History() []LogEntry {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]LogEntry, len(m.entries))
	copy(out, m.entries)

	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}
