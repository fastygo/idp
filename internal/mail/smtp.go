package mail

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	"idp-cyberos/internal/config"

	"gopkg.in/gomail.v2"
)

type SMTPSender struct {
	dialer  *gomail.Dialer
	from    string
	fromName string

	mu      sync.Mutex
	entries []LogEntry
}

func NewSMTPSender(cfg config.SMTPConfig) (*SMTPSender, error) {
	port, err := strconv.Atoi(cfg.Port)
	if err != nil {
		return nil, fmt.Errorf("invalid SMTP port %q: %w", cfg.Port, err)
	}

	d := gomail.NewDialer(cfg.Host, port, cfg.User, cfg.Password)

	return &SMTPSender{
		dialer:   d,
		from:     cfg.FromAddress,
		fromName: cfg.FromName,
	}, nil
}

func (s *SMTPSender) Send(_ context.Context, msg Message) error {
	m := gomail.NewMessage()
	m.SetAddressHeader("From", s.from, s.fromName)
	m.SetHeader("To", msg.To)
	m.SetHeader("Subject", msg.Subject)

	if msg.BodyHTML != "" {
		m.SetBody("text/html", msg.BodyHTML)
		if msg.BodyPlain != "" {
			m.AddAlternative("text/plain", msg.BodyPlain)
		}
	} else {
		m.SetBody("text/plain", msg.BodyPlain)
	}

	err := s.dialer.DialAndSend(m)

	s.mu.Lock()
	defer s.mu.Unlock()

	status := "sent"
	if err != nil {
		status = "error: " + err.Error()
		log.Printf("[SMTP] send failed to=%s: %v", msg.To, err)
	} else {
		log.Printf("[SMTP] sent to=%s subject=%q", msg.To, msg.Subject)
	}

	s.entries = append(s.entries, LogEntry{
		To:      msg.To,
		Subject: msg.Subject,
		SentAt:  time.Now().UTC().Format("2006-01-02 15:04:05"),
		Status:  status,
	})

	return err
}

func (s *SMTPSender) History() []LogEntry {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]LogEntry, len(s.entries))
	copy(out, s.entries)

	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}
