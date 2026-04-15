package mail

import "context"

type Message struct {
	To        string
	Subject   string
	BodyHTML  string
	BodyPlain string
}

type LogEntry struct {
	To        string
	Subject   string
	SentAt    string
	Status    string
}

type Sender interface {
	Send(ctx context.Context, msg Message) error
	History() []LogEntry
}
