package plain

import (
	"context"
	"fmt"

	"github.com/VictorDenisov/kafka-go"
)

type Mechanism struct {
	Username, Password string
}

func (m *Mechanism) Start(ctx context.Context) (string, []byte, error) {
	return "PLAIN", []byte(fmt.Sprintf("\x00%s\x00%s", m.Username, m.Password)), nil
}

func (m *Mechanism) Next(ctx context.Context, challenge []byte) (bool, []byte, error) {
	if len(challenge) > 0 {
		return false, nil, kafka.IllegalSASLState
	}
	return true, nil, nil
}