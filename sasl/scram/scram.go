package scram

import (
	"context"
	"crypto/sha512"
	"hash"

	"github.com/pkg/errors"
	"github.com/xdg/scram"
)

type Algorithm int

const (
	_ Algorithm = iota
	SHA256
	SHA512
)

func (a Algorithm) String() string {
	switch a {
	case SHA256:
		return "SCRAM-SHA-256"
	case SHA512:
		return "SCRAM-SHA-512"
	}
	return "unknown"
}

func (a Algorithm) hashGenerator() scram.HashGeneratorFcn {
	switch a {
	case SHA256:
		return scram.SHA256
	case SHA512:
		return scram.HashGeneratorFcn(func() hash.Hash {
			return sha512.New()
		})
	}
	return nil
}

type mechanism struct {
	algo   Algorithm
	client *scram.ClientConversation
}

func Mechanism(algo Algorithm, username, password string) (*mechanism, error) {
	hashGen := algo.hashGenerator()
	if hashGen == nil {
		return nil, errors.New("unknown hash algorithm")
	}

	client, err := hashGen.NewClient(username, password, "")
	if err != nil {
		return nil, err
	}

	return &mechanism{
		algo:   algo,
		client: client.NewConversation(),
	}, nil
}

func (m *mechanism) Start(ctx context.Context) (string, []byte, error) {
	str, err := m.client.Step("")
	return m.algo.String(), []byte(str), err
}

func (m *mechanism) Next(ctx context.Context, challenge []byte) (bool, []byte, error) {
	str, err := m.client.Step(string(challenge))
	return m.client.Done(), []byte(str), err
}
