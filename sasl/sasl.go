package sasl

import "context"

// todo : update docs, talk about ctx.
type Mechanism interface {
	// Begins SASL authentication with the server. It returns the
	// authentication mechanism name and "initial response" data (if required by
	// the selected mechanism). A non-nil error causes the client to abort the
	// authentication attempt.
	//
	// A nil ir value is different from a zero-length value. The nil value
	// indicates that the selected mechanism does not use an initial response,
	// while a zero-length value indicates an empty initial response, which must
	// be sent to the server.
	Start(ctx context.Context) (mech string, ir []byte, err error)

	// todo : need done?
	// Continues challenge-response authentication. A non-nil error causes
	// the client to abort the authentication attempt.
	Next(ctx context.Context, challenge []byte) (done bool, response []byte, err error)
}

// todo : test unsupported mechanism request.
// todo : build out test cases.
