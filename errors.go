package macdaddy

// Error represents one of the errors that can occur
type Error uint8

// Error implements the error interface
func (e Error) Error() string {
	switch e {
	case ErrUnknownEpoch:
		return "macdaddy: unknown authentication epoch"
	}
	return "macdaddy: message authentication failed"
}

const (
	// ErrBadToken means the provided token is not a MAC (e.g. too short)
	ErrBadToken Error = iota
	// ErrUnknownTerm occurs when the MAC epoch is unknown
	ErrUnknownEpoch
)
