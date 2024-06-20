package redis

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"strconv"
	"time"
)

type PrivateKeySerializer interface {
	Serialize(key *rsa.PrivateKey, expiresAt time.Time) ([]byte, error)
	Deserialize(value []byte) (*rsa.PrivateKey, time.Time, error)
}

const unixNanoTimestampLen = 19 // E.g. 1718839756442011388 - 19 characters

type PemPrivateKeySerializer struct{}

func (s *PemPrivateKeySerializer) Serialize(key *rsa.PrivateKey, expiresAt time.Time) ([]byte, error) {
	return fmt.Appendf(nil, "%d%s", expiresAt.UnixNano(), x509.MarshalPKCS1PrivateKey(key)), nil
}

func (s *PemPrivateKeySerializer) Deserialize(value []byte) (*rsa.PrivateKey, time.Time, error) {
	if len(value) < unixNanoTimestampLen+1 {
		return nil, time.Time{}, errors.New("the value is too short")
	}

	timeBytes := value[:unixNanoTimestampLen]
	keyPem := value[unixNanoTimestampLen:]

	timePart, err := strconv.ParseInt(string(timeBytes), 10, 64)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("the timestamp could not be parsed: %w", err)
	}

	expiresAt := time.Unix(0, timePart)

	privateKey, err := x509.ParsePKCS1PrivateKey(keyPem)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("the private key could not be parsed: %w", err)
	}

	return privateKey, expiresAt, nil
}
