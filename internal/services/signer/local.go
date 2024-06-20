package signer

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"

	"github.com/spf13/viper"
)

var randomReader = rand.Reader

type Local struct {
	key *rsa.PrivateKey
}

func NewLocalWithConfig(config *viper.Viper) (*Local, error) {
	var privateKey *rsa.PrivateKey
	var err error

	keyStr := config.GetString("signing.key")
	if keyStr == "" {
		privateKey, err = rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, err
		}

		slog.Warn("A private signing key has been generated. To make it permanent, specify the valid RSA private key in the config parameter signing.key")
	} else {
		keyBytes := []byte(keyStr)
		rawPem, _ := pem.Decode(keyBytes)
		if rawPem == nil {
			return nil, errors.New("unable to decode pem key")
		}

		privateKey, err = x509.ParsePKCS1PrivateKey(rawPem.Bytes)
		if err != nil {
			return nil, err
		}
	}

	return NewLocal(privateKey), nil
}

func NewLocal(key *rsa.PrivateKey) *Local {
	return &Local{key}
}

func (s *Local) Sign(ctx context.Context, data []byte) ([]byte, error) {
	messageHash := sha1.New()
	_, err := io.Copy(messageHash, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	messageHashSum := messageHash.Sum(nil)
	signature, err := rsa.SignPKCS1v15(randomReader, s.key, crypto.SHA1, messageHashSum)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func (s *Local) GetPublicKey(ctx context.Context) (*rsa.PublicKey, error) {
	return &s.key.PublicKey, nil
}
