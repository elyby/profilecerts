package certmanager

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"

	"ely.by/profilecerts/internal/http"
)

const keySize = 2048

var timeNow = time.Now
var randReader = rand.Reader
var certTtl = time.Hour * 48
var refreshWindow = time.Hour * 8

type KeysStorage interface {
	GetPrivateKeyForUuid(ctx context.Context, uuid string) (*rsa.PrivateKey, time.Time, error)
	StorePrivateKeyForUuid(ctx context.Context, uuid string, key *rsa.PrivateKey, expireAt time.Time) error
}

type Manager struct {
	KeysStorage
}

func New(keysStorage KeysStorage) *Manager {
	return &Manager{keysStorage}
}

func (m *Manager) GetKeypairForUser(ctx context.Context, uuid string) (*http.ProfileCertificate, error) {
	privateKey, expiresAt, err := m.KeysStorage.GetPrivateKeyForUuid(ctx, uuid)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve exists certificate for player's uuid: %w", err)
	}

	if privateKey == nil || expiresAt.Add(-refreshWindow).Before(timeNow()) {
		privateKey, err = rsa.GenerateKey(randReader, keySize)
		if err != nil {
			return nil, fmt.Errorf("unable to generate a new RSA private key: %w", err)
		}

		expiresAt = timeNow().Add(certTtl)
		err = m.KeysStorage.StorePrivateKeyForUuid(ctx, uuid, privateKey, expiresAt)
		if err != nil {
			return nil, fmt.Errorf("unable to store a newly generated private key: %w", err)
		}
	}

	return &http.ProfileCertificate{
		Key:       privateKey,
		ExpiresAt: expiresAt,
		RefreshAt: expiresAt.Add(-refreshWindow),
	}, nil
}
