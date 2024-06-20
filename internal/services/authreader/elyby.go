package authreader

import (
	"context"
	"crypto"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/patrickmn/go-cache"
)

const minecraftServerScope = "minecraft_server_session"
const cacheKey = "publicKeySet"

type claims struct {
	jwt.RegisteredClaims
	Scope string `json:"scope"`
}

type AccountsPublicKeyProvider interface {
	GetPublicKeys(ctx context.Context) ([]crypto.PublicKey, error)
}

type AccountsRepository interface {
	FindUuidById(ctx context.Context, id int) (string, error)
}

type ElybyJwtReader struct {
	publicKeyProvider AccountsPublicKeyProvider
	repository        AccountsRepository
	cache             *cache.Cache
}

func NewElyby(publicKeyProvider AccountsPublicKeyProvider, repository AccountsRepository) *ElybyJwtReader {
	return &ElybyJwtReader{
		publicKeyProvider: publicKeyProvider,
		repository:        repository,
		cache:             cache.New(time.Hour, 0),
	}
}

func (r *ElybyJwtReader) GetUuidFromAuthorizationHeader(ctx context.Context, authHeader string) (string, error) {
	userId, err := r.extractUserId(ctx, authHeader)
	if err != nil {
		return "", err
	}

	uuid, err := r.repository.FindUuidById(ctx, userId)
	if err != nil {
		return "", fmt.Errorf("unable to retrieve uuid by user id: %w", err)
	}

	if uuid == "" {
		return "", fmt.Errorf("unable to find uuid for user id %d", userId)
	}

	return uuid, nil
}

func (r *ElybyJwtReader) extractUserId(ctx context.Context, authHeader string) (int, error) {
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return 0, &unauthorizedError{msg: "authorization header has an invalid format"}
	}

	tokenStr := authHeader[7:] // trim "Bearer " part

	uncastedKeyset, found := r.cache.Get(cacheKey)
	if !found {
		jwtPublicKeys, err := r.publicKeyProvider.GetPublicKeys(ctx)
		if err != nil {
			return 0, fmt.Errorf("unable to retrieve accounts public keys; %w", err)
		}

		// I still don't understand why I can't just provide jwtPublicKeys directly to Keys,
		// so I have to typecast them one by one 🙃
		keyset := jwt.VerificationKeySet{
			Keys: make([]jwt.VerificationKey, len(jwtPublicKeys)),
		}
		for i, key := range jwtPublicKeys {
			keyset.Keys[i] = key
		}

		r.cache.SetDefault(cacheKey, keyset)
		uncastedKeyset = keyset
	}

	castedKeyset, _ := uncastedKeyset.(jwt.VerificationKeySet)

	token, err := jwt.ParseWithClaims(tokenStr, &claims{}, func(token *jwt.Token) (interface{}, error) {
		return castedKeyset, nil
	})
	if err != nil {
		return 0, &unauthorizedError{msg: "unable to parse or verify the provided token", err: err}
	}

	claims := token.Claims.(*claims)
	if !slices.Contains(strings.Split(claims.Scope, " "), minecraftServerScope) {
		return 0, &unauthorizedError{msg: "the token doesn't have the scope to perform the action", err: err}
	}

	sub, err := token.Claims.GetSubject()
	if err != nil {
		return 0, &unauthorizedError{msg: "unable to extract sub claim from the token", err: err}
	}

	if !strings.HasPrefix(sub, "ely|") {
		return 0, &unauthorizedError{msg: "invalid sub value"}
	}

	return strconv.Atoi(sub[4:])
}
