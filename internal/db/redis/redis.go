package redis

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"log/slog"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
)

type Redis struct {
	client     *goredis.Client
	serializer PrivateKeySerializer
}

func New(addr string, serializer PrivateKeySerializer) *Redis {
	rdb := goredis.NewClient(&goredis.Options{
		Addr: addr,
	})

	return &Redis{rdb, serializer}
}

func NewWithConfig(config *viper.Viper) *Redis {
	config.SetDefault("db.redis.host", "localhost")
	config.SetDefault("db.redis.port", 6379)

	return New(fmt.Sprintf("%s:%d", config.GetString("db.redis.host"), config.GetInt("db.redis.port")), &PemPrivateKeySerializer{})
}

func (s *Redis) GetPrivateKeyForUuid(ctx context.Context, uuid string) (*rsa.PrivateKey, time.Time, error) {
	r := s.client.Get(ctx, redisKey(uuid))
	if errors.Is(r.Err(), goredis.Nil) {
		return nil, time.Time{}, nil
	} else if r.Err() != nil {
		return nil, time.Time{}, fmt.Errorf("unalbe to retrieve data from Redis: %w", r.Err())
	}

	bytes, _ := r.Bytes()
	privateKey, expiresAt, err := s.serializer.Deserialize(bytes)
	if err != nil {
		slog.WarnContext(
			ctx,
			"got corrupted data from Redis key that stores private key for user",
			slog.Any("err", err),
			slog.String("uuid", uuid),
			slog.Any("raw_bytes", bytes),
		)

		return nil, time.Time{}, nil
	}

	return privateKey, expiresAt, nil
}

func (s *Redis) StorePrivateKeyForUuid(ctx context.Context, uuid string, key *rsa.PrivateKey, expireAt time.Time) error {
	dataToStore, err := s.serializer.Serialize(key, expireAt)
	if err != nil {
		return fmt.Errorf("unable to serialize data: %w", err)
	}

	r := s.client.Set(ctx, redisKey(uuid), dataToStore, expireAt.Sub(time.Now()))
	if r.Err() != nil {
		return fmt.Errorf("unable to store data to Redis: %w", r.Err())
	}

	return nil
}

func (s *Redis) Ping(ctx context.Context) error {
	return s.client.Ping(ctx).Err()
}

func redisKey(uuid string) string {
	return fmt.Sprintf("profilecerts:private-keys:uuid:%s", uuid)
}
