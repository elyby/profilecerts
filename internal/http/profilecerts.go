package http

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	uuidLib "github.com/google/uuid"
	"github.com/muesli/reflow/wrap"

	"ely.by/profilecerts/internal/services/authreader"
)

type ProfileCertificate struct {
	Key       *rsa.PrivateKey
	ExpiresAt time.Time
	RefreshAt time.Time
}

type ProfileCertificatesService interface {
	GetKeypairForUser(ctx context.Context, uuid string) (*ProfileCertificate, error)
}

// Should return non-empty string when token parsed successfully
type AuthReader interface {
	GetUuidFromAuthorizationHeader(ctx context.Context, authHeader string) (string, error)
}

type SignerService interface {
	Sign(ctx context.Context, data []byte) ([]byte, error)
	GetPublicKey(ctx context.Context) (*rsa.PublicKey, error)
}

type ProfilesCertificatesApi struct {
	ProfileCertificatesService
	AuthReader
	SignerService
}

func NewProfileCertificatesApi(
	profilesCertificatesService ProfileCertificatesService,
	authReader AuthReader,
	signerService SignerService,
) *ProfilesCertificatesApi {
	return &ProfilesCertificatesApi{
		ProfileCertificatesService: profilesCertificatesService,
		AuthReader:                 authReader,
		SignerService:              signerService,
	}
}

func (s *ProfilesCertificatesApi) DefineRoutes(r gin.IRouter) {
	r.POST("/certificates", s.getCertificatesHandler)
	r.POST("/player/certificates", s.getCertificatesHandler)
	r.GET("/publickeys", s.getPublicKeysHandler)
}

// See https://wiki.vg/Mojang_API#Player_Certificates
func (s *ProfilesCertificatesApi) getCertificatesHandler(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.Status(http.StatusUnauthorized)
		return
	}

	uuid, err := s.AuthReader.GetUuidFromAuthorizationHeader(c.Request.Context(), authHeader)
	if err != nil {
		if authreader.IsUnauthorized(err) {
			c.Status(http.StatusUnauthorized)
		} else {
			c.Error(err)
		}

		return
	}

	profileCert, err := s.ProfileCertificatesService.GetKeypairForUser(c.Request.Context(), uuid)
	if err != nil {
		c.Error(fmt.Errorf("unable to retrieve a private key for user: %w", err))
		return
	}

	privateKeyPKCS8, _ := x509.MarshalPKCS8PrivateKey(profileCert.Key)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyPKCS8,
	}
	privateKeyPem := pem.EncodeToMemory(privateKeyBlock)

	publicKey := &profileCert.Key.PublicKey
	publicKeyPKIX, _ := x509.MarshalPKIXPublicKey(publicKey)
	publicKeyBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyPKIX,
	}
	publicKeyPem := pem.EncodeToMemory(publicKeyBlock)

	pkV1buf := make([]byte, 0, 512)
	pkV1buf = fmt.Appendf(pkV1buf, "%d", profileCert.ExpiresAt.UnixMilli())
	pkV1buf = append(pkV1buf, []byte("-----BEGIN RSA PUBLIC KEY-----\n")...)
	pkV1keyBuf := make([]byte, base64.StdEncoding.EncodedLen(len(publicKeyPKIX)))
	base64.StdEncoding.Encode(pkV1keyBuf, publicKeyPKIX)
	pkV1buf = append(pkV1buf, wrap.Bytes(pkV1keyBuf, 76)...)
	pkV1buf = append(pkV1buf, []byte("\n-----END RSA PUBLIC KEY-----\n")...)

	publicKeySignature, err := s.SignerService.Sign(c.Request.Context(), pkV1buf)
	if err != nil {
		c.Error(fmt.Errorf("unable to sign publicKeySignature: %w", err))
		return
	}

	parsedUuid := uuidLib.MustParse(uuid)

	pkV2buf := make([]byte, 0, len(publicKeyPKIX)+24)                                         // key length + 8 bytes * (2 uuid parts + timestamp)
	pkV2buf = binary.BigEndian.AppendUint64(pkV2buf, binary.BigEndian.Uint64(parsedUuid[:8])) // Most significant bits
	pkV2buf = binary.BigEndian.AppendUint64(pkV2buf, binary.BigEndian.Uint64(parsedUuid[8:])) // Least significant bits
	pkV2buf = binary.BigEndian.AppendUint64(pkV2buf, uint64(profileCert.ExpiresAt.UnixMilli()))
	pkV2buf = append(pkV2buf, publicKeyPKIX...)

	publicKeySignatureV2, err := s.SignerService.Sign(c.Request.Context(), pkV2buf)
	if err != nil {
		c.Error(fmt.Errorf("unable to sign publicKeySignatureV2: %w", err))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"keyPair": gin.H{
			"privateKey": string(privateKeyPem),
			"publicKey":  string(publicKeyPem),
		},
		"publicKeySignature":   publicKeySignature,
		"publicKeySignatureV2": publicKeySignatureV2,
		"expiresAt":            profileCert.ExpiresAt.UTC().Format(time.RFC3339Nano),
		"refreshedAfter":       profileCert.RefreshAt.UTC().Format(time.RFC3339Nano),
	})
}

func (s *ProfilesCertificatesApi) getPublicKeysHandler(c *gin.Context) {
	publicKey, err := s.SignerService.GetPublicKey(c.Request.Context())
	if err != nil {
		c.Error(fmt.Errorf("unable to retrieve global public signing key"))
		return
	}

	publicKeyPKIX, _ := x509.MarshalPKIXPublicKey(publicKey)

	c.JSON(http.StatusOK, gin.H{
		"profilePropertyKeys": []map[string][]byte{
			{
				"publicKey": publicKeyPKIX,
			},
		},
		"playerCertificateKeys": []map[string][]byte{
			{
				"publicKey": publicKeyPKIX,
			},
		},
	})
}
