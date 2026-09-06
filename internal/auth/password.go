package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/kiefernetworks/shellvault-server/internal/crypto"
	"golang.org/x/crypto/argon2"
)

const (
	argonMemory      = 256 * 1024 // 256 MiB (matching client v2)
	argonIterations  = 3
	argonParallelism = 1 // matching client v2
	argonSaltLen     = 16
	argonKeyLen      = 32
)

var argon2Slots = make(chan struct{}, 1)

func acquireArgon2(ctx context.Context) (func(), error) {
	select {
	case argon2Slots <- struct{}{}:
		return func() { <-argon2Slots }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func HashPassword(password string) (string, error) {
	return HashPasswordContext(context.Background(), password)
}

func HashPasswordContext(ctx context.Context, password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generating salt: %w", err)
	}

	release, err := acquireArgon2(ctx)
	if err != nil {
		return "", fmt.Errorf("waiting for password hashing capacity: %w", err)
	}
	defer release()
	hash := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonKeyLen)
	defer crypto.Zero(hash)

	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argonMemory,
		argonIterations,
		argonParallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
	return encoded, nil
}

func VerifyPassword(password, encoded string) (bool, error) {
	return VerifyPasswordContext(context.Background(), password, encoded)
}

func VerifyPasswordContext(ctx context.Context, password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return false, fmt.Errorf("invalid hash format")
	}

	var version int
	var memory uint32
	var iterations uint32
	var parallelism uint8

	n, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		return false, fmt.Errorf("parsing version: %w", err)
	}
	if n != 1 || parts[2] != fmt.Sprintf("v=%d", version) || version != argon2.Version {
		return false, fmt.Errorf("unsupported hash version")
	}

	n, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism)
	if err != nil {
		return false, fmt.Errorf("parsing params: %w", err)
	}
	if n != 3 || parts[3] != fmt.Sprintf("m=%d,t=%d,p=%d", memory, iterations, parallelism) {
		return false, fmt.Errorf("invalid hash parameters")
	}
	validV1 := memory == 64*1024 && iterations == 3 && parallelism == 4
	validV2 := memory == argonMemory && iterations == argonIterations && parallelism == argonParallelism
	if !validV1 && !validV2 {
		return false, fmt.Errorf("unsupported hash parameters")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("decoding salt: %w", err)
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("decoding hash: %w", err)
	}
	if len(salt) != argonSaltLen || len(expectedHash) != argonKeyLen {
		return false, fmt.Errorf("invalid hash dimensions")
	}

	release, err := acquireArgon2(ctx)
	if err != nil {
		return false, fmt.Errorf("waiting for password verification capacity: %w", err)
	}
	defer release()
	hash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(expectedHash)))
	defer crypto.Zero(hash)

	return subtle.ConstantTimeCompare(hash, expectedHash) == 1, nil
}
