package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

func LoadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("examining key file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("key path must be a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("key file must not be accessible by group or other users")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}
	defer Zero(data)

	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	defer Zero(block.Bytes)

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}

	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519")
	}

	return edKey, nil
}

func GenerateEd25519Key() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("generating Ed25519 key: %w", err)
	}
	return priv, nil
}

func SaveEd25519PrivateKey(path string, key ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshaling private key: %w", err)
	}
	defer Zero(der)

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}

	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("creating keys directory: %w", err)
		}
	}

	encoded := pem.EncodeToMemory(block)
	defer Zero(encoded)
	temporary, err := os.CreateTemp(filepath.Dir(path), ".signing-key-*")
	if err != nil {
		return fmt.Errorf("creating key file: %w", err)
	}
	defer os.Remove(temporary.Name())
	if _, err = temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("writing key: %w", err)
	}
	if err = temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("syncing key: %w", err)
	}
	if err = temporary.Close(); err != nil {
		return fmt.Errorf("closing key: %w", err)
	}
	// Link publishes an already-synced file without replacing an existing path.
	if err = os.Link(temporary.Name(), path); err != nil {
		return fmt.Errorf("publishing key: %w", err)
	}
	if runtime.GOOS != "windows" {
		dir, err := os.Open(filepath.Dir(path))
		if err != nil {
			return err
		}
		defer dir.Close()
		if err = dir.Sync(); err != nil {
			return fmt.Errorf("syncing key directory: %w", err)
		}
	}
	return nil
}

// LoadOrCreateEd25519PrivateKey loads the server signing identity.
func LoadOrCreateEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	key, err := LoadEd25519PrivateKey(path)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key, err = GenerateEd25519Key()
	if err != nil {
		return nil, err
	}
	if err = SaveEd25519PrivateKey(path, key); err != nil {
		Zero(key)
		if errors.Is(err, os.ErrExist) {
			return LoadEd25519PrivateKey(path)
		}
		return nil, fmt.Errorf("persisting signing key: %w", err)
	}
	return key, nil
}
