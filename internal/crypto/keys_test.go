package crypto

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGenerateEd25519Key(t *testing.T) {
	key, err := GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	if len(key) != ed25519.PrivateKeySize {
		t.Errorf("key size = %d, want %d", len(key), ed25519.PrivateKeySize)
	}
}

func TestGenerateEd25519KeyUnique(t *testing.T) {
	k1, _ := GenerateEd25519Key()
	k2, _ := GenerateEd25519Key()
	if k1.Equal(k2) {
		t.Error("two generated keys should differ")
	}
}

func TestSaveAndLoadKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.key")

	key, err := GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}

	if err := SaveEd25519PrivateKey(path, key); err != nil {
		t.Fatalf("SaveEd25519PrivateKey: %v", err)
	}

	// Windows mode bits do not describe ACLs. Verify Unix permissions only;
	// the save/load round trip below still runs on every platform.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); runtime.GOOS != "windows" && perm != 0600 {
		t.Errorf("file permissions = %o, want 0600", perm)
	}

	loaded, err := LoadEd25519PrivateKey(path)
	if err != nil {
		t.Fatalf("LoadEd25519PrivateKey: %v", err)
	}

	if !key.Equal(loaded) {
		t.Error("loaded key does not match saved key")
	}
}

func TestSaveCreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "dir", "test.key")

	key, _ := GenerateEd25519Key()
	if err := SaveEd25519PrivateKey(path, key); err != nil {
		t.Fatalf("SaveEd25519PrivateKey with nested dir: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Errorf("file not created: %v", err)
	}
}

func TestLoadKeyNotFound(t *testing.T) {
	_, err := LoadEd25519PrivateKey("/nonexistent/path/key.pem")
	if err == nil {
		t.Error("expected error for missing key file")
	}
}

func TestLoadKeyInvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(path, []byte("not a pem file"), 0600); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	_, err := LoadEd25519PrivateKey(path)
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestSignAndVerifyWithSavedKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sign-test.key")

	key, err := GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	if err := SaveEd25519PrivateKey(path, key); err != nil {
		t.Fatalf("SaveEd25519PrivateKey: %v", err)
	}

	loaded, _ := LoadEd25519PrivateKey(path)

	message := []byte("test message")
	sig := ed25519.Sign(loaded, message)

	pub := loaded.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, message, sig) {
		t.Error("signature verification failed with loaded key")
	}
}

func TestKeyStartupDoesNotReplaceCorruptOrUnwritableState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "corrupt.pem")
	original := []byte("broken signing key")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if key, err := LoadOrCreateEd25519PrivateKey(path); err == nil || key != nil {
		t.Fatal("corrupt key was silently replaced")
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(original) {
		t.Fatal("corrupt key file changed")
	}
	if key, err := LoadOrCreateEd25519PrivateKey(filepath.Join(path, "missing.pem")); err == nil || key != nil {
		t.Fatal("startup accepted unsavable key")
	}
	if key, err := LoadOrCreateEd25519PrivateKey(dir); err == nil || key != nil {
		t.Fatal("startup accepted directory as a key")
	}
}
func TestKeyStartupCreatesOnceAndNeverOverwrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "key.pem")
	first, err := LoadOrCreateEd25519PrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateEd25519PrivateKey(path)
	if err != nil || !first.Equal(second) {
		t.Fatal("restart changed signing identity")
	}
	other, _ := GenerateEd25519Key()
	if err := SaveEd25519PrivateKey(path, other); err == nil {
		t.Fatal("save overwrote an existing signing key")
	}
	retained, err := LoadEd25519PrivateKey(path)
	if err != nil || !first.Equal(retained) {
		t.Fatal("existing key was not preserved")
	}
}
