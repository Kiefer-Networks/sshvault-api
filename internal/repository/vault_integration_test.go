package repository_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kiefernetworks/shellvault-server/internal/model"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
	"github.com/kiefernetworks/shellvault-server/internal/service"
)

func vaultTestPool(t *testing.T) (*pgxpool.Pool, uuid.UUID) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is required for PostgreSQL integration tests")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "vault_test_" + uuid.New().String()[:8]
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE"); admin.Close() })
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	for _, name := range []string{"001_users.up.sql", "004_vaults.up.sql", "007_vault_history.up.sql"} {
		sql, err := os.ReadFile(filepath.Join("..", "..", "migrations", name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Exec(ctx, string(sql)); err != nil {
			t.Fatal(err)
		}
	}
	uid := uuid.New()
	if _, err = pool.Exec(ctx, "INSERT INTO users (id,email,password) VALUES ($1,'vault@example.com','test')", uid); err != nil {
		t.Fatal(err)
	}
	return pool, uid
}

func TestVaultCreateDoesNotOverwriteExistingVersion(t *testing.T) {
	pool, uid := vaultTestPool(t)
	repo := repository.NewVaultRepository(pool)
	ctx := context.Background()
	if err := repo.Create(ctx, &model.Vault{UserID: uid, Version: 1, Blob: []byte("first"), Checksum: "a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.UpdateBlob(ctx, uid, 1, []byte("newer"), "b"); err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, &model.Vault{UserID: uid, Version: 1, Blob: []byte("stale"), Checksum: "c"}); err == nil {
		t.Error("stale creation must report a conflict")
	}
	got, err := repo.GetByUserID(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 2 || string(got.Blob) != "newer" {
		t.Fatalf("stale creation overwrote vault: %+v", got)
	}
}

func TestVaultMetadataDoesNotMaterializeBlob(t *testing.T) {
	pool, uid := vaultTestPool(t)
	repo := repository.NewVaultRepository(pool)
	ctx := context.Background()
	if err := repo.Create(ctx, &model.Vault{UserID: uid, Version: 1, Blob: make([]byte, service.MaxVaultSizeBytes), Checksum: "checksum"}); err != nil {
		t.Fatal(err)
	}

	metadata, err := repo.GetMetadataByUserID(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	if metadata == nil || metadata.ID == uuid.Nil || metadata.Version != 1 || metadata.Checksum != "checksum" {
		t.Fatalf("unexpected metadata: %+v", metadata)
	}
	if metadata.Blob != nil {
		t.Fatalf("metadata materialized %d blob bytes", len(metadata.Blob))
	}
}

type firstReadBarrier struct {
	repository.VaultRepository
	read sync.WaitGroup
}

func (r *firstReadBarrier) GetByUserID(ctx context.Context, uid uuid.UUID) (*model.Vault, error) {
	v, err := r.VaultRepository.GetByUserID(ctx, uid)
	if v == nil && err == nil {
		r.read.Done()
		r.read.Wait()
	}
	return v, err
}

func TestConcurrentFirstVaultSyncReturnsOneConflict(t *testing.T) {
	pool, uid := vaultTestPool(t)
	repo := &firstReadBarrier{VaultRepository: repository.NewVaultRepository(pool)}
	repo.read.Add(2)
	svc := service.NewVaultService(repo, repository.NewTransactor(pool), 15, 10)
	errs := make(chan error, 2)
	for _, blob := range []string{"first client", "second client"} {
		go func() {
			_, err := svc.PutVault(context.Background(), uid, &service.PutVaultRequest{Version: 1, Blob: []byte(blob), Checksum: fmt.Sprintf("%x", sha256.Sum256([]byte(blob)))})
			errs <- err
		}()
	}
	successes, conflicts := 0, 0
	for range 2 {
		err := <-errs
		if err == nil {
			successes++
		} else if _, ok := err.(*service.ConflictError); ok {
			conflicts++
		} else {
			t.Errorf("unexpected error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d; want one each", successes, conflicts)
	}
}

func TestVaultUpdatePreservesHistoryAndRollsBackOnHistoryFailure(t *testing.T) {
	pool, uid := vaultTestPool(t)
	repo := repository.NewVaultRepository(pool)
	svc := service.NewVaultService(repo, repository.NewTransactor(pool), 15, 10)
	ctx := context.Background()
	put := func(version int, blob string) error {
		_, err := svc.PutVault(ctx, uid, &service.PutVaultRequest{Version: version, Blob: []byte(blob), Checksum: fmt.Sprintf("%x", sha256.Sum256([]byte(blob)))})
		return err
	}
	if err := put(1, "first"); err != nil {
		t.Fatal(err)
	}
	if err := put(2, "second"); err != nil {
		t.Fatal(err)
	}
	history, err := svc.GetHistoryVersion(ctx, uid, 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(history.Blob) != "first" {
		t.Fatalf("history lost: %+v", history)
	}
	if _, err = pool.Exec(ctx, "ALTER TABLE vault_history ADD CONSTRAINT reject_new_history CHECK (version < 2)"); err != nil {
		t.Fatal(err)
	}
	if err := put(3, "third"); err == nil {
		t.Fatal("expected history insert failure")
	}
	got, err := repo.GetByUserID(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 2 || string(got.Blob) != "second" {
		t.Fatalf("failed history write did not roll back vault: %+v", got)
	}
}

func TestVault15MiBWritesPreserveLargerLegacyReadsAndHistory(t *testing.T) {
	pool, uid := vaultTestPool(t)
	ctx := context.Background()
	repo := repository.NewVaultRepository(pool)
	svc := service.NewVaultService(repo, repository.NewTransactor(pool), 15, 10)
	legacy := make([]byte, 16<<20)
	if err := repo.Create(ctx, &model.Vault{UserID: uid, Version: 1, Blob: legacy, Checksum: "legacy"}); err != nil {
		t.Fatal(err)
	}
	if v, err := svc.GetVault(ctx, uid); err != nil || len(v.Blob) != 16<<20 {
		t.Fatal("legacy vault became unreadable")
	}
	if _, err := svc.PutVault(ctx, uid, &service.PutVaultRequest{Version: 2, Blob: legacy, Checksum: "not evaluated"}); err == nil {
		t.Fatal("oversized replacement was accepted")
	}
	current, err := repo.GetByUserID(ctx, uid)
	if err != nil || current.Version != 1 || len(current.Blob) != 16<<20 {
		t.Fatal("rejected replacement changed legacy vault")
	}
	accepted := legacy[:15<<20]
	if _, err := svc.PutVault(ctx, uid, &service.PutVaultRequest{Version: 2, Blob: accepted, Checksum: fmt.Sprintf("%x", sha256.Sum256(accepted))}); err != nil {
		t.Fatal(err)
	}
	history, err := svc.GetHistoryVersion(ctx, uid, 1)
	if err != nil || len(history.Blob) != 16<<20 {
		t.Fatal("replacing with allowed size made legacy history unreadable")
	}
}
