package billing

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/kiefernetworks/shellvault-server/internal/model"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
)

// AppleProvider handles Apple App Store Server API v2 verification
// using direct HTTP calls with ES256-signed JWTs for authentication.
type AppleProvider struct {
	keyID       string
	issuerID    string
	bundleID    string
	environment string
	privateKey  *ecdsa.PrivateKey
	httpClient  *http.Client
	subRepo     repository.SubscriptionRepository
}

func NewAppleProvider(
	keyPath, keyID, issuerID, bundleID, environment string,
	subRepo repository.SubscriptionRepository,
) (*AppleProvider, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading apple p8 key: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM block in apple key file")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing apple private key: %w", err)
	}

	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("apple key is not ECDSA P-256")
	}

	if environment == "" {
		environment = "production"
	}

	return &AppleProvider{
		keyID:       keyID,
		issuerID:    issuerID,
		bundleID:    bundleID,
		environment: environment,
		privateKey:  ecKey,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
		subRepo:     subRepo,
	}, nil
}

func (p *AppleProvider) CreateCheckoutSession(_ context.Context, _, _ string) (string, error) {
	return "", fmt.Errorf("apple subscriptions are managed via the App Store")
}

func (p *AppleProvider) CreatePortalSession(_ context.Context, _ string) (string, error) {
	return "", fmt.Errorf("apple subscriptions are managed via the App Store")
}

func (p *AppleProvider) CancelSubscription(_ context.Context, _ string) error {
	return fmt.Errorf("apple subscriptions must be cancelled via the App Store")
}

// generateToken creates an ES256 JWT for authenticating against the
// App Store Server API v2.
func (p *AppleProvider) generateToken() (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": p.issuerID,
		"iat": now.Unix(),
		"exp": now.Add(20 * time.Minute).Unix(),
		"aud": "appstoreconnect-v1",
		"bid": p.bundleID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = p.keyID

	return token.SignedString(p.privateKey)
}

func (p *AppleProvider) apiBaseURL() string {
	if p.environment == "sandbox" {
		return "https://api.storekit-sandbox.itunes.apple.com"
	}
	return "https://api.storekit.itunes.apple.com"
}

// VerifyPurchase queries the App Store Server API for subscription status
// by original transaction ID.
func (p *AppleProvider) VerifyPurchase(ctx context.Context, transactionID string) (*AppleSubscriptionInfo, error) {
	token, err := p.generateToken()
	if err != nil {
		return nil, fmt.Errorf("generating apple api token: %w", err)
	}

	url := fmt.Sprintf("%s/inApps/v1/subscriptions/%s", p.apiBaseURL(), transactionID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling Apple API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("apple API error (HTTP %d): %s", resp.StatusCode, string(body))
	}

	// Response contains an array of subscription group status items,
	// each with a lastTransactions array of signed transactions.
	var apiResp appleSubscriptionStatusResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	// Find the most recent transaction across all subscription groups.
	for _, group := range apiResp.Data {
		for _, item := range group.LastTransactions {
			txInfo, err := p.decodeSignedTransaction(item.SignedTransactionInfo)
			if err != nil {
				log.Warn().Err(err).Msg("failed to decode signed transaction")
				continue
			}
			return &AppleSubscriptionInfo{
				Status:                item.Status,
				OriginalTransactionID: txInfo.OriginalTransactionID,
				ExpiresDate:           txInfo.ExpiresDate,
				PurchaseDate:          txInfo.PurchaseDate,
			}, nil
		}
	}

	return nil, fmt.Errorf("no subscription data found for transaction %s", transactionID)
}

// HandleWebhook processes Apple App Store Server Notifications V2.
// The payload contains a signedPayload field which is a JWS with the
// notification body. The x5c certificate chain is verified against
// the embedded Apple Root CA G3.
func (p *AppleProvider) HandleWebhook(ctx context.Context, payload, _ string) error {
	var envelope appleNotificationEnvelope
	if err := json.Unmarshal([]byte(payload), &envelope); err != nil {
		return fmt.Errorf("parsing notification envelope: %w", err)
	}

	notifPayload, err := p.verifyAndDecodeJWS(envelope.SignedPayload)
	if err != nil {
		return fmt.Errorf("verifying notification JWS: %w", err)
	}

	var notification appleNotificationV2
	if err := json.Unmarshal(notifPayload, &notification); err != nil {
		return fmt.Errorf("parsing notification: %w", err)
	}

	log.Info().
		Str("type", notification.NotificationType).
		Str("subtype", notification.Subtype).
		Msg("processing Apple notification")

	// Decode the signed transaction from the notification data.
	if notification.Data.SignedTransactionInfo == "" {
		log.Info().Msg("Apple notification without transaction info, skipping")
		return nil
	}

	txInfo, err := p.decodeSignedTransaction(notification.Data.SignedTransactionInfo)
	if err != nil {
		return fmt.Errorf("decoding transaction from notification: %w", err)
	}

	// Look up subscription by originalTransactionId.
	sub, err := p.subRepo.GetByProviderSubID(ctx, txInfo.OriginalTransactionID)
	if err != nil || sub == nil {
		log.Warn().
			Str("original_transaction_id", txInfo.OriginalTransactionID).
			Msg("Apple webhook for unknown subscription, skipping")
		return nil
	}

	// Map notification type to status.
	newStatus := mapAppleNotificationType(notification.NotificationType, notification.Subtype)
	if newStatus != "" && newStatus != sub.Status {
		sub.Status = newStatus
		if txInfo.ExpiresDate > 0 {
			t := time.UnixMilli(txInfo.ExpiresDate)
			sub.CurrentPeriodEnd = &t
		}
		if txInfo.PurchaseDate > 0 {
			t := time.UnixMilli(txInfo.PurchaseDate)
			sub.CurrentPeriodStart = &t
		}
		if err := p.subRepo.Update(ctx, sub); err != nil {
			return fmt.Errorf("updating subscription: %w", err)
		}
		log.Info().
			Str("sub_id", sub.ID.String()).
			Str("new_status", newStatus).
			Msg("updated Apple subscription status via webhook")
	}

	return nil
}

// VerifyAndUpsert verifies a transaction against the Apple API and
// creates or updates the subscription in the database for the given user.
func (p *AppleProvider) VerifyAndUpsert(ctx context.Context, userID uuid.UUID, transactionID string) (*model.Subscription, error) {
	info, err := p.VerifyPurchase(ctx, transactionID)
	if err != nil {
		return nil, fmt.Errorf("verifying purchase: %w", err)
	}

	status := MapAppleSubscriptionStatus(info.Status)
	origTxID := info.OriginalTransactionID
	if origTxID == "" {
		origTxID = transactionID
	}

	existing, _ := p.subRepo.GetByUserID(ctx, userID)

	if existing != nil {
		existing.Provider = "apple"
		existing.ProviderSubID = origTxID
		existing.Status = status
		if info.PurchaseDate > 0 {
			t := time.UnixMilli(info.PurchaseDate)
			existing.CurrentPeriodStart = &t
		}
		if info.ExpiresDate > 0 {
			t := time.UnixMilli(info.ExpiresDate)
			existing.CurrentPeriodEnd = &t
		}
		if err := p.subRepo.Update(ctx, existing); err != nil {
			return nil, fmt.Errorf("updating subscription: %w", err)
		}
		return existing, nil
	}

	sub := &model.Subscription{
		ID:            uuid.New(),
		UserID:        userID,
		Provider:      "apple",
		ProviderSubID: origTxID,
		Status:        status,
	}
	if info.PurchaseDate > 0 {
		t := time.UnixMilli(info.PurchaseDate)
		sub.CurrentPeriodStart = &t
	}
	if info.ExpiresDate > 0 {
		t := time.UnixMilli(info.ExpiresDate)
		sub.CurrentPeriodEnd = &t
	}
	if err := p.subRepo.Create(ctx, sub); err != nil {
		return nil, fmt.Errorf("creating subscription: %w", err)
	}

	return sub, nil
}

// ============================================================
// JWS VERIFICATION
// ============================================================

// verifyAndDecodeJWS verifies a JWS token from Apple using the x5c
// certificate chain and returns the decoded payload.
func (p *AppleProvider) verifyAndDecodeJWS(jws string) ([]byte, error) {
	parts := strings.SplitN(jws, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWS format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decoding JWS header: %w", err)
	}

	var header struct {
		Alg string   `json:"alg"`
		X5c []string `json:"x5c"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("parsing JWS header: %w", err)
	}

	if len(header.X5c) == 0 {
		return nil, fmt.Errorf("x5c chain missing from JWS header")
	}

	// Parse all certificates in the chain.
	certs := make([]*x509.Certificate, len(header.X5c))
	for i, certB64 := range header.X5c {
		certDER, err := base64.StdEncoding.DecodeString(certB64)
		if err != nil {
			return nil, fmt.Errorf("decoding x5c cert %d: %w", i, err)
		}
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, fmt.Errorf("parsing x5c cert %d: %w", i, err)
		}
		certs[i] = cert
	}

	// Verify the chain against Apple Root CA G3.
	rootCA, err := appleRootCAG3()
	if err != nil {
		return nil, fmt.Errorf("loading Apple Root CA G3: %w", err)
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCA)

	intermediatePool := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediatePool.AddCert(cert)
	}

	if _, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
		CurrentTime:   time.Now(),
	}); err != nil {
		return nil, fmt.Errorf("x5c chain verification failed: %w", err)
	}

	// Verify the JWS signature using the leaf certificate's public key.
	token, err := jwt.Parse(jws, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return certs[0].PublicKey, nil
	}, jwt.WithValidMethods([]string{"ES256"}))
	if err != nil {
		return nil, fmt.Errorf("verifying JWS signature: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid JWS token")
	}

	// Return raw payload bytes.
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding JWS payload: %w", err)
	}

	return payload, nil
}

// decodeSignedTransaction decodes a signed transaction JWS from Apple.
func (p *AppleProvider) decodeSignedTransaction(signedTx string) (*appleTransactionInfo, error) {
	payload, err := p.verifyAndDecodeJWS(signedTx)
	if err != nil {
		return nil, fmt.Errorf("verifying signed transaction: %w", err)
	}

	var txInfo appleTransactionInfo
	if err := json.Unmarshal(payload, &txInfo); err != nil {
		return nil, fmt.Errorf("parsing transaction info: %w", err)
	}

	return &txInfo, nil
}

// ============================================================
// APPLE API TYPES
// ============================================================

// AppleSubscriptionInfo is the normalized view of an Apple subscription.
type AppleSubscriptionInfo struct {
	Status                int
	OriginalTransactionID string
	ExpiresDate           int64
	PurchaseDate          int64
}

type appleSubscriptionStatusResponse struct {
	Data        []appleSubscriptionGroupStatus `json:"data"`
	BundleID    string                         `json:"bundleId"`
	AppAppleID  int64                          `json:"appAppleId"`
	Environment string                         `json:"environment"`
}

type appleSubscriptionGroupStatus struct {
	SubscriptionGroupIdentifier string                    `json:"subscriptionGroupIdentifier"`
	LastTransactions            []appleLastTransactionItem `json:"lastTransactions"`
}

type appleLastTransactionItem struct {
	Status                int    `json:"status"`
	OriginalTransactionID string `json:"originalTransactionId"`
	SignedTransactionInfo string `json:"signedTransactionInfo"`
	SignedRenewalInfo     string `json:"signedRenewalInfo"`
}

type appleTransactionInfo struct {
	TransactionID         string `json:"transactionId"`
	OriginalTransactionID string `json:"originalTransactionId"`
	BundleID              string `json:"bundleId"`
	ProductID             string `json:"productId"`
	PurchaseDate          int64  `json:"purchaseDate"`
	ExpiresDate           int64  `json:"expiresDate"`
	Type                  string `json:"type"`
	InAppOwnershipType    string `json:"inAppOwnershipType"`
	Environment           string `json:"environment"`
}

type appleNotificationEnvelope struct {
	SignedPayload string `json:"signedPayload"`
}

type appleNotificationV2 struct {
	NotificationType string                  `json:"notificationType"`
	Subtype          string                  `json:"subtype"`
	Data             appleNotificationV2Data `json:"data"`
	Version          string                  `json:"version"`
	SignedDate       int64                   `json:"signedDate"`
}

type appleNotificationV2Data struct {
	AppAppleID            int64  `json:"appAppleId"`
	BundleID              string `json:"bundleId"`
	BundleVersion         string `json:"bundleVersion"`
	Environment           string `json:"environment"`
	SignedTransactionInfo string `json:"signedTransactionInfo"`
	SignedRenewalInfo     string `json:"signedRenewalInfo"`
}

// ============================================================
// STATUS MAPPING
// ============================================================

// Apple Subscription Status values (from Get All Subscription Statuses API).
const (
	appleStatusActive       = 1
	appleStatusExpired      = 2
	appleStatusBillingRetry = 3
	appleStatusGracePeriod  = 4
	appleStatusRevoked      = 5
)

// MapAppleSubscriptionStatus maps Apple subscription status codes to ShellVault status strings.
func MapAppleSubscriptionStatus(status int) string {
	switch status {
	case appleStatusActive, appleStatusGracePeriod:
		return model.SubStatusActive
	case appleStatusExpired:
		return model.SubStatusExpired
	case appleStatusBillingRetry:
		return model.SubStatusPastDue
	case appleStatusRevoked:
		return model.SubStatusCanceled
	default:
		return model.SubStatusCanceled
	}
}

// mapAppleNotificationType maps V2 notification types to ShellVault status.
func mapAppleNotificationType(notifType, subtype string) string {
	switch notifType {
	case "SUBSCRIBED", "DID_RENEW":
		return model.SubStatusActive
	case "EXPIRED":
		return model.SubStatusExpired
	case "DID_FAIL_TO_RENEW":
		return model.SubStatusPastDue
	case "GRACE_PERIOD_EXPIRED":
		return model.SubStatusExpired
	case "REVOKE":
		return model.SubStatusCanceled
	case "DID_CHANGE_RENEWAL_STATUS":
		if subtype == "AUTO_RENEW_DISABLED" {
			return model.SubStatusCanceled
		}
		return model.SubStatusActive
	case "REFUND":
		return model.SubStatusCanceled
	default:
		return ""
	}
}

// ============================================================
// APPLE ROOT CA G3
// ============================================================

var (
	appleRootCAG3Once sync.Once
	appleRootCAG3Cert *x509.Certificate
	appleRootCAG3Err  error
)

// appleRootCAG3 returns the Apple Root CA - G3 certificate used to
// verify the x5c certificate chain in JWS tokens from the App Store
// Server API and Server Notifications V2.
// The certificate is parsed once and cached for subsequent calls.
func appleRootCAG3() (*x509.Certificate, error) {
	appleRootCAG3Once.Do(func() {
		block, _ := pem.Decode([]byte(appleRootCAG3PEM))
		if block == nil {
			appleRootCAG3Err = fmt.Errorf("failed to decode Apple Root CA G3 PEM")
			return
		}
		appleRootCAG3Cert, appleRootCAG3Err = x509.ParseCertificate(block.Bytes)
	})
	return appleRootCAG3Cert, appleRootCAG3Err
}

// Apple Root CA - G3 (valid until 2039-02-20).
// Source: https://www.apple.com/certificateauthority/
const appleRootCAG3PEM = `-----BEGIN CERTIFICATE-----
MIICQzCCAcmgAwIBAgIILcX8iNLFS5UwCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwS
QXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9u
IEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcN
MTQwNDMwMTgxOTA2WhcNMzkwNDMwMTgxOTA2WjBnMRswGQYDVQQDDBJBcHBsZSBS
b290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9y
aXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzB2MBAGByqGSM49
AgEGBSuBBAAiA2IABJjpLz1AcqTtkyJygRMc3RCV8cWjTnHcFBbZDuWmBSp3ZHtf
TjjTuxxEtX/1H7YyYl3J6YRbTzBPEVoA/VhYDKX1DyxNB0cTddqXl5dvMVztK515
1Du8SL0tVOY625TYQKNjMGEwHQYDVR0OBBYEFLuw3GKHGVMhjnkEWM3wFI0GMEMG
A1UdIwQcMBqAFLuw3GKHGVMhjnkEWM3wFI0GMEMGDwYDVR0TAQH/BAUwAwEB/zAO
BgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaAAwZQIxAIPpwcQWCIaonMRBIgWk
OiPBLKTEvXY/g1vrmBdK2kCknks/+DBZYBKnJMsHfJBhEAIwZpiB2qr7hAjgKBhF
OecfrtJGTJGiqThEC3d/KBHvkJWQ55Y6v1hp1NKjNwNj2K3c
-----END CERTIFICATE-----`
