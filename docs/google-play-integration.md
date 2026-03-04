# Google Play Billing Integration

This document describes the current state, required changes, and implementation steps for full Google Play Billing integration in ShellVault.

## Current State

### What exists

| Component | File | Status |
|-----------|------|--------|
| Provider stub | `internal/billing/google.go` | Stub — all methods return errors or log TODOs |
| Webhook route | `POST /v1/webhooks/google` | Registered in `cmd/server/main.go` |
| Webhook handler | `internal/handler/billing_handler.go` | Reads body, delegates to provider, always returns 200 |
| Config field | `GOOGLE_SERVICE_ACCOUNT_PATH` | Loaded via envconfig but never used |
| DB model | `internal/model/subscription.go` | Provider-agnostic, supports `provider = "google"` |
| Subscription repo | `internal/repository/subscription_repo.go` | Full CRUD, provider-agnostic |
| Audit action | `internal/audit/model.go` | `ActWebhookGoogle` defined |
| OpenAPI spec | `api/openapi.yaml` | Endpoint documented |
| Account deletion | `internal/service/user_service.go` | Sets Google subs to `canceled` in DB |
| CLI | `cmd/cli/billing.go` | Can create `--provider google` subs manually |
| Client IAP plugin | `pubspec.yaml` | `in_app_purchase: ^3.2.0` |
| Client platform detection | `lib/core/utils/platform_utils.dart` | `isNativeIapPlatform` returns `true` on Android |
| Client billing status | `lib/features/account/domain/entities/billing_status.dart` | Supports `provider: 'google'` |
| Client UI | `lib/features/settings/presentation/screens/account_sync_screen.dart` | Shows Google Play management link |

### What is missing

| Component | Impact |
|-----------|--------|
| Provider not instantiated in `cmd/server/main.go` | Google webhooks are processed by whichever provider is active (Stripe or Noop) |
| No RTDN parsing in `GoogleProvider.HandleWebhook` | Webhook notifications are silently ignored |
| No Google Play Developer API calls | Server never verifies subscription status |
| No Pub/Sub signature verification | Any request to `/v1/webhooks/google` is accepted |
| No client-side subscription purchase flow | Client only has consumable IAP (support), no subscription purchase |
| No receipt verification endpoint | Client cannot send purchase tokens to server for verification |
| `billing sync` CLI has no Google support | Only logs a warning |

## Architecture

```
Android App                    Google Play                   ShellVault Server
    |                              |                              |
    |--- buySubscription() ------->|                              |
    |<-- PurchaseDetails ---------|                              |
    |                              |                              |
    |--- POST /v1/billing/verify-google ----------------------->|
    |    { purchaseToken, productId }                            |
    |                              |                              |
    |                              |<-- purchases.subscriptionsv2.get --|
    |                              |--- subscription status ---------->|
    |                              |                              |
    |<-- { active: true } ----------------------------------------|
    |                              |                              |
    |                              |--- Pub/Sub RTDN ----------->|
    |                              |    POST /v1/webhooks/google  |
    |                              |                              |
```

## Implementation Steps

### Step 1: Google Cloud Setup (Prerequisites)

1. **Google Play Console**: Create the subscription product (e.g. `shellvault_sync_monthly`)
2. **Google Cloud Console**:
   - Enable "Google Play Android Developer API"
   - Create a Service Account with "Viewer" role
   - Download the JSON key file
   - Grant the Service Account access in Google Play Console (Settings > API access)
3. **Real-Time Developer Notifications (RTDN)**:
   - Create a Pub/Sub topic (e.g. `shellvault-subscriptions`)
   - Create a push subscription pointing to `https://api.example.com/v1/webhooks/google`
   - Link the topic in Google Play Console (Monetization setup > Real-time developer notifications)

### Step 2: Server — Google Play Developer API Client

**File:** `internal/billing/google.go`

**Dependency:** `google.golang.org/api/androidpublisher/v3`

```bash
go get google.golang.org/api/androidpublisher/v3
go get google.golang.org/api/option
```

Required changes to `GoogleProvider`:

```go
type GoogleProvider struct {
    packageName string
    service     *androidpublisher.Service
    subRepo     repository.SubscriptionRepository
}

func NewGoogleProvider(
    serviceAccountPath string,
    packageName string,
    subRepo repository.SubscriptionRepository,
) (*GoogleProvider, error) {
    ctx := context.Background()
    data, err := os.ReadFile(serviceAccountPath)
    if err != nil {
        return nil, fmt.Errorf("reading service account: %w", err)
    }
    svc, err := androidpublisher.NewService(ctx,
        option.WithCredentialsJSON(data),
    )
    if err != nil {
        return nil, fmt.Errorf("creating androidpublisher service: %w", err)
    }
    return &GoogleProvider{
        packageName: packageName,
        service:     svc,
        subRepo:     subRepo,
    }, nil
}
```

### Step 3: Server — Verify Purchase Token

Add a new method to `GoogleProvider` (not part of the `Provider` interface — called directly):

```go
func (p *GoogleProvider) VerifyPurchase(ctx context.Context, productID, purchaseToken string) (*androidpublisher.SubscriptionPurchaseV2, error) {
    return p.service.Purchases.Subscriptionsv2.Get(
        p.packageName, purchaseToken,
    ).Context(ctx).Do()
}
```

### Step 4: Server — New Endpoint `POST /v1/billing/verify-google`

**File:** `internal/handler/billing_handler.go`

New handler that:
1. Reads `{ "purchase_token": "...", "product_id": "..." }` from the authenticated user
2. Calls `GoogleProvider.VerifyPurchase()`
3. Maps the Google subscription state to internal status
4. Creates or updates the subscription in DB with `provider = "google"`
5. Returns `BillingStatus`

Google subscription state mapping:

| Google `SubscriptionState` | ShellVault Status |
|---------------------------|-------------------|
| `SUBSCRIPTION_STATE_ACTIVE` | `active` |
| `SUBSCRIPTION_STATE_CANCELED` | `canceled` |
| `SUBSCRIPTION_STATE_IN_GRACE_PERIOD` | `active` |
| `SUBSCRIPTION_STATE_ON_HOLD` | `past_due` |
| `SUBSCRIPTION_STATE_PAUSED` | `canceled` |
| `SUBSCRIPTION_STATE_EXPIRED` | `expired` |

**Route registration** in `cmd/server/main.go`:

```go
r.Post("/billing/verify-google", billingHandler.VerifyGoogle)
```

### Step 5: Server — Webhook (RTDN) Processing

**File:** `internal/billing/google.go`

Implement `HandleWebhook`:

1. Decode the Pub/Sub push message (base64 JSON envelope)
2. Extract `DeveloperNotification` → `SubscriptionNotification`
3. Use `purchaseToken` from the notification to call `VerifyPurchase()`
4. Update subscription status in DB based on the response

RTDN notification types to handle:

| NotificationType | Action |
|-----------------|--------|
| `SUBSCRIPTION_PURCHASED` | Create/activate subscription |
| `SUBSCRIPTION_RENEWED` | Update period, keep active |
| `SUBSCRIPTION_CANCELED` | Set status to `canceled` |
| `SUBSCRIPTION_EXPIRED` | Set status to `expired` |
| `SUBSCRIPTION_ON_HOLD` | Set status to `past_due` |
| `SUBSCRIPTION_IN_GRACE_PERIOD` | Keep `active`, log warning |
| `SUBSCRIPTION_REVOKED` | Set status to `expired` |
| `SUBSCRIPTION_RECOVERED` | Reactivate to `active` |

Pub/Sub push message format:

```json
{
  "message": {
    "data": "<base64-encoded DeveloperNotification>",
    "messageId": "...",
    "publishTime": "..."
  },
  "subscription": "projects/.../subscriptions/..."
}
```

### Step 6: Server — Wire Up in main.go

**File:** `cmd/server/main.go`

Currently only Stripe is wired. Change to support multiple providers:

```go
var billingProvider billing.Provider
var googleProvider *billing.GoogleProvider

if cfg.Billing.Enabled() {
    billingProvider = billing.NewStripeProvider(...)
} else {
    billingProvider = billing.NewNoopProvider()
}

if cfg.Billing.GoogleServiceAcctPath != "" {
    gp, err := billing.NewGoogleProvider(
        cfg.Billing.GoogleServiceAcctPath,
        cfg.Billing.GooglePackageName,   // new config field
        subRepo,
    )
    if err != nil {
        log.Fatal().Err(err).Msg("failed to init Google provider")
    }
    googleProvider = gp
}
```

The webhook handler needs access to the Google provider specifically, since the `Provider` interface routes all webhooks through a single provider. Consider either:
- **Option A:** Add a provider registry (`map[string]billing.Provider`) to `BillingService`
- **Option B:** Pass `googleProvider` directly to `BillingHandler` for the verify endpoint

### Step 7: Server — Config

**File:** `internal/config/config.go`

Add to `BillingConfig`:

```go
GooglePackageName string `envconfig:"GOOGLE_PACKAGE_NAME"`
```

**File:** `.env.example`

```
GOOGLE_SERVICE_ACCOUNT_PATH=
GOOGLE_PACKAGE_NAME=de.kiefernetworks.shellvault
```

### Step 8: Client — Subscription Purchase Flow

**File:** `lib/features/account/presentation/providers/subscription_purchase_provider.dart` (new)

Create a Riverpod provider that:
1. Loads the subscription product via `InAppPurchase.instance.queryProductDetails({'shellvault_sync_monthly'})`
2. Initiates purchase via `InAppPurchase.instance.buyNonConsumable(purchaseParam)`
3. Listens to the purchase stream
4. On `PurchaseStatus.purchased`: sends `purchaseToken` + `productId` to `POST /v1/billing/verify-google`
5. On success: invalidates `billingStatusProvider` to refresh UI

### Step 9: Client — API Call

**File:** `lib/features/account/data/repositories/account_repository_impl.dart`

Add method:

```dart
Future<Result<BillingStatus>> verifyGooglePurchase({
  required String purchaseToken,
  required String productId,
}) async {
  final response = await _api.post('/v1/billing/verify-google', data: {
    'purchase_token': purchaseToken,
    'product_id': productId,
  });
  return Result.success(BillingStatus.fromJson(response.data));
}
```

### Step 10: Client — UI Integration

**File:** `lib/features/settings/presentation/screens/account_sync_screen.dart`

On Android (when `isNativeIapPlatform && Platform.isAndroid`):
- Replace the Stripe checkout flow with the IAP purchase flow
- "Activate Sync" button triggers the subscription purchase provider
- After purchase, poll `billingStatusProvider` (existing logic)

### Step 11: CLI — billing sync for Google

**File:** `cmd/cli/billing.go`

In `billingSyncCmd`, add Google reconciliation:

```go
if googleProvider != nil && googleCount > 0 {
    // For each active Google sub, verify via API
    // Similar to reconcileStripe but using GoogleProvider.VerifyPurchase
}
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GOOGLE_SERVICE_ACCOUNT_PATH` | Yes | Path to Google Cloud service account JSON |
| `GOOGLE_PACKAGE_NAME` | Yes | Android package name (`de.kiefernetworks.shellvault`) |

## Testing

### Server

1. Unit test `GoogleProvider.VerifyPurchase` with mocked HTTP transport
2. Test webhook payload parsing with sample RTDN messages
3. Test subscription state mapping for all notification types
4. Integration test: verify endpoint creates/updates subscription

### Client

1. Test purchase flow on a physical Android device (IAP does not work on emulators)
2. Use Google Play Console test tracks (internal/closed) for testing
3. Test license testing accounts for free test purchases
4. Verify polling picks up the activated subscription after verification

### End-to-End

1. Install app from internal test track
2. Purchase subscription with test account
3. Verify server receives purchase token and activates subscription
4. Verify RTDN webhook fires on renewal/cancellation
5. Cancel via Google Play > verify server updates status
6. Run `billing sync` > verify Google subs are checked

## File Summary

### Server Changes

| File | Change |
|------|--------|
| `internal/billing/google.go` | Full implementation with Android Publisher API |
| `internal/config/config.go` | Add `GOOGLE_PACKAGE_NAME` |
| `cmd/server/main.go` | Instantiate `GoogleProvider`, wire to handler |
| `internal/handler/billing_handler.go` | New `VerifyGoogle` endpoint |
| `internal/service/billing_service.go` | Provider registry or direct Google provider access |
| `cmd/cli/billing.go` | Google sync in `billing sync` |
| `go.mod` | Add `google.golang.org/api` dependency |
| `.env.example` | Add `GOOGLE_PACKAGE_NAME` |

### Client Changes

| File | Change |
|------|--------|
| `lib/features/account/data/repositories/account_repository_impl.dart` | `verifyGooglePurchase()` API call |
| `lib/features/account/domain/repositories/account_repository.dart` | Interface method |
| `lib/features/account/presentation/providers/` | New subscription purchase provider |
| `lib/features/settings/presentation/screens/account_sync_screen.dart` | Android IAP flow |
| `lib/features/sync/presentation/screens/sync_settings_screen.dart` | Same IAP flow |
