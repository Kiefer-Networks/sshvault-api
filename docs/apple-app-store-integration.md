# Apple App Store Server API v2 Integration

## Prerequisites

- Apple Developer Program membership
- App Store Connect access

## Setup Steps

### 1. Create Subscription in App Store Connect

1. Go to [App Store Connect](https://appstoreconnect.apple.com) > My Apps > Your App
2. Navigate to **Subscriptions** in the sidebar
3. Create a subscription group (e.g., "ShellVault Sync")
4. Add a subscription product with ID `shellvault_sync_yearly`
5. Configure pricing and localization

### 2. Generate API Key

1. In App Store Connect, go to **Users and Access** > **Integrations** > **In-App Purchase**
2. Click **Generate API Key**
3. Download the `.p8` key file (only available once)
4. Note the **Key ID** shown next to the key
5. Note your **Issuer ID** at the top of the page

### 3. Configure Server Notifications V2

1. In App Store Connect, go to your app > **App Information**
2. Under **App Store Server Notifications**, set:
   - **Production URL**: `https://api.sshvault.app/v1/webhooks/apple`
   - **Sandbox URL**: `https://api-sandbox.sshvault.app/v1/webhooks/apple`
   - **Version**: Version 2

### 4. Server Environment Variables

Set these in your `.env` or deployment configuration:

```
APPLE_KEY_PATH=/path/to/AuthKey_XXXXXXXXXX.p8
APPLE_KEY_ID=XXXXXXXXXX
APPLE_ISSUER_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
APPLE_BUNDLE_ID=com.kiefernetworks.shellvault
APPLE_ENVIRONMENT=production
```

- `APPLE_KEY_PATH`: Path to the downloaded `.p8` key file
- `APPLE_KEY_ID`: Key ID from App Store Connect
- `APPLE_ISSUER_ID`: Issuer ID from App Store Connect
- `APPLE_BUNDLE_ID`: Your app's bundle identifier
- `APPLE_ENVIRONMENT`: `production` or `sandbox`

### 5. Testing

#### Sandbox Testing

1. Create a sandbox tester account in App Store Connect > Users and Access > Sandbox > Test Accounts
2. Sign out of the App Store on your test device
3. Set `APPLE_ENVIRONMENT=sandbox` on your test server
4. Launch the app and initiate a purchase — the sandbox account will be prompted
5. Sandbox subscriptions auto-renew at accelerated rates (yearly = every hour)

#### Verifying Integration

- Check server logs for `Apple App Store billing enabled` on startup
- Test a purchase and verify the `/v1/billing/verify-apple` endpoint responds with `active: true`
- Check that webhook notifications arrive at `/v1/webhooks/apple`
- Run `shellvault-cli billing sync` to verify reconciliation works

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/v1/billing/verify-apple` | POST | Verify transaction and activate subscription |
| `/v1/webhooks/apple` | POST | Receive App Store Server Notifications V2 |

## References

- [App Store Server API](https://developer.apple.com/documentation/appstoreserverapi)
- [App Store Server Notifications V2](https://developer.apple.com/documentation/appstoreservernotifications)
- [Sandbox Testing](https://developer.apple.com/documentation/storekit/in-app_purchase/testing_in-app_purchases_with_sandbox)
