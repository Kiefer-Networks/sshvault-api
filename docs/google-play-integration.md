# Google Play Billing — Setup Guide

Server and client code for Google Play Billing is fully implemented. This guide covers the external setup steps required to activate it.

## Prerequisites

- [Google Play Console](https://play.google.com/console) account with a published app
- [Google Cloud Console](https://console.cloud.google.com) project linked to the Play Console

## 1. Create the Subscription Product

1. Open [Google Play Console](https://play.google.com/console) → your app → **Monetize** → **Subscriptions**
2. Create a new subscription with product ID: `shellvault_sync_yearly`
3. Add a base plan (e.g. yearly, auto-renewing)
4. Set the price (e.g. €12.99/year)
5. Activate the subscription

Reference: [Create a subscription](https://support.google.com/googleplay/android-developer/answer/140504)

## 2. Create a Service Account

1. Open [Google Cloud Console](https://console.cloud.google.com) → **IAM & Admin** → **Service Accounts**
2. Create a new service account (e.g. `shellvault-billing`)
3. Grant the role **Viewer** (or no role — Play Console handles permissions)
4. Create a JSON key and download it
5. Place the key on your server (e.g. `/etc/shellvault/google-sa.json`)

Reference: [Create service account](https://cloud.google.com/iam/docs/service-accounts-create)

## 3. Grant Play Console API Access

1. Open [Google Play Console](https://play.google.com/console) → **Settings** → **API access**
2. Link the Google Cloud project
3. Find the service account and click **Manage Play Console permissions**
4. Grant **Financial data** → *View financial data, orders, and cancellation survey responses*
5. Apply to your app

Reference: [API access](https://support.google.com/googleplay/android-developer/answer/9844686)

## 4. Enable the Android Publisher API

1. Open [Google Cloud Console](https://console.cloud.google.com) → **APIs & Services** → **Library**
2. Search for **Google Play Android Developer API**
3. Click **Enable**

Reference: [Enable API](https://console.cloud.google.com/apis/library/androidpublisher.googleapis.com)

## 5. Set Up Real-Time Developer Notifications (RTDN)

RTDN delivers subscription status changes to your server via Cloud Pub/Sub.

1. Open [Google Cloud Console](https://console.cloud.google.com) → **Pub/Sub** → **Topics**
2. Create a topic (e.g. `shellvault-subscriptions`)
3. Create a **push subscription** for the topic:
   - Endpoint URL: `https://your-api-domain.com/v1/webhooks/google`
   - Acknowledgement deadline: 30 seconds
4. Open [Google Play Console](https://play.google.com/console) → your app → **Monetize** → **Monetization setup**
5. Under **Real-time developer notifications**, set the topic name (e.g. `projects/your-project/topics/shellvault-subscriptions`)
6. Send a test notification to verify

Reference: [RTDN setup](https://developer.android.com/google/play/billing/getting-ready#configure-rtdn)

## 6. Configure the Server

Add these environment variables to your `.env` or deployment config:

```env
GOOGLE_SERVICE_ACCOUNT_PATH=/etc/shellvault/google-sa.json
GOOGLE_PACKAGE_NAME=de.kiefernetworks.shellvault
```

The server will automatically enable Google Play billing when both variables are set. Check the startup logs for:

```
Google Play billing enabled
```

## 7. Testing

### License Testing

1. Open [Google Play Console](https://play.google.com/console) → **Settings** → **License testing**
2. Add Google accounts for testing (these accounts can make free test purchases)

### Internal Test Track

1. Upload your APK/AAB to the **Internal testing** track
2. Add testers via email list
3. Testers install via the Play Store opt-in link

### Verify End-to-End

1. Install from internal test track
2. Purchase subscription with a license testing account
3. Check server logs for `google purchase verification` messages
4. Run `shellvault-cli billing sync` to verify reconciliation
5. Cancel via [Google Play subscriptions](https://play.google.com/store/account/subscriptions) → check webhook processing

Reference: [Test in-app billing](https://developer.android.com/google/play/billing/test)

## Environment Variables Reference

| Variable | Description |
|----------|-------------|
| `GOOGLE_SERVICE_ACCOUNT_PATH` | Path to Google Cloud service account JSON key |
| `GOOGLE_PACKAGE_NAME` | Android package name (e.g. `de.kiefernetworks.shellvault`) |

## API Endpoints

| Endpoint | Auth | Description |
|----------|------|-------------|
| `POST /v1/billing/verify-google` | JWT | Client sends `{ "purchase_token": "..." }`, server verifies with Google API |
| `POST /v1/webhooks/google` | Public | Cloud Pub/Sub push endpoint for RTDN |
| `GET /v1/billing/status` | JWT | Returns subscription status (works for all providers) |

## Client Product ID

The Flutter app uses the product ID `shellvault_sync_yearly` (defined in `subscription_purchase_provider.dart`). Make sure the Google Play Console subscription matches this ID exactly.
