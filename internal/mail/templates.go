package mail

import "fmt"

func VerificationEmailBody(apiBaseURL, token string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 20px;">
  <div style="max-width: 600px; margin: 0 auto;">
    <h2>Verify your ShellVault email</h2>
    <p>Please click the link below to verify your email address:</p>
    <p>
      <a href="%s/v1/auth/verify-email?token=%s"
         style="display: inline-block; padding: 12px 24px; background: #007AFF; color: white; text-decoration: none; border-radius: 8px;">
        Verify Email
      </a>
    </p>
    <p style="color: #666; font-size: 14px;">
      If you didn't create a ShellVault account, you can ignore this email.
    </p>
    <p style="color: #999; font-size: 12px;">&mdash; ShellVault by Kiefer Networks</p>
  </div>
</body>
</html>`, apiBaseURL, token)
}

func PaymentConfirmationEmailBody(email string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 20px;">
  <div style="max-width: 600px; margin: 0 auto;">
    <h2>Payment Confirmed – ShellVault Sync</h2>
    <p>Thank you for your purchase! Your ShellVault Sync subscription is now active.</p>
    <table style="width: 100%%; border-collapse: collapse; margin: 20px 0;">
      <tr style="border-bottom: 1px solid #eee;">
        <td style="padding: 8px 0; color: #666;">Account</td>
        <td style="padding: 8px 0; text-align: right;">%s</td>
      </tr>
      <tr style="border-bottom: 1px solid #eee;">
        <td style="padding: 8px 0; color: #666;">Plan</td>
        <td style="padding: 8px 0; text-align: right;">ShellVault Sync (Annual)</td>
      </tr>
      <tr>
        <td style="padding: 8px 0; color: #666;">Status</td>
        <td style="padding: 8px 0; text-align: right; color: #22863a; font-weight: bold;">Active</td>
      </tr>
    </table>
    <p>You can manage your subscription (invoices, payment method, cancellation) anytime through the app under <strong>Settings → Sync</strong>.</p>
    <p style="color: #666; font-size: 14px;">
      If you have any questions, reply to this email or contact us at support@kiefer-networks.de.
    </p>
    <p style="color: #999; font-size: 12px;">&mdash; ShellVault by Kiefer Networks</p>
  </div>
</body>
</html>`, email)
}

func PasswordResetEmailBody(appBaseURL, token string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 20px;">
  <div style="max-width: 600px; margin: 0 auto;">
    <h2>Reset your ShellVault password</h2>
    <p>Click the link below to reset your password. This link expires in 1 hour.</p>
    <p>
      <a href="%s/reset-password?token=%s"
         style="display: inline-block; padding: 12px 24px; background: #007AFF; color: white; text-decoration: none; border-radius: 8px;">
        Reset Password
      </a>
    </p>
    <p style="color: #666; font-size: 14px;">
      If you didn't request a password reset, you can ignore this email.
    </p>
    <p style="color: #999; font-size: 12px;">&mdash; ShellVault by Kiefer Networks</p>
  </div>
</body>
</html>`, appBaseURL, token)
}
