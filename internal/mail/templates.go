package mail

import "fmt"

func VerificationEmailBody(apiBaseURL, token string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 20px;">
  <div style="max-width: 600px; margin: 0 auto;">
    <h2>Verify your SSHVault email</h2>
    <p>Open the link below and choose your own password to activate a new account. Opening the link alone makes no changes. The link expires in 24 hours:</p>
    <p>
      <a href="%s/v1/auth/verify-email?token=%s"
         style="display: inline-block; padding: 12px 24px; background: #007AFF; color: white; text-decoration: none; border-radius: 8px;">
        Verify Email
      </a>
    </p>
    <p style="color: #666; font-size: 14px;">
      If you didn't create an SSHVault account, you can ignore this email.
    </p>
    <p style="color: #999; font-size: 12px;">&mdash; SSHVault by Kiefer Networks</p>
  </div>
</body>
</html>`, apiBaseURL, token)
}

func PasswordResetEmailBody(appBaseURL, token string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 20px;">
  <div style="max-width: 600px; margin: 0 auto;">
    <h2>Reset your SSHVault password</h2>
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
    <p style="color: #999; font-size: 12px;">&mdash; SSHVault by Kiefer Networks</p>
  </div>
</body>
</html>`, appBaseURL, token)
}

func EmailChangeBody(apiBaseURL, token string) string {
	return fmt.Sprintf(`<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body>
 <h2>Confirm your SSHVault email change</h2>
 <p>Review this change within one hour, then press Confirm on the page. Opening this link does not change your account. Your current email remains active until confirmation, which signs you out of all devices.</p>
 <p><a href="%s/v1/auth/confirm-email-change?token=%s">Confirm email change</a></p>
 <p>If you did not request this change, ignore this email.</p>
 </body></html>`, apiBaseURL, token)
}
