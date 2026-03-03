package middleware

import (
	"reflect"
	"testing"
)

func TestCORSOptions_DefaultOrigins(t *testing.T) {
	opts := CORSOptions("")

	expected := []string{"https://sshvault.app", "https://app.sshvault.app"}
	if !reflect.DeepEqual(opts.AllowedOrigins, expected) {
		t.Errorf("AllowedOrigins = %v, want %v", opts.AllowedOrigins, expected)
	}
}

func TestCORSOptions_CustomOrigins(t *testing.T) {
	opts := CORSOptions("https://example.com, https://test.example.com")

	expected := []string{"https://example.com", "https://test.example.com"}
	if !reflect.DeepEqual(opts.AllowedOrigins, expected) {
		t.Errorf("AllowedOrigins = %v, want %v", opts.AllowedOrigins, expected)
	}
}

func TestCORSOptions_SingleCustomOrigin(t *testing.T) {
	opts := CORSOptions("https://mysite.com")

	expected := []string{"https://mysite.com"}
	if !reflect.DeepEqual(opts.AllowedOrigins, expected) {
		t.Errorf("AllowedOrigins = %v, want %v", opts.AllowedOrigins, expected)
	}
}

func TestCORSOptions_WhitespaceOnlyFallsBackToDefaults(t *testing.T) {
	opts := CORSOptions("   ,  ,  ")

	expected := []string{"https://sshvault.app", "https://app.sshvault.app"}
	if !reflect.DeepEqual(opts.AllowedOrigins, expected) {
		t.Errorf("AllowedOrigins with whitespace-only input = %v, want defaults %v", opts.AllowedOrigins, expected)
	}
}

func TestCORSOptions_TrimsWhitespace(t *testing.T) {
	opts := CORSOptions("  https://a.com  , https://b.com  ")

	expected := []string{"https://a.com", "https://b.com"}
	if !reflect.DeepEqual(opts.AllowedOrigins, expected) {
		t.Errorf("AllowedOrigins = %v, want %v", opts.AllowedOrigins, expected)
	}
}

func TestCORSOptions_SkipsEmptyEntries(t *testing.T) {
	opts := CORSOptions("https://a.com,,https://b.com,")

	expected := []string{"https://a.com", "https://b.com"}
	if !reflect.DeepEqual(opts.AllowedOrigins, expected) {
		t.Errorf("AllowedOrigins = %v, want %v", opts.AllowedOrigins, expected)
	}
}

func TestCORSOptions_AllowedMethods(t *testing.T) {
	opts := CORSOptions("")

	expected := []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	if !reflect.DeepEqual(opts.AllowedMethods, expected) {
		t.Errorf("AllowedMethods = %v, want %v", opts.AllowedMethods, expected)
	}
}

func TestCORSOptions_AllowedHeaders(t *testing.T) {
	opts := CORSOptions("")

	expected := []string{"Accept", "Authorization", "Content-Type", "X-Request-ID"}
	if !reflect.DeepEqual(opts.AllowedHeaders, expected) {
		t.Errorf("AllowedHeaders = %v, want %v", opts.AllowedHeaders, expected)
	}
}

func TestCORSOptions_ExposedHeaders(t *testing.T) {
	opts := CORSOptions("")

	expected := []string{"X-Request-ID"}
	if !reflect.DeepEqual(opts.ExposedHeaders, expected) {
		t.Errorf("ExposedHeaders = %v, want %v", opts.ExposedHeaders, expected)
	}
}

func TestCORSOptions_AllowCredentials(t *testing.T) {
	opts := CORSOptions("")

	if !opts.AllowCredentials {
		t.Error("AllowCredentials should be true")
	}
}

func TestCORSOptions_MaxAge(t *testing.T) {
	opts := CORSOptions("")

	if opts.MaxAge != 300 {
		t.Errorf("MaxAge = %d, want 300", opts.MaxAge)
	}
}

func TestCORSOptions_CustomOriginsPreserveOtherSettings(t *testing.T) {
	opts := CORSOptions("https://custom.example.com")

	if !opts.AllowCredentials {
		t.Error("AllowCredentials should be true even with custom origins")
	}
	if opts.MaxAge != 300 {
		t.Errorf("MaxAge = %d, want 300 even with custom origins", opts.MaxAge)
	}

	expectedMethods := []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	if !reflect.DeepEqual(opts.AllowedMethods, expectedMethods) {
		t.Errorf("AllowedMethods = %v, want %v", opts.AllowedMethods, expectedMethods)
	}

	expectedHeaders := []string{"Accept", "Authorization", "Content-Type", "X-Request-ID"}
	if !reflect.DeepEqual(opts.AllowedHeaders, expectedHeaders) {
		t.Errorf("AllowedHeaders = %v, want %v", opts.AllowedHeaders, expectedHeaders)
	}
}

func TestCORSOptions_ManyOrigins(t *testing.T) {
	opts := CORSOptions("https://a.com,https://b.com,https://c.com,https://d.com,https://e.com")

	if len(opts.AllowedOrigins) != 5 {
		t.Errorf("expected 5 origins, got %d: %v", len(opts.AllowedOrigins), opts.AllowedOrigins)
	}
}
