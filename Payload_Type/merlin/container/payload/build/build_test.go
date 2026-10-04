package build

import (
	"strings"
	"testing"

	structs "github.com/MythicMeta/MythicContainer/agent_structs"
)

// validC2Parameters returns a C2 profile parameter map that satisfies all of
// Build()'s C2-profile validation, so a test can reach the build-parameter
// checks (verbose/debug/arch/buildmode/httpClient/...) that come after it.
func validC2Parameters() map[string]interface{} {
	return map[string]interface{}{
		"AESPSK":            map[string]interface{}{"value": "none"},
		"headers":           map[string]interface{}{},
		"callback_port":     float64(443),
		"killdate":          "2024-03-14",
		"callback_interval": float64(10),
		"callback_jitter":   float64(23),
		"callback_host":     "https://example.com",
		"post_uri":          "data",
		"proxy_host":        "",
		"proxy_port":        "",
	}
}

// newBuildMessage builds a PayloadBuildMessage with a valid C2 profile and the
// supplied build parameters.
func newBuildMessage(buildParams map[string]interface{}) structs.PayloadBuildMessage {
	msg := structs.PayloadBuildMessage{
		SelectedOS: "linux",
		C2Profiles: []structs.PayloadBuildC2Profile{
			{
				Name:       "http",
				Parameters: validC2Parameters(),
			},
		},
	}
	msg.BuildParameters = structs.BuildParameters{Parameters: buildParams}
	return msg
}

// TestBuildMissingBuildmodeArg verifies that a failure to read the 'buildmode'
// build parameter is surfaced as an error rather than silently ignored. It
// guards the fix for the check that previously tested a stale 'ok' (left over
// from an earlier C2-profile map lookup) instead of the error returned by
// GetStringArg: before the fix the missing 'buildmode' slipped through and the
// build failed later with an unrelated error.
func TestBuildMissingBuildmodeArg(t *testing.T) {
	msg := newBuildMessage(map[string]interface{}{
		"verbose": false,
		"debug":   false,
		"arch":    "amd64",
		// buildmode intentionally omitted
	})

	resp := Build(msg)

	if !strings.Contains(resp.BuildStdErr, "error getting the 'buildmode' key") {
		t.Fatalf("expected a 'buildmode' key retrieval error, got BuildStdErr=%q", resp.BuildStdErr)
	}
}

// TestBuildMissingHTTPClientArg is the same guard for the 'httpClient' build
// parameter check, which had the identical stale-'ok' bug.
func TestBuildMissingHTTPClientArg(t *testing.T) {
	msg := newBuildMessage(map[string]interface{}{
		"verbose":   false,
		"debug":     false,
		"arch":      "amd64",
		"buildmode": "default",
		// httpClient intentionally omitted
	})

	resp := Build(msg)

	if !strings.Contains(resp.BuildStdErr, "error getting the 'httpClient' key") {
		t.Fatalf("expected a 'httpClient' key retrieval error, got BuildStdErr=%q", resp.BuildStdErr)
	}
}
