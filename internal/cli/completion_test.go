package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestCompletionRejectsInvalidArguments(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"fish"},
		{"bash", "extra"},
		{"zsh", "extra"},
	} {
		var out bytes.Buffer
		err := (app{out: &out, errOut: io.Discard}).completion(args)
		if err == nil {
			t.Fatalf("completion(%q) succeeded", args)
		}
		if out.Len() != 0 {
			t.Fatalf("completion(%q) wrote output on error: %q", args, out.String())
		}
	}
}

func TestCompletionPropagatesOutputError(t *testing.T) {
	want := errors.New("output failed")
	got := (app{out: errorWriter{err: want}, errOut: io.Discard}).completion([]string{"bash"})
	if !errors.Is(got, want) {
		t.Fatalf("completion output error = %v, want %v", got, want)
	}
}

func TestCompletionScriptsContainRegistrations(t *testing.T) {
	for _, shell := range []string{"bash", "zsh"} {
		script := completionOutput(t, shell)
		if !strings.Contains(script, "_wirectl_connect_completion") {
			t.Fatalf("%s completion has no function", shell)
		}
		if !strings.Contains(script, "wirectl-connect") || !strings.Contains(script, "wirectl") {
			t.Fatalf("%s completion does not register both entry points", shell)
		}
	}
}

func TestBashCompletionCandidatesAndContexts(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is unavailable")
	}
	script := completionOutput(t, "bash")
	cases := []struct {
		name  string
		words []string
		want  []string
	}{
		{
			name:  "root commands include download",
			words: []string{"wirectl", "d"},
			want:  []string{"download"},
		},
		{
			name:  "connect command",
			words: []string{"wirectl", "connect", "lo"},
			want:  []string{"login"},
		},
		{
			name:  "serve options",
			words: []string{"wirectl-connect", "serve", "--h"},
			want:  []string{"--help", "--http"},
		},
		{
			name:  "completion shells",
			words: []string{"wirectl-connect", "completion", "z"},
			want:  []string{"zsh"},
		},
		{name: "option values are not commands", words: []string{"wirectl-connect", "--name", "serve", "--re"}, want: []string{"--relay-only", "--replace"}},
		{name: "no pairing secret suggestions", words: []string{"wirectl-connect", "vpn.example.com", ""}},
		{name: "no enrollment secret suggestions", words: []string{"wirectl-connect", "login", "vpn.example.com", ""}},
		{name: "login flags stay scoped", words: []string{"wirectl-connect", "login", "--re"}},

		{
			name:  "double dash ends options",
			words: []string{"wirectl-connect", "--", "--h"},
			want:  nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := runBashCompletion(t, script, "", tc.words)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("candidates = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestBashCompletionPathValuesPreserveSpaces(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is unavailable")
	}
	dir := completionTestDir(t)
	withSpace := filepath.Join(dir, "directory with spaces")
	if err := os.Mkdir(withSpace, 0700); err != nil {
		t.Fatal(err)
	}
	script := completionOutput(t, "bash")
	pathPrefix := filepath.Join(dir, "d")
	wantPath := filepath.Join(dir, "directory with spaces")
	for _, tc := range []struct {
		name       string
		words      []string
		wordbreaks string
		want       string
	}{
		{
			name:       "separate value",
			words:      []string{"wirectl-connect", "serve", "--state-dir", pathPrefix},
			wordbreaks: "=:",
			want:       wantPath,
		},
		{
			name:       "equals without equals wordbreak",
			words:      []string{"wirectl-connect", "serve", "--state-dir=" + pathPrefix},
			wordbreaks: ":",
			want:       "--state-dir=" + wantPath,
		},
		{
			name:       "equals with equals wordbreak",
			words:      []string{"wirectl-connect", "serve", "--state-dir=" + pathPrefix},
			wordbreaks: "=:",
			want:       wantPath,
		},
		{
			name:       "split equals",
			words:      []string{"wirectl-connect", "serve", "--state-dir", "=", pathPrefix},
			wordbreaks: "=:",
			want:       wantPath,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := runBashCompletionWithWordbreaks(t, script, "", tc.wordbreaks, tc.words)
			if !containsString(got, tc.want) {
				t.Fatalf("candidates = %#v, want path %q", got, tc.want)
			}
			if len(got) != 1 {
				t.Fatalf("candidates = %#v, want only the matching path", got)
			}
		})
	}
}

func TestBashCompletionPreservesExistingDownloadCompletion(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is unavailable")
	}
	script := completionOutput(t, "bash")
	prelude := `_wirectl_download_completion() { COMPREPLY=(download-from-existing-script); }
`
	got := runBashCompletion(t, script, prelude, []string{"wirectl", "download", "x"})
	if !reflect.DeepEqual(got, []string{"download-from-existing-script"}) {
		t.Fatalf("download candidates = %#v", got)
	}
}

func TestZshCompletionCandidatesAndContexts(t *testing.T) {
	if _, err := exec.LookPath("zsh"); err != nil {
		t.Skip("zsh is unavailable")
	}
	script := completionOutput(t, "zsh")
	cases := []struct {
		name  string
		words []string
		want  []string
	}{
		{
			name:  "root commands include download",
			words: []string{"wirectl", "d"},
			want:  []string{"download"},
		},
		{
			name:  "connect command",
			words: []string{"wirectl", "connect", "lo"},
			want:  []string{"login"},
		},
		{
			name:  "serve options",
			words: []string{"wirectl-connect", "serve", "--h"},
			want:  []string{"--help", "--http"},
		},
		{
			name:  "completion shells",
			words: []string{"wirectl-connect", "completion", "z"},
			want:  []string{"zsh"},
		},
		{name: "option values are not commands", words: []string{"wirectl-connect", "--name", "serve", "--re"}, want: []string{"--relay-only", "--replace"}},
		{name: "no pairing secret suggestions", words: []string{"wirectl-connect", "vpn.example.com", ""}},
		{name: "no enrollment secret suggestions", words: []string{"wirectl-connect", "login", "vpn.example.com", ""}},
		{name: "login flags stay scoped", words: []string{"wirectl-connect", "login", "--re"}},

		{
			name:  "double dash ends options",
			words: []string{"wirectl-connect", "--", "--h"},
			want:  nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := runZshCompletion(t, script, "", tc.words)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("candidates = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestZshCompletionPathAndDownloadContexts(t *testing.T) {
	if _, err := exec.LookPath("zsh"); err != nil {
		t.Skip("zsh is unavailable")
	}
	script := completionOutput(t, "zsh")
	got := runZshCompletion(t, script, "", []string{"wirectl-connect", "serve", "--state-dir", "prefix with spaces"})
	if !reflect.DeepEqual(got, []string{"FILE:directory with spaces"}) {
		t.Fatalf("state directory candidates = %#v", got)
	}
	got = runZshCompletion(t, script, "", []string{"wirectl-connect", "serve", "--state-dir=prefix with spaces"})
	if !reflect.DeepEqual(got, []string{"FILE:directory with spaces"}) {
		t.Fatalf("equals state directory candidates = %#v", got)
	}
	prelude := `_wirectl_download_completion() { _captured=(download-from-existing-script); }
`
	got = runZshCompletion(t, script, prelude, []string{"wirectl", "download", "x"})
	if !reflect.DeepEqual(got, []string{"download-from-existing-script"}) {
		t.Fatalf("download candidates = %#v", got)
	}
}

func completionOutput(t *testing.T, shell string) string {
	t.Helper()
	var out, errOut bytes.Buffer
	if err := Run(context.Background(), []string{"completion", shell}, "test", bytes.NewReader(nil), &out, &errOut); err != nil {
		t.Fatalf("generate %s completion: %v", shell, err)
	}
	if errOut.Len() != 0 {
		t.Fatalf("generate %s completion wrote stderr: %q", shell, errOut.String())
	}
	return out.String()
}

func completionTestDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

func runBashCompletion(t *testing.T, script, prelude string, words []string) []string {
	t.Helper()
	return runBashCompletionWithWordbreaks(t, script, prelude, "", words)
}

func runBashCompletionWithWordbreaks(t *testing.T, script, prelude, wordbreaks string, words []string) []string {
	t.Helper()
	scriptPath := writeCompletionScript(t, script, prelude)
	harness := `COMP_WORDBREAKS="$1"
shift
source "$1"
shift
COMP_WORDS=("$@")
COMP_CWORD=$((${#COMP_WORDS[@]} - 1))
_wirectl_connect_completion
printf '%s\n' "${COMPREPLY[@]}"
`
	args := []string{"--noprofile", "--norc", "-c", harness, "wirectl-completion-test", wordbreaks, scriptPath}
	args = append(args, words...)
	return runCompletionCommand(t, "bash", args...)
}

func runZshCompletion(t *testing.T, script, prelude string, words []string) []string {
	t.Helper()
	scriptPath := writeCompletionScript(t, script, prelude)
	harness := `compdef() { :; }
compadd() {
    local arg name prefix="${PREFIX-}"
    while (( $# )); do
        case "$1" in
            -a)
                name="$2"; shift 2; eval '_captured=("${'"$name"'[@]}")'
                local -a filtered
                for arg in "${_captured[@]}"; do [[ "$arg" == "$prefix"* ]] && filtered+=("$arg"); done
                _captured=("${filtered[@]}")
                return ;;
            --)
                shift; _captured=()
                for arg in "$@"; do [[ "$arg" == "$prefix"* ]] && _captured+=("$arg"); done
                return ;;
            *) shift ;;
        esac
    done
}
_files() { _captured=("FILE:directory with spaces"); }
compset() { return 0; }
_captured=()
source "$1"
shift
words=("$@")
CURRENT=${#words[@]}
PREFIX="${words[$CURRENT]}"
_wirectl_connect_completion
print -rC1 -- "${_captured[@]}"
`
	args := []string{"-f", "-c", harness, "wirectl-completion-test", scriptPath}
	args = append(args, words...)
	return runCompletionCommand(t, "zsh", args...)
}

func writeCompletionScript(t *testing.T, script, prelude string) string {
	t.Helper()
	dir := completionTestDir(t)
	path := filepath.Join(dir, "completion script")
	if err := os.WriteFile(path, []byte(prelude+script), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func runCompletionCommand(t *testing.T, shell string, args ...string) []string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell integration runs on Unix; Windows still tests script generation")
	}
	cmd := exec.Command(shell, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s completion harness: %v\nstderr: %s", shell, err, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("%s completion harness wrote stderr: %s", shell, stderr.String())
	}
	output := strings.TrimSuffix(stdout.String(), "\n")
	if output == "" {
		return nil
	}
	return strings.Split(output, "\n")
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

type errorWriter struct{ err error }

func (w errorWriter) Write([]byte) (int, error) { return 0, fmt.Errorf("write completion: %w", w.err) }
