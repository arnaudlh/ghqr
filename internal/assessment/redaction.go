// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"
)

var (
	emailPattern           = regexp.MustCompile(`(?i)[a-z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-z0-9.-]+\.[a-z]{2,}`)
	tokenPattern           = regexp.MustCompile(`(?:github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9_]{16,})`)
	privateMaterialPattern = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)
	assignmentPattern      = regexp.MustCompile(`(?im)([a-z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|private[_-]?key)[a-z0-9_.-]*)[ \t]*[:=][ \t]*("[^"\r\n]*"|'[^'\r\n]*'|[^\r\n#]+)`)
)

// Redactor sanitizes structured evidence before it crosses any persistence boundary.
// Discovered literal secrets are retained in memory only, with race-safe access.
type Redactor struct {
	mu      sync.RWMutex
	secrets []string
}

// NewRedactor binds configured credential values without exposing them in its output.
func NewRedactor(secrets ...string) *Redactor {
	values := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		if secret != "" {
			values = append(values, secret)
		}
	}
	sort.Slice(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	return &Redactor{secrets: values}
}

// Text removes known credentials, personal email and labeled/private material.
func (r *Redactor) Text(text string) string {
	if r != nil {
		r.mu.RLock()
		for _, secret := range r.secrets {
			text = strings.ReplaceAll(text, secret, "[REDACTED]")
		}
		r.mu.RUnlock()
	}
	text = emailPattern.ReplaceAllString(text, "[REDACTED_EMAIL]")
	text = tokenPattern.ReplaceAllString(text, "[REDACTED_TOKEN]")
	text = privateMaterialPattern.ReplaceAllString(text, "[REDACTED_PRIVATE_KEY]")
	return assignmentPattern.ReplaceAllString(text, "${1}=[REDACTED]")
}

// JSON preserves nonsensitive JSON shape and numbers while recording redaction paths.
// Raw unredacted bytes are never written, including successful secret-alert responses.
func (r *Redactor) JSON(data []byte) ([]byte, []string, error) {
	if len(data) > maxEvidenceResponseBytes {
		return nil, nil, fmt.Errorf("structured evidence exceeds the supported size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, nil, fmt.Errorf("evidence is not valid JSON")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, nil, fmt.Errorf("evidence must contain exactly one JSON value")
	}
	secrets := []string{}
	if r != nil {
		r.mu.RLock()
		secrets = append(secrets, r.secrets...)
		r.mu.RUnlock()
	}
	findLiteralSecrets(value, &secrets, 0)
	if r != nil {
		r.mu.Lock()
		known := make(map[string]bool, len(r.secrets))
		for _, secret := range r.secrets {
			known[secret] = true
		}
		for _, secret := range secrets {
			if !known[secret] && secret != "[REDACTED]" {
				r.secrets = append(r.secrets, secret)
				known[secret] = true
			}
		}
		sort.Slice(r.secrets, func(i, j int) bool { return len(r.secrets[i]) > len(r.secrets[j]) })
		r.mu.Unlock()
	}
	local := NewRedactor(secrets...)
	redactions := []string{}
	clean, err := local.sanitize(value, "$", "", &redactions, 0)
	if err != nil {
		return nil, nil, err
	}
	result, err := json.MarshalIndent(clean, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("encode sanitized evidence: %w", err)
	}
	sort.Strings(redactions)
	return result, redactions, nil
}

func findLiteralSecrets(value any, secrets *[]string, depth int) {
	if depth > 64 {
		return
	}
	switch item := value.(type) {
	case map[string]any:
		for key, child := range item {
			if sensitiveKey(key) {
				if text, ok := child.(string); ok && text != "" {
					*secrets = append(*secrets, text)
				}
			}
			findLiteralSecrets(child, secrets, depth+1)
		}
	case []any:
		for _, child := range item {
			findLiteralSecrets(child, secrets, depth+1)
		}
	}
}

func sensitiveKey(key string) bool {
	key = strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	switch key {
	case "secret", "password", "passwd", "pwd", "token", "access_token", "refresh_token",
		"api_key", "authorization", "private_key", "bind_pw", "credentials", "client_secret",
		"email", "emails", "email_addresses":
		return true
	}
	for _, suffix := range []string{"_password", ".password", "_passwd", "_secret", "_token", "_private_key", "_bind_pw", "_email"} {
		if strings.HasSuffix(key, suffix) {
			return true
		}
	}
	return false
}

func freeTextKey(key string) bool {
	switch strings.ToLower(key) {
	case "message", "description", "body", "comment", "comments", "notes", "resolution_comment",
		"bypass_request_comment", "bypass_reason", "private_note":
		return true
	}
	return false
}

func (r *Redactor) sanitize(value any, path, parent string, redactions *[]string, depth int) (any, error) {
	if depth > 64 {
		return nil, fmt.Errorf("evidence exceeds supported nesting depth")
	}
	switch item := value.(type) {
	case map[string]any:
		clean := make(map[string]any, len(item))
		for key, child := range item {
			safeKey := r.Text(key)
			childPath := path + "." + safeKey
			if safeKey != key {
				*redactions = append(*redactions, path+".<redacted-key>")
			}
			if _, exists := clean[safeKey]; exists {
				return nil, fmt.Errorf("redacting evidence keys would create an ambiguous object")
			}
			if !explicitlyEmptyValue(child) && (sensitiveKey(key) || freeTextKey(key)) {
				clean[safeKey] = "[REDACTED]"
				*redactions = append(*redactions, childPath)
				continue
			}
			if text, ok := child.(string); ok && ((key == "url" && parent == "config") || key == "webhook_url") {
				address, err := url.Parse(text)
				if err != nil {
					return nil, fmt.Errorf("webhook destination is not a valid URL")
				}
				host := address.Hostname()
				if host == "" {
					if err := validateHost(text); err != nil {
						return nil, fmt.Errorf("webhook destination is not a valid URL or sanitized host")
					}
					host = text
				}
				clean[safeKey] = r.Text(host)
				if text != host {
					*redactions = append(*redactions, childPath)
				}
				continue
			}
			if key == "content" && item["encoding"] == "base64" {
				text, ok := child.(string)
				if !ok {
					return nil, fmt.Errorf("base64 evidence content must be a string")
				}
				decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(text, "\n", ""))
				if err != nil || !utf8.Valid(decoded) {
					return nil, fmt.Errorf("base64 evidence content is not supported UTF-8 text")
				}
				sanitized := r.Text(string(decoded))
				if sanitized != string(decoded) {
					*redactions = append(*redactions, childPath)
				}
				clean[safeKey] = base64.StdEncoding.EncodeToString([]byte(sanitized))
				continue
			}
			sanitized, err := r.sanitize(child, childPath, strings.ToLower(key), redactions, depth+1)
			if err != nil {
				return nil, err
			}
			clean[safeKey] = sanitized
		}
		return clean, nil
	case []any:
		clean := make([]any, len(item))
		for index, child := range item {
			sanitized, err := r.sanitize(child, fmt.Sprintf("%s[%d]", path, index), parent, redactions, depth+1)
			if err != nil {
				return nil, err
			}
			clean[index] = sanitized
		}
		return clean, nil
	case string:
		clean := r.Text(item)
		if clean != item {
			*redactions = append(*redactions, path)
		}
		return clean, nil
	default:
		return value, nil
	}
}
