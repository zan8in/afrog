package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type ClientOptions struct {
	Timeout time.Duration
	Proxy   string
}

type Client struct {
	base string
	hc   *http.Client
}

type LoginRequest struct {
	LicenseKey        string `json:"license_key"`
	DeviceFingerprint string `json:"device_fingerprint"`
	ClientVersion     string `json:"client_version"`
	OS                string `json:"os"`
}

type LoginResponse struct {
	AccountID           string `json:"account_id"`
	DeviceID            string `json:"device_id"`
	AccessToken         string `json:"access_token"`
	RefreshToken        string `json:"refresh_token"`
	AccessExpiresInSec  int64  `json:"access_expires_in_sec"`
	RefreshExpiresInSec int64  `json:"refresh_expires_in_sec"`
}

type RefreshRequest struct {
	RefreshToken      string `json:"refresh_token"`
	DeviceFingerprint string `json:"device_fingerprint"`
}

type RefreshResponse struct {
	AccessToken         string `json:"access_token"`
	RefreshToken        string `json:"refresh_token"`
	AccessExpiresInSec  int64  `json:"access_expires_in_sec"`
	RefreshExpiresInSec int64  `json:"refresh_expires_in_sec"`
}

type ManifestRequest struct {
	Channel      string `json:"channel"`
	OSArch       string `json:"os_arch"`
	AfrogVersion string `json:"afrog_version"`
}

type ManifestResponse struct {
	ManifestJSONB64 string `json:"manifest_json_b64"`
	ManifestSigB64  string `json:"manifest_sig_b64"`
}

type AuthorizeDownloadRequest struct {
	ArtifactID         string `json:"artifact_id"`
	ExpectedManifestID string `json:"expected_manifest_id"`
	DeviceFingerprint  string `json:"device_fingerprint"`
}

type AuthorizeDownloadResponse struct {
	DownloadURL   string `json:"download_url"`
	ContentKeyB64 string `json:"content_key_b64"`
}

func NewClient(base string, opts ClientOptions) *Client {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if opts.Timeout <= 0 {
		opts.Timeout = 20 * time.Second
	}
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout: 10 * time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	if strings.TrimSpace(opts.Proxy) != "" {
		if pu, err := url.Parse(opts.Proxy); err == nil {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	return &Client{
		base: base,
		hc: &http.Client{
			Timeout:   opts.Timeout,
			Transport: tr,
		},
	}
}

type apiError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	RequestID string `json:"request_id"`
}

func (e apiError) toError(status int) error {
	msg := strings.TrimSpace(e.Error.Message)
	if msg == "" {
		msg = http.StatusText(status)
	}
	code := strings.TrimSpace(e.Error.Code)
	if code != "" {
		msg = fmt.Sprintf("%s (%s)", msg, code)
	}
	if strings.TrimSpace(e.RequestID) != "" {
		msg = fmt.Sprintf("%s [request_id=%s]", msg, e.RequestID)
	}
	return errors.New(msg)
}

func (c *Client) doJSON(ctx context.Context, method, path string, token string, req any, resp any) error {
	if c == nil || c.hc == nil {
		return errors.New("client not initialized")
	}
	u := c.base + path
	var body io.Reader
	if req != nil {
		b, err := json.Marshal(req)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	r, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	r.Header.Set("Accept", "application/json")
	if req != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if strings.TrimSpace(token) != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}

	res, err := c.hc.Do(r)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	b, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if res.StatusCode >= 400 {
		var ae apiError
		_ = json.Unmarshal(b, &ae)
		return ae.toError(res.StatusCode)
	}
	if resp == nil {
		return nil
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return errors.New("empty response")
	}
	return json.Unmarshal(b, resp)
}

func (c *Client) Login(ctx context.Context, req LoginRequest) (LoginResponse, error) {
	var resp LoginResponse
	if err := c.doJSON(ctx, http.MethodPost, "/login", "", req, &resp); err != nil {
		return LoginResponse{}, err
	}
	return resp, nil
}

func (c *Client) Refresh(ctx context.Context, req RefreshRequest) (RefreshResponse, error) {
	var resp RefreshResponse
	if err := c.doJSON(ctx, http.MethodPost, "/refresh", "", req, &resp); err != nil {
		return RefreshResponse{}, err
	}
	return resp, nil
}

func (c *Client) GetManifest(ctx context.Context, accessToken string, req ManifestRequest) (ManifestResponse, error) {
	var resp ManifestResponse
	if err := c.doJSON(ctx, http.MethodPost, "/manifest", accessToken, req, &resp); err != nil {
		return ManifestResponse{}, err
	}
	return resp, nil
}

func (c *Client) AuthorizeDownload(ctx context.Context, accessToken string, req AuthorizeDownloadRequest) (AuthorizeDownloadResponse, error) {
	var resp AuthorizeDownloadResponse
	if err := c.doJSON(ctx, http.MethodPost, "/authorize-download", accessToken, req, &resp); err != nil {
		return AuthorizeDownloadResponse{}, err
	}
	return resp, nil
}

func DownloadToFile(ctx context.Context, downloadURL string, path string) error {
	u := strings.TrimSpace(downloadURL)
	if u == "" {
		return errors.New("download url is empty")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "*/*")

	hc := &http.Client{Timeout: 2 * time.Minute}
	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 4*1024))
		msg := strings.TrimSpace(string(b))
		if msg == "" {
			msg = http.StatusText(res.StatusCode)
		}
		return fmt.Errorf("download failed: %s", msg)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := io.Copy(f, res.Body); err != nil {
		return err
	}
	return f.Sync()
}
