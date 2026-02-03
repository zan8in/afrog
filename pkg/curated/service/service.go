package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/zan8in/afrog/v3/pkg/curated/api"
	"github.com/zan8in/afrog/v3/pkg/curated/manifest"
	"github.com/zan8in/afrog/v3/pkg/curated/pack"
)

type Config struct {
	Endpoint      string
	Channel       string
	CuratedPocDir string
	LicenseKey    string
	NoUpdate      bool
	ForceUpdate   bool
	ClientVersion string
}

type Service struct {
	cfg Config
}

type UpdateOptions struct {
	Force         bool
	AFCPPath      string
	ContentKeyB64 string
	ManifestID    string
}

type authState struct {
	LicenseKey        string    `json:"license_key"`
	AccountID         string    `json:"account_id"`
	DeviceID          string    `json:"device_id"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	AccessToken       string    `json:"access_token"`
	RefreshToken      string    `json:"refresh_token"`
	AccessExpiresAt   time.Time `json:"access_expires_at"`
	RefreshExpiresAt  time.Time `json:"refresh_expires_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	Checksum          string    `json:"checksum"`
}

type runtimeState struct {
	CurrentDir     string    `json:"current_dir"`
	LastUpdateAt   time.Time `json:"last_update_at"`
	LastCheckAt    time.Time `json:"last_check_at"`
	LastError      string    `json:"last_error"`
	ManifestID     string    `json:"manifest_id"`
	AfrogVersion   string    `json:"afrog_version"`
	CuratedChannel string    `json:"curated_channel"`
}

type Status struct {
	Auth  *authState
	State *runtimeState
}

func New(cfg Config) *Service {
	if strings.TrimSpace(cfg.Channel) == "" {
		cfg.Channel = "stable"
	}
	if strings.TrimSpace(cfg.LicenseKey) == "" {
		cfg.LicenseKey = strings.TrimSpace(os.Getenv("AFROG_CURATED_LICENSE_KEY"))
	}
	return &Service{cfg: cfg}
}

func (s *Service) Login(ctx context.Context, license string) error {
	if strings.TrimSpace(license) == "" {
		return errors.New("license is empty")
	}
	dir, err := configDir()
	if err != nil {
		return err
	}
	as, _ := readAuth(filepath.Join(dir, "curated-auth.json"))
	if as == nil {
		as = &authState{}
	}
	as.LicenseKey = strings.TrimSpace(license)
	as.UpdatedAt = time.Now()
	if as.DeviceFingerprint == "" {
		as.DeviceFingerprint = loadOrCreateDeviceFingerprint(filepath.Join(dir, "curated-device.json"))
	}

	endpoint := strings.TrimSpace(s.cfg.Endpoint)
	if endpoint != "" {
		c := api.NewClient(endpoint, api.ClientOptions{})
		cv := strings.TrimSpace(s.cfg.ClientVersion)
		if cv == "" {
			cv = "afrog-curated"
		}
		resp, err := c.Login(ctx, api.LoginRequest{
			LicenseKey:        as.LicenseKey,
			DeviceFingerprint: as.DeviceFingerprint,
			ClientVersion:     cv,
			OS:                runtimeOSArch(),
		})
		if err != nil {
			return err
		}
		as.AccountID = resp.AccountID
		as.DeviceID = resp.DeviceID
		as.AccessToken = resp.AccessToken
		as.RefreshToken = resp.RefreshToken
		if resp.AccessExpiresInSec > 0 {
			as.AccessExpiresAt = time.Now().Add(time.Duration(resp.AccessExpiresInSec) * time.Second)
		}
		if resp.RefreshExpiresInSec > 0 {
			as.RefreshExpiresAt = time.Now().Add(time.Duration(resp.RefreshExpiresInSec) * time.Second)
		}
	}
	return writeAuth(filepath.Join(dir, "curated-auth.json"), as)
}

func (s *Service) Mount(ctx context.Context) (string, error) {
	dir := strings.TrimSpace(s.cfg.CuratedPocDir)
	if dir == "" {
		cfgDir, err := configDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(cfgDir, "pocs-curated")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}

	cfgDir, err := configDir()
	if err != nil {
		return "", err
	}

	st, _ := readRuntime(filepath.Join(cfgDir, "curated-state.json"))
	if st == nil {
		st = &runtimeState{}
	}
	shouldCheck := st.LastCheckAt.IsZero() || time.Since(st.LastCheckAt) > 6*time.Hour
	endpoint := strings.TrimSpace(s.cfg.Endpoint)
	var updateErr error
	if endpoint != "" && (s.cfg.ForceUpdate || shouldCheck) && !s.cfg.NoUpdate {
		uopts := UpdateOptions{}
		if s.cfg.ForceUpdate {
			uopts.Force = true
		}
		updateErr = s.Update(ctx, uopts)
	}
	st, _ = readRuntime(filepath.Join(cfgDir, "curated-state.json"))
	if st == nil {
		st = &runtimeState{}
	}
	_ = s.updateRuntimeCurrentDir(dir, st.ManifestID, st.LastError)
	if updateErr != nil && endpoint != "" && !dirHasCuratedPocs(dir) {
		return "", updateErr
	}
	return filepath.Clean(dir), nil
}

func (s *Service) Update(ctx context.Context, opts UpdateOptions) error {
	dir := strings.TrimSpace(s.cfg.CuratedPocDir)
	if dir == "" {
		cfgDir, err := configDir()
		if err != nil {
			return err
		}
		dir = filepath.Join(cfgDir, "pocs-curated")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if strings.TrimSpace(opts.AFCPPath) != "" {
		return s.installAFCP(dir, opts)
	}
	return s.updateFromRemote(ctx, dir, opts)
}

func (s *Service) Status(ctx context.Context) (Status, error) {
	_ = ctx
	cfgDir, err := configDir()
	if err != nil {
		return Status{}, err
	}
	as, _ := readAuth(filepath.Join(cfgDir, "curated-auth.json"))
	rs, _ := readRuntime(filepath.Join(cfgDir, "curated-state.json"))
	st := Status{}
	if as != nil {
		st.Auth = as
	}
	if rs != nil {
		st.State = rs
	}
	if st.Auth == nil && st.State == nil {
		return st, errors.New("no local state")
	}
	return st, nil
}

func (s Status) String() string {
	var lines []string
	if s.Auth != nil {
		lines = append(lines, fmt.Sprintf("license_key: %s", s.Auth.LicenseKey))
		lines = append(lines, fmt.Sprintf("auth_updated_at: %s", s.Auth.UpdatedAt.Format(time.RFC3339)))
	}
	if s.State != nil {
		lines = append(lines, fmt.Sprintf("current_dir: %s", s.State.CurrentDir))
		if s.State.ManifestID != "" {
			lines = append(lines, fmt.Sprintf("manifest_id: %s", s.State.ManifestID))
		}
		if s.State.CuratedChannel != "" {
			lines = append(lines, fmt.Sprintf("channel: %s", s.State.CuratedChannel))
		}
		if !s.State.LastCheckAt.IsZero() {
			lines = append(lines, fmt.Sprintf("last_check_at: %s", s.State.LastCheckAt.Format(time.RFC3339)))
		}
		if !s.State.LastUpdateAt.IsZero() {
			lines = append(lines, fmt.Sprintf("last_update_at: %s", s.State.LastUpdateAt.Format(time.RFC3339)))
		}
		if strings.TrimSpace(s.State.LastError) != "" {
			lines = append(lines, fmt.Sprintf("last_error: %s", s.State.LastError))
		}
	}
	if len(lines) == 0 {
		return "empty"
	}
	return strings.Join(lines, "\n")
}

func (s *Service) Logout(ctx context.Context) error {
	_ = ctx
	dir, err := configDir()
	if err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(dir, "curated-auth.json"))
	_ = os.Remove(filepath.Join(dir, "curated-state.json"))
	return nil
}

func configDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".config", "afrog")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	return dir, nil
}

func (s *Service) updateRuntimeDir(dir string, manifestID string, msg string) error {
	cfgDir, err := configDir()
	if err != nil {
		return err
	}
	path := filepath.Join(cfgDir, "curated-state.json")
	rs, _ := readRuntime(path)
	if rs == nil {
		rs = &runtimeState{}
	}
	now := time.Now()
	rs.CurrentDir = dir
	rs.LastCheckAt = now
	rs.LastUpdateAt = now
	rs.LastError = strings.TrimSpace(msg)
	if strings.TrimSpace(manifestID) != "" {
		rs.ManifestID = strings.TrimSpace(manifestID)
	}
	rs.CuratedChannel = strings.TrimSpace(s.cfg.Channel)
	data, err := json.MarshalIndent(rs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func (s *Service) updateRuntimeCurrentDir(dir string, manifestID string, msg string) error {
	cfgDir, err := configDir()
	if err != nil {
		return err
	}
	path := filepath.Join(cfgDir, "curated-state.json")
	rs, _ := readRuntime(path)
	if rs == nil {
		rs = &runtimeState{}
	}
	rs.CurrentDir = strings.TrimSpace(dir)
	rs.LastError = strings.TrimSpace(msg)
	if strings.TrimSpace(manifestID) != "" {
		rs.ManifestID = strings.TrimSpace(manifestID)
	}
	rs.CuratedChannel = strings.TrimSpace(s.cfg.Channel)
	data, err := json.MarshalIndent(rs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func dirHasCuratedPocs(dir string) bool {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return false
	}
	found := false
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d == nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		n := strings.ToLower(strings.TrimSpace(d.Name()))
		if strings.HasSuffix(n, ".yaml") || strings.HasSuffix(n, ".yml") {
			found = true
			return fs.SkipAll
		}
		return nil
	})
	return found
}

func readAuth(path string) (*authState, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var as authState
	if err := json.Unmarshal(b, &as); err != nil {
		return nil, err
	}
	if strings.TrimSpace(as.DeviceFingerprint) == "" || strings.TrimSpace(as.Checksum) == "" {
		return &as, nil
	}
	if !verifyAuthChecksum(&as) {
		return nil, errors.New("invalid auth state checksum")
	}
	return &as, nil
}

func readRuntime(path string) (*runtimeState, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rs runtimeState
	if err := json.Unmarshal(b, &rs); err != nil {
		return nil, err
	}
	return &rs, nil
}

func (s *Service) installAFCP(curatedDir string, opts UpdateOptions) error {
	now := time.Now()
	keyB, err := base64.StdEncoding.DecodeString(strings.TrimSpace(opts.ContentKeyB64))
	if err != nil {
		_ = s.updateRuntimeDir(curatedDir, opts.ManifestID, err.Error())
		return err
	}

	parent := filepath.Dir(curatedDir)
	staging := filepath.Join(parent, fmt.Sprintf(".pocs-curated-staging-%d", now.UnixNano()))
	_ = os.RemoveAll(staging)
	if err := os.MkdirAll(staging, 0755); err != nil {
		_ = s.updateRuntimeDir(curatedDir, opts.ManifestID, err.Error())
		return err
	}

	hdr, err := pack.DecryptAFCP1ToDir(strings.TrimSpace(opts.AFCPPath), staging, keyB)
	if err != nil {
		_ = os.RemoveAll(staging)
		_ = s.updateRuntimeDir(curatedDir, opts.ManifestID, err.Error())
		return err
	}

	manifestID := strings.TrimSpace(opts.ManifestID)
	if manifestID == "" && hdr != nil {
		manifestID = strings.TrimSpace(hdr.ManifestID)
	}

	backup := filepath.Join(parent, fmt.Sprintf(".pocs-curated-backup-%d", now.UnixNano()))
	_ = os.RemoveAll(backup)
	if _, err := os.Stat(curatedDir); err == nil {
		if err := os.Rename(curatedDir, backup); err != nil {
			_ = os.RemoveAll(staging)
			_ = s.updateRuntimeDir(curatedDir, manifestID, err.Error())
			return err
		}
	}

	if err := os.Rename(staging, curatedDir); err != nil {
		if _, stErr := os.Stat(backup); stErr == nil {
			_ = os.Rename(backup, curatedDir)
		}
		_ = os.RemoveAll(staging)
		_ = s.updateRuntimeDir(curatedDir, manifestID, err.Error())
		return err
	}

	_ = os.RemoveAll(backup)
	if err := s.updateRuntimeDir(curatedDir, manifestID, ""); err != nil {
		return err
	}
	return nil
}

func (s *Service) updateFromRemote(ctx context.Context, curatedDir string, opts UpdateOptions) error {
	endpoint := strings.TrimSpace(s.cfg.Endpoint)
	if endpoint == "" {
		return s.updateRuntimeDir(curatedDir, opts.ManifestID, "")
	}
	cfgDir, err := configDir()
	if err != nil {
		return err
	}
	authPath := filepath.Join(cfgDir, "curated-auth.json")
	as, err := readAuth(authPath)
	license := strings.TrimSpace(s.cfg.LicenseKey)
	if (err != nil || as == nil) && license != "" {
		if loginErr := s.Login(ctx, license); loginErr != nil {
			_ = s.updateRuntimeDir(curatedDir, opts.ManifestID, normalizeRuntimeError(loginErr))
			return loginErr
		}
		as, err = readAuth(authPath)
	}
	if err == nil && as != nil && license != "" && strings.TrimSpace(as.LicenseKey) != "" && strings.TrimSpace(as.LicenseKey) != license {
		if loginErr := s.Login(ctx, license); loginErr != nil {
			_ = s.updateRuntimeDir(curatedDir, opts.ManifestID, normalizeRuntimeError(loginErr))
			return loginErr
		}
		as, err = readAuth(authPath)
	}
	if err != nil || as == nil {
		errOut := errors.New("not logged in")
		_ = s.updateRuntimeDir(curatedDir, opts.ManifestID, normalizeRuntimeError(errOut))
		return errOut
	}
	if as.DeviceFingerprint == "" {
		as.DeviceFingerprint = loadOrCreateDeviceFingerprint(filepath.Join(cfgDir, "curated-device.json"))
		_ = writeAuth(authPath, as)
	}
	c := api.NewClient(endpoint, api.ClientOptions{})
	var manResp api.ManifestResponse
	for attempt := 0; attempt < 2; attempt++ {
		now := time.Now()
		if strings.TrimSpace(as.AccessToken) == "" || (!as.AccessExpiresAt.IsZero() && now.After(as.AccessExpiresAt)) {
			if strings.TrimSpace(as.RefreshToken) == "" {
				errOut := errors.New("authorization expired, please login again")
				_ = s.updateRuntimeDir(curatedDir, opts.ManifestID, normalizeRuntimeError(errOut))
				return errOut
			}
			ref, err := c.Refresh(ctx, api.RefreshRequest{
				RefreshToken:      as.RefreshToken,
				DeviceFingerprint: as.DeviceFingerprint,
			})
			if err != nil {
				if attempt == 0 && license != "" && isInvalidRefreshTokenMessage(err.Error()) {
					if loginErr := s.Login(ctx, license); loginErr != nil {
						_ = s.updateRuntimeDir(curatedDir, opts.ManifestID, normalizeRuntimeError(loginErr))
						return loginErr
					}
					as, err = readAuth(authPath)
					if err != nil || as == nil {
						errOut := errors.New("not logged in")
						_ = s.updateRuntimeDir(curatedDir, opts.ManifestID, normalizeRuntimeError(errOut))
						return errOut
					}
					continue
				}
				_ = s.updateRuntimeDir(curatedDir, opts.ManifestID, normalizeRuntimeError(err))
				return err
			}
			as.AccessToken = ref.AccessToken
			if ref.AccessExpiresInSec > 0 {
				as.AccessExpiresAt = time.Now().Add(time.Duration(ref.AccessExpiresInSec) * time.Second)
			}
			if strings.TrimSpace(ref.RefreshToken) != "" {
				as.RefreshToken = ref.RefreshToken
				if ref.RefreshExpiresInSec > 0 {
					as.RefreshExpiresAt = time.Now().Add(time.Duration(ref.RefreshExpiresInSec) * time.Second)
				}
			}
			_ = writeAuth(authPath, as)
		}

		resp, err := c.GetManifest(ctx, as.AccessToken, api.ManifestRequest{
			Channel:      strings.TrimSpace(s.cfg.Channel),
			OSArch:       runtimeOSArch(),
			AfrogVersion: "",
		})
		if err != nil {
			_ = s.updateRuntimeDir(curatedDir, opts.ManifestID, normalizeRuntimeError(err))
			return err
		}
		manResp = resp
		break
	}
	man, err := manifest.ParseAndVerify(manResp.ManifestJSONB64, manResp.ManifestSigB64)
	if err != nil {
		_ = s.updateRuntimeDir(curatedDir, opts.ManifestID, normalizeRuntimeError(err))
		return err
	}

	rs, _ := readRuntime(filepath.Join(cfgDir, "curated-state.json"))
	currentManifest := ""
	if rs != nil {
		currentManifest = rs.ManifestID
	}
	if !opts.Force && currentManifest != "" && currentManifest == man.ManifestID {
		_ = s.updateRuntimeDir(curatedDir, man.ManifestID, "")
		return nil
	}

	artifact, ok := man.SelectBestArtifact(currentManifest)
	if !ok {
		err := errors.New("no artifact available")
		_ = s.updateRuntimeDir(curatedDir, man.ManifestID, normalizeRuntimeError(err))
		return err
	}

	authz, err := c.AuthorizeDownload(ctx, as.AccessToken, api.AuthorizeDownloadRequest{
		ArtifactID:         artifact.ArtifactID,
		ExpectedManifestID: man.ManifestID,
		DeviceFingerprint:  as.DeviceFingerprint,
	})
	if err != nil {
		_ = s.updateRuntimeDir(curatedDir, man.ManifestID, normalizeRuntimeError(err))
		return err
	}

	cacheDir := filepath.Join(cfgDir, "curated-cache")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return err
	}
	tmpFile := filepath.Join(cacheDir, fmt.Sprintf("download-%d.afcp", time.Now().UnixNano()))
	if err := api.DownloadToFile(ctx, authz.DownloadURL, tmpFile); err != nil {
		_ = s.updateRuntimeDir(curatedDir, man.ManifestID, normalizeRuntimeError(err))
		return err
	}

	installOpts := UpdateOptions{
		AFCPPath:      tmpFile,
		ContentKeyB64: authz.ContentKeyB64,
		ManifestID:    man.ManifestID,
	}
	if err := s.installAFCP(curatedDir, installOpts); err != nil {
		_ = s.updateRuntimeDir(curatedDir, man.ManifestID, normalizeRuntimeError(err))
		return err
	}
	_ = os.Remove(tmpFile)
	return nil
}

func normalizeRuntimeError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.TrimSpace(err.Error())
	if msg == "" {
		return ""
	}
	if isLicenseExpiredMessage(msg) {
		return "license expired, please renew"
	}
	return msg
}

func isLicenseExpiredMessage(msg string) bool {
	m := strings.ToLower(strings.TrimSpace(msg))
	if m == "" {
		return false
	}
	if strings.Contains(m, "license_expired") ||
		strings.Contains(m, "subscription_expired") ||
		strings.Contains(m, "plan_expired") {
		return true
	}
	if strings.Contains(m, "license") && strings.Contains(m, "expired") {
		return true
	}
	if strings.Contains(m, "license") && strings.Contains(m, "expire") {
		return true
	}
	if strings.Contains(m, "已过期") || strings.Contains(m, "过期") {
		return true
	}
	return false
}

func isInvalidRefreshTokenMessage(msg string) bool {
	m := strings.ToLower(strings.TrimSpace(msg))
	if m == "" {
		return false
	}
	return strings.Contains(m, "invalid refresh token")
}

func writeAuth(path string, as *authState) error {
	if as != nil {
		as.Checksum = computeAuthChecksum(as)
	}
	data, err := json.MarshalIndent(as, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func loadOrCreateDeviceFingerprint(path string) string {
	if v := strings.TrimSpace(os.Getenv("AFROG_CURATED_DEVICE_FINGERPRINT")); v != "" {
		return v
	}
	if b, err := os.ReadFile(path); err == nil {
		var m map[string]string
		if json.Unmarshal(b, &m) == nil {
			if fp := strings.TrimSpace(m["fingerprint"]); fp != "" {
				return fp
			}
		}
	}
	rb := make([]byte, 32)
	_, _ = rand.Read(rb)
	host, _ := os.Hostname()
	data := strings.Join([]string{
		strings.TrimSpace(runtime.GOOS),
		strings.TrimSpace(runtime.GOARCH),
		strings.TrimSpace(host),
		base64.RawURLEncoding.EncodeToString(rb),
	}, "|")
	sum := sha256.Sum256([]byte(data))
	fp := base64.RawURLEncoding.EncodeToString(sum[:])
	_ = os.MkdirAll(filepath.Dir(path), 0755)
	_ = os.WriteFile(path, []byte(fmt.Sprintf("{\"fingerprint\":\"%s\"}", fp)), 0600)
	return fp
}

func computeAuthChecksum(as *authState) string {
	if as == nil {
		return ""
	}
	secret := strings.TrimSpace(as.DeviceFingerprint)
	if secret == "" {
		return ""
	}
	fields := []string{
		strings.TrimSpace(as.LicenseKey),
		strings.TrimSpace(as.AccountID),
		strings.TrimSpace(as.DeviceID),
		strings.TrimSpace(as.AccessToken),
		strings.TrimSpace(as.RefreshToken),
		as.AccessExpiresAt.UTC().Format(time.RFC3339Nano),
		as.RefreshExpiresAt.UTC().Format(time.RFC3339Nano),
	}
	data := strings.Join(fields, "|")
	h := sha256.Sum256([]byte(secret + "|" + data))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func verifyAuthChecksum(as *authState) bool {
	if as == nil {
		return true
	}
	want := strings.TrimSpace(as.Checksum)
	if want == "" {
		return true
	}
	got := strings.TrimSpace(computeAuthChecksum(as))
	return got != "" && got == want
}

func runtimeOSArch() string {
	goos := strings.TrimSpace(os.Getenv("GOOS"))
	goarch := strings.TrimSpace(os.Getenv("GOARCH"))
	if goos == "" {
		goos = runtimeValue("GOOS")
	}
	if goarch == "" {
		goarch = runtimeValue("GOARCH")
	}
	if goos == "" {
		goos = "unknown"
	}
	if goarch == "" {
		goarch = "unknown"
	}
	return strings.ToLower(goos) + "/" + strings.ToLower(goarch)
}

func runtimeValue(key string) string {
	switch strings.TrimSpace(key) {
	case "GOOS":
		return runtime.GOOS
	case "GOARCH":
		return runtime.GOARCH
	default:
		return ""
	}
}
