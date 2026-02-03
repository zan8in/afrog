package manifest

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
)

type Manifest struct {
	ManifestID string     `json:"manifest_id"`
	Channel    string     `json:"channel"`
	Artifacts  []Artifact `json:"artifacts"`
}

type Artifact struct {
	ArtifactID     string `json:"artifact_id"`
	Type           string `json:"type"`
	BaseManifestID string `json:"base_manifest_id"`
	Size           int64  `json:"size"`
	SHA256         string `json:"sha256"`
	Enc            Enc    `json:"enc"`
}

type Enc struct {
	Format string `json:"format"`
	Alg    string `json:"alg"`
}

func ParseAndVerify(manifestJSONB64 string, manifestSigB64 string) (*Manifest, error) {
	manBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(manifestJSONB64))
	if err != nil {
		return nil, err
	}
	sigBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(manifestSigB64))
	if err != nil {
		return nil, err
	}

	pubKeyB64 := strings.TrimSpace(os.Getenv("AFROG_CURATED_MANIFEST_PUBKEY_B64"))
	if pubKeyB64 != "" {
		pk, err := base64.StdEncoding.DecodeString(pubKeyB64)
		if err != nil {
			return nil, err
		}
		if len(pk) != ed25519.PublicKeySize {
			return nil, errors.New("invalid manifest pubkey size")
		}
		if !ed25519.Verify(ed25519.PublicKey(pk), manBytes, sigBytes) {
			return nil, errors.New("manifest signature verify failed")
		}
	}

	var m Manifest
	if err := json.Unmarshal(manBytes, &m); err != nil {
		return nil, err
	}
	if strings.TrimSpace(m.ManifestID) == "" {
		return nil, errors.New("missing manifest_id")
	}
	return &m, nil
}

func (m *Manifest) SelectBestArtifact(currentManifestID string) (Artifact, bool) {
	if m == nil || len(m.Artifacts) == 0 {
		return Artifact{}, false
	}
	cur := strings.TrimSpace(currentManifestID)
	if cur != "" {
		for _, a := range m.Artifacts {
			if strings.ToLower(strings.TrimSpace(a.Type)) == "patch" && strings.TrimSpace(a.BaseManifestID) == cur {
				return a, true
			}
		}
	}
	for _, a := range m.Artifacts {
		if strings.ToLower(strings.TrimSpace(a.Type)) == "full" || strings.TrimSpace(a.Type) == "" {
			return a, true
		}
	}
	return m.Artifacts[0], true
}

