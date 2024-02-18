package runner

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/rs/xid"
	fileutil "github.com/zan8in/pins/file"
)

var PoCScanProgress []string

type ScanProgress struct {
	progress       []string
	resumeProgress []string
	mutex          sync.Mutex
}

func NewScanProgress(resume string) (*ScanProgress, error) {
	progress := make([]string, 0)
	resumeProgress := make([]string, 0)

	if len(resume) > 0 {
		if rsChan, err := fileutil.ReadFile(resume); err != nil {
			return nil, err
		} else {
			for r := range rsChan {
				list := strings.Split(r, ",")
				resumeProgress = append(resumeProgress, list...)
			}
		}
	}

	return &ScanProgress{
		progress:       progress,
		resumeProgress: resumeProgress,
	}, nil
}

func (p *ScanProgress) Increment(id string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.progress = append(p.progress, id)
}

func (p *ScanProgress) Contains(id string) bool {
	for _, item := range p.resumeProgress {
		if item == id {
			return true
		}
	}
	return false
}

func (p *ScanProgress) String() string {
	return strings.Join(p.progress, ",")
}

func (p *ScanProgress) SaveScanProgress() (string, error) {
	resumeFileName := fmt.Sprintf("afrog-resume-%s.afg", xid.New().String())

	if len(p.progress) > 0 {
		return resumeFileName, os.WriteFile(resumeFileName, []byte(strings.Join(p.progress, ",")), 0666)
	}

	return "", nil
}
