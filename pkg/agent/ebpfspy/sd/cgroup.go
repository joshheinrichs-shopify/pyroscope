package sd

import (
	"bufio"
	"context"
	"fmt"
	"os"

	"github.com/pyroscope-io/pyroscope/pkg/agent/spy"
)

type CgroupServiceDiscovery struct {
	pid2Labels map[uint32]*spy.Labels
}

func NewCgroupServiceDiscovery() ServiceDiscovery {
	return &CgroupServiceDiscovery{
		pid2Labels: map[uint32]*spy.Labels{},
	}
}

func (sd *CgroupServiceDiscovery) Refresh(_ context.Context) error {
	sd.pid2Labels = map[uint32]*spy.Labels{}
	return nil
}

func (sd *CgroupServiceDiscovery) GetLabels(pid uint32) *spy.Labels {
	ls, ok := sd.pid2Labels[pid]
	if ok {
		return ls
	}

	ls = spy.NewLabels()
	ls.Set("cgroup", getCgroupFromPid(pid))
	sd.pid2Labels[pid] = ls

	return ls
}

func getCgroupFromPid(pid uint32) string {
	f, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// cgroup v2 only for now
		if line != "" {
			return line
		}
	}
	return ""
}
