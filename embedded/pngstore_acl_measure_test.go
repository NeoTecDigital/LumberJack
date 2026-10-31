// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

var pngACLMeasure = flag.String("png-acl-measure", "", "Comma-separated labelled record counts; explicit diagnostic only")
var pngACLMeasureOut = flag.String("png-acl-measure-out", "", "Append measured lines to this file")

const pngACLStateMagic = "LUMBERJACK-STATE-2\nthis file is a flat node table\n"
const pngACLStateMagicReferences = "LUMBERJACK-STATE-3\nthis file is a flat node table\n"

type pngACLPoint struct {
	Records     int     `json:"records"`
	ForestBytes int     `json:"forestBytes"`
	FileBytes   int64   `json:"fileBytes"`
	WriteRows   int     `json:"writeRows"`
	WriteMillis []int64 `json:"writeMillis"`
	ReadRows    int     `json:"readRows"`
	ReadMillis  []int64 `json:"readMillis"`
	Refused     string  `json:"refused,omitempty"`
}

// The measure runs real commands against real bounds: a refusal is reported, never worked around.
func TestPNGSharedACLMeasure(t *testing.T) {
	if *pngACLMeasure == "" {
		t.Skip("explicit diagnostic requested only")
	}
	run := pngACLStart(t, *pngProfileArtifact, t.TempDir())
	defer closePNGFixture(t, run.handle)
	run.provision()
	records := 0
	for _, target := range pngACLTargets(t) {
		point := pngACLPoint{Records: target, WriteRows: 50, ReadRows: 25}
		var err error
		records, err = run.seedTo(records, target)
		point.ForestBytes, point.FileBytes = pngACLForestBytes(t, run.directory)
		if err == nil {
			err = run.measure(&point)
			records += len(point.WriteMillis) * point.WriteRows
		}
		pngACLReport(t, &point, records, err)
		if err != nil {
			return
		}
	}
}

func pngACLTargets(t *testing.T) []int {
	t.Helper()
	targets := []int{}
	for _, value := range strings.Split(*pngACLMeasure, ",") {
		target, err := strconv.Atoi(value)
		if err != nil {
			t.Fatal(err)
		}
		targets = append(targets, target)
	}
	return targets
}

func (run *pngACLRun) seedTo(records, target int) (int, error) {
	for records < target {
		count := run.config.ProvisioningProfile.Bounds.MaxChanges
		if target-records < count {
			count = target - records
		}
		if err := run.writeRows(count); err != nil {
			return records, err
		}
		records += count
	}
	return records, nil
}

func (run *pngACLRun) measure(point *pngACLPoint) error {
	for sample := 0; sample < 3; sample++ {
		start := time.Now()
		if err := run.readPage(point.ReadRows, pngACLAdministrator); err != nil {
			return err
		}
		point.ReadMillis = append(point.ReadMillis, time.Since(start).Milliseconds())
		start = time.Now()
		if err := run.writeRows(point.WriteRows); err != nil {
			return err
		}
		point.WriteMillis = append(point.WriteMillis, time.Since(start).Milliseconds())
	}
	return nil
}

func pngACLReport(t *testing.T, point *pngACLPoint, records int, failure error) {
	t.Helper()
	if failure != nil {
		point.Refused = fmt.Sprintf("after %d records: %v", records, failure)
	}
	raw, err := json.Marshal(point)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("LABELLED measure " + string(raw))
	if *pngACLMeasureOut == "" {
		return
	}
	stream, err := os.OpenFile(*pngACLMeasureOut, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err = stream.Write(append(raw, '\n')); err != nil {
		t.Fatal(err)
	}
}

// Decompressed forest bytes are what the scope and snapshot bounds count.
func pngACLForestBytes(t *testing.T, directory string) (int, int64) {
	t.Helper()
	raw, size := pngACLStateFile(t, directory)
	reader, err := gzip.NewReader(bytes.NewReader(raw[len(pngACLStateMagic)+32:]))
	if err != nil {
		t.Fatal(err)
	}
	count, err := io.Copy(io.Discard, reader)
	if err != nil {
		t.Fatal(err)
	}
	return int(count), size
}

func pngACLStateFile(t *testing.T, directory string) ([]byte, int64) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(directory, "*"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		raw, err := os.ReadFile(path)
		if err == nil && (bytes.HasPrefix(raw, []byte(pngACLStateMagic)) || bytes.HasPrefix(raw, []byte(pngACLStateMagicReferences))) {
			return raw, info.Size()
		}
	}
	t.Fatal("labelled state file absent")
	return nil, 0
}
