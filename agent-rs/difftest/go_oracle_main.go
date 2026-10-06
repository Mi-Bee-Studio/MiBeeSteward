// Differential-test oracle: classify JSONL evidence batches with the Go
// implementation (mibee-fingerprints-go RuleClassifier) and print identities
// as JSONL. Built into a throwaway module under mibee-fingerprints-go/tmp/.
//
// Input line:  {"dir":"<corpus dir>","evidence":[{...},{...}]}
// Output line: {"line":N,"identities":[...]}  (identities verbatim from Classify)
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	fp "github.com/Mi-Bee-Studio/mibee-fingerprints-go"
)

type req struct {
	Dir      string        `json:"dir"`
	Evidence []fp.Evidence `json:"evidence"`
}

type resp struct {
	Line       int                  `json:"line"`
	Identities []fp.ServiceIdentity `json:"identities"`
}

func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	line := 0
	cls := &fp.RuleClassifier{}
	loaded := ""
	for sc.Scan() {
		line++
		var r req
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			fmt.Fprintf(os.Stderr, "line %d: %v\n", line, err)
			os.Exit(1)
		}
		if r.Dir != loaded {
			cls = &fp.RuleClassifier{}
			if err := cls.LoadFromDir(r.Dir); err != nil {
				fmt.Fprintf(os.Stderr, "load %s: %v\n", r.Dir, err)
				os.Exit(1)
			}
			loaded = r.Dir
		}
		out := resp{Line: line, Identities: cls.Classify(r.Evidence)}
		b, _ := json.Marshal(out)
		w.Write(b)
		w.WriteByte('\n')
	}
}
