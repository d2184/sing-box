package parser

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestManualLinkCoverage(t *testing.T) {
	const path = "../../test.txt"
	f, err := os.Open(path)
	if err != nil {
		t.Skip("test.txt not found, skipping manual coverage check")
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	success := 0
	total := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		total++
		if _, err := ParseSubscriptionLink(line); err != nil {
			fmt.Printf("LINE %d FAILED: %v\n  %s\n", lineNum, err, line)
			continue
		}
		success++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("\n%d/%d succeeded\n", success, total)
}
