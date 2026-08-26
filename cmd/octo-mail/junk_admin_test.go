package main

import (
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestCollectEMLPaths(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "nested")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	paths := []string{filepath.Join(dir, "b.eml"), filepath.Join(nested, "a.EML")}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte("Subject: test\r\n\r\nbody"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "ignore.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := collectEMLPaths([]string{dir, paths[0]})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{paths[0], paths[1]}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("paths = %v, want %v", got, want)
	}
}

func TestParseJunkEvaluateArgs(t *testing.T) {
	opts, err := parseJunkEvaluateArgs([]string{
		"evaluate-global", "eval/ham", "eval/spam", "--json", "report.json", "--csv", "report.csv",
	})
	if err != nil {
		t.Fatal(err)
	}
	if opts.hamPath != "eval/ham" || opts.spamPath != "eval/spam" ||
		opts.jsonPath != "report.json" || opts.csvPath != "report.csv" {
		t.Fatalf("options = %#v", opts)
	}
	if _, err := parseJunkEvaluateArgs([]string{"evaluate-global", "ham", "spam", "--wat", "x"}); err == nil {
		t.Fatal("unknown option accepted")
	}
}

func TestSummarizeJunkEvaluationAndZeroFPCutoff(t *testing.T) {
	rows := []junkEvaluationRow{
		{Label: "ham", Language: "zh", Probability: 0.10, Significant: true, Junk: false},
		{Label: "ham", Language: "en", Probability: 0.80, Significant: true, Junk: false},
		{Label: "spam", Language: "zh", Probability: 0.70, Significant: true, Junk: false},
		{Label: "spam", Language: "en", Probability: 0.90, Significant: true, Junk: true},
	}
	summary, candidate := summarizeJunkEvaluation(rows)
	if summary.Overall.HamCount != 2 || summary.Overall.HamFalsePositives != 0 ||
		summary.Overall.SpamCount != 2 || summary.Overall.SpamDetected != 1 {
		t.Fatalf("summary = %#v", summary)
	}
	if candidate == nil || !(candidate.Threshold > 0.80) || candidate.SpamRecall != 0.5 || candidate.HamFPR != 0 {
		t.Fatalf("candidate = %#v", candidate)
	}
	if math.IsNaN(candidate.Threshold) {
		t.Fatal("candidate threshold is NaN")
	}
	if summary.ByLanguage["zh"].HamCount != 1 || summary.ByLanguage["en"].SpamDetected != 1 {
		t.Fatalf("language metrics = %#v", summary.ByLanguage)
	}
}

func TestInferEvaluationLanguage(t *testing.T) {
	for path, want := range map[string]string{
		"curated/eval/ham/zh/a.eml":    "zh",
		"curated/eval/spam/en/b.eml":   "en",
		"curated/eval/ham/mixed/c.eml": "mixed",
		"curated/eval/ham/d.eml":       "unknown",
	} {
		if got := inferEvaluationLanguage(path); got != want {
			t.Errorf("inferEvaluationLanguage(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestReadTrainingMessageLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large.eml")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTrainingMessage(path, 4); err == nil {
		t.Fatal("oversized training message accepted")
	}
	raw, err := readTrainingMessage(path, 5)
	if err != nil || string(raw) != "12345" {
		t.Fatalf("bounded read = %q, %v", raw, err)
	}
}
