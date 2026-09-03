package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/junkfilter"
)

type junkEvaluationRow struct {
	Path        string  `json:"path"`
	Label       string  `json:"label"`
	Language    string  `json:"language"`
	Probability float64 `json:"probability"`
	Significant bool    `json:"significant"`
	Junk        bool    `json:"junk"`
}

type junkEvaluationMetrics struct {
	HamCount             int     `json:"hamCount"`
	HamFalsePositives    int     `json:"hamFalsePositives"`
	HamFalsePositiveRate float64 `json:"hamFalsePositiveRate"`
	SpamCount            int     `json:"spamCount"`
	SpamDetected         int     `json:"spamDetected"`
	SpamRecall           float64 `json:"spamRecall"`
}

type junkEvaluationSummary struct {
	Overall         junkEvaluationMetrics            `json:"overall"`
	InactiveSamples int                              `json:"inactiveSamples"`
	ByLanguage      map[string]junkEvaluationMetrics `json:"byLanguage"`
}

type junkCandidateThreshold struct {
	Threshold  float64 `json:"threshold"`
	HamFPR     float64 `json:"hamFpr"`
	SpamRecall float64 `json:"spamRecall"`
}

type junkEvaluationReport struct {
	SchemaVersion              int                     `json:"schemaVersion"`
	GeneratedAt                time.Time               `json:"generatedAt"`
	Model                      junkfilter.GlobalStats  `json:"model"`
	RuntimeEnabled             bool                    `json:"runtimeEnabled"`
	ConfiguredThreshold        float64                 `json:"configuredThreshold"`
	Summary                    junkEvaluationSummary   `json:"summary"`
	ZeroHamFalsePositiveCutoff *junkCandidateThreshold `json:"zeroHamFalsePositiveCutoff,omitempty"`
	Results                    []junkEvaluationRow     `json:"results"`
}

type junkEvaluateOptions struct {
	hamPath  string
	spamPath string
	jsonPath string
	csvPath  string
}

func parseJunkEvaluateArgs(args []string) (junkEvaluateOptions, error) {
	if len(args) < 3 {
		return junkEvaluateOptions{}, errors.New("usage: octo-mail junk evaluate-global <ham-file-or-directory> <spam-file-or-directory> [--json <path>] [--csv <path>]")
	}
	opts := junkEvaluateOptions{hamPath: args[1], spamPath: args[2]}
	for i := 3; i < len(args); i++ {
		if i+1 >= len(args) {
			return junkEvaluateOptions{}, fmt.Errorf("missing value for %s", args[i])
		}
		switch args[i] {
		case "--json":
			opts.jsonPath = args[i+1]
		case "--csv":
			opts.csvPath = args[i+1]
		default:
			return junkEvaluateOptions{}, fmt.Errorf("unknown evaluate-global option %q", args[i])
		}
		i++
	}
	return opts, nil
}

func evaluateGlobalCorpus(ctx context.Context, mgr *junkfilter.Manager, maxSize int64, hamPaths, spamPaths []string) (junkEvaluationReport, error) {
	stats, err := mgr.GlobalStats(ctx)
	if err != nil {
		return junkEvaluationReport{}, fmt.Errorf("read global model stats: %w", err)
	}
	report := junkEvaluationReport{
		SchemaVersion: 1, GeneratedAt: time.Now().UTC(), Model: stats,
		ConfiguredThreshold: mgr.SharedThreshold,
	}
	for _, item := range []struct {
		label string
		paths []string
	}{{"ham", hamPaths}, {"spam", spamPaths}} {
		for _, path := range item.paths {
			raw, err := readTrainingMessage(path, maxSize)
			if err != nil {
				return junkEvaluationReport{}, err
			}
			result, err := mgr.ClassifyGlobalDetailed(ctx, raw)
			if err != nil {
				return junkEvaluationReport{}, fmt.Errorf("classify %s: %w", path, err)
			}
			report.Results = append(report.Results, junkEvaluationRow{
				Path: path, Label: item.label, Language: inferEvaluationLanguage(path), Probability: result.Probability,
				Significant: result.Significant, Junk: result.Junk,
			})
		}
	}
	report.Summary, report.ZeroHamFalsePositiveCutoff = summarizeJunkEvaluation(report.Results)
	if !stats.Active {
		report.ZeroHamFalsePositiveCutoff = nil
	}
	return report, nil
}

func summarizeJunkEvaluation(rows []junkEvaluationRow) (junkEvaluationSummary, *junkCandidateThreshold) {
	summary := junkEvaluationSummary{ByLanguage: map[string]junkEvaluationMetrics{}}
	maxHam := -1.0
	for _, row := range rows {
		if !row.Significant {
			summary.InactiveSamples++
		}
		switch row.Label {
		case "ham":
			summary.Overall.HamCount++
			if row.Junk {
				summary.Overall.HamFalsePositives++
			}
			if row.Probability > maxHam {
				maxHam = row.Probability
			}
		case "spam":
			summary.Overall.SpamCount++
			if row.Junk {
				summary.Overall.SpamDetected++
			}
		}
		language := row.Language
		if language == "" {
			language = "unknown"
		}
		metrics := summary.ByLanguage[language]
		if row.Label == "ham" {
			metrics.HamCount++
			if row.Junk {
				metrics.HamFalsePositives++
			}
		} else if row.Label == "spam" {
			metrics.SpamCount++
			if row.Junk {
				metrics.SpamDetected++
			}
		}
		summary.ByLanguage[language] = metrics
	}
	if summary.Overall.HamCount > 0 {
		summary.Overall.HamFalsePositiveRate = float64(summary.Overall.HamFalsePositives) / float64(summary.Overall.HamCount)
	}
	if summary.Overall.SpamCount > 0 {
		summary.Overall.SpamRecall = float64(summary.Overall.SpamDetected) / float64(summary.Overall.SpamCount)
	}
	for language, metrics := range summary.ByLanguage {
		if metrics.HamCount > 0 {
			metrics.HamFalsePositiveRate = float64(metrics.HamFalsePositives) / float64(metrics.HamCount)
		}
		if metrics.SpamCount > 0 {
			metrics.SpamRecall = float64(metrics.SpamDetected) / float64(metrics.SpamCount)
		}
		summary.ByLanguage[language] = metrics
	}
	if maxHam < 0 || maxHam >= 1 {
		return summary, nil
	}
	threshold := math.Nextafter(maxHam, math.Inf(1))
	detected := 0
	for _, row := range rows {
		if row.Label == "spam" && row.Probability >= threshold {
			detected++
		}
	}
	recall := 0.0
	if summary.Overall.SpamCount > 0 {
		recall = float64(detected) / float64(summary.Overall.SpamCount)
	}
	return summary, &junkCandidateThreshold{Threshold: threshold, HamFPR: 0, SpamRecall: recall}
}

func inferEvaluationLanguage(path string) string {
	for _, part := range strings.FieldsFunc(strings.ToLower(filepath.ToSlash(path)), func(r rune) bool {
		return r == '/'
	}) {
		switch part {
		case "zh", "zh-cn", "chinese":
			return "zh"
		case "en", "english":
			return "en"
		case "mixed":
			return "mixed"
		}
	}
	return "unknown"
}

func writeJunkEvaluationJSON(path string, report junkEvaluationReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if path == "" || path == "-" {
		_, err = os.Stdout.Write(data)
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func writeJunkEvaluationCSV(path string, rows []junkEvaluationRow) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if err := w.Write([]string{"path", "label", "language", "probability", "significant", "junk"}); err != nil {
		return err
	}
	for _, row := range rows {
		if err := w.Write([]string{
			row.Path, row.Label, row.Language, strconv.FormatFloat(row.Probability, 'g', 17, 64),
			strconv.FormatBool(row.Significant), strconv.FormatBool(row.Junk),
		}); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}
