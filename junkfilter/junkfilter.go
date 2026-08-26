// Package junkfilter is octo-mail's deployment-wide Bayesian spam classifier.
// Operator-curated aggregate statistics provide the same reviewed baseline to
// every account. Runtime mailbox actions do not train account-local content
// models. Shared statistics live in PostgreSQL so every stateless node observes
// the same model. The message tokenizer is reused from the junk library; only
// bounded CJK features and SQL-backed Bayesian combination are added here.
package junkfilter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"math"
	"sort"
	"strings"
	"unicode"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mjl-/mox/junk"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
)

// DefaultParams mirror the localserve defaults: single words, gentle power,
// top-10 words, ignore near-neutral, rare-word threshold 2.
var DefaultParams = junk.Params{
	Onegrams:    true,
	MaxPower:    0.01,
	TopWords:    10,
	IgnoreWords: 0.1,
	RareWords:   2,
}

const (
	// A shared corpus is only allowed to influence delivery after both classes
	// have enough examples. Rspamd calls the equivalent guard min_learns and
	// documents 200 as its default; use the same conservative floor so a small,
	// unrepresentative seed set cannot affect every mailbox in the deployment.
	globalMinClassLearns = 200
	// Normalize corpus frequencies to a bounded scale so model size alone cannot
	// make rare features artificially overconfident.
	globalPriorPerClass = 20.0
	// Mox intentionally keeps CJK runs intact. Add bounded 2/3-rune features so
	// two similar Chinese messages can match without adopting Rspamd's ~5x OSB
	// token expansion for every language.
	maxCJKFeatures = 2048
	// DefaultSharedThreshold is deliberately conservative because one false
	// positive affects every mailbox in the deployment. Operators may tune this
	// after evaluating a frozen, representative holdout set.
	DefaultSharedThreshold = 0.9999
)

type wordCount struct {
	ham  float64
	spam float64
}

type corpus struct {
	hams  float64
	spams float64
	words map[string]wordCount
}

// Classification is the shared model's reversible routing result.
type Classification struct {
	Probability float64
	Significant bool
	Junk        bool
}

// GlobalStats reports whether the curated deployment-wide model has reached
// the minimum sample floor required to influence delivery.
type GlobalStats struct {
	Hams   int64 `json:"hams"`
	Spams  int64 `json:"spams"`
	Active bool  `json:"active"`
}

// Manager classifies mail with deployment-wide statistics backed by Postgres.
// It is safe for concurrent use; there is no per-node cache or divergent model.
type Manager struct {
	Pool            *pgxpool.Pool
	Params          junk.Params
	SharedThreshold float64 // shared-only probability >= SharedThreshold is junk

	log mlog.Log
}

// NewManager returns a deployment-wide classifier backed by PostgreSQL.
func NewManager(pool *pgxpool.Pool, params junk.Params) *Manager {
	return &Manager{
		Pool:            pool,
		Params:          params,
		SharedThreshold: DefaultSharedThreshold,
		log:             mlog.New("junkfilter", slog.Default()),
	}
}

// tokenize extracts the message's word set using the junk library's tokenizer
// (headers + text/html parts, n-grams per Params). The tokenizer reads only the
// Params, not any database/bloom state, so a params-only Filter value suffices.
// badContentType reports the junk-library signal that the message's Content-Type
// is malformed — a strong spam indicator the caller treats as certain-spam.
func (m *Manager) tokenize(raw []byte) (words map[string]struct{}, badContentType bool, err error) {
	f := &junk.Filter{Params: m.Params}
	part, perr := message.EnsurePart(m.log.Logger, false, bytes.NewReader(raw), int64(len(raw)))
	if perr != nil && errors.Is(perr, message.ErrBadContentType) {
		// Mirror the junk library: a bad content-type is a sure sign of spam.
		return nil, true, nil
	}
	// For any other parse trouble, EnsurePart still returns a best-effort Part;
	// tokenize what we can (an unreadable message simply yields few/no words).
	w, terr := f.ParseMessage(part)
	if terr != nil {
		return map[string]struct{}{}, false, nil
	}
	addCJKFeatures(w)
	return w, false, nil
}

// addCJKFeatures augments Mox's tokens with adjacent CJK rune pairs/triples.
// The source parser, MIME handling and base tokens remain Mox-owned; this only
// fixes the product-language gap where an entire Chinese sentence otherwise
// becomes one token and almost never matches a related message.
func addCJKFeatures(words map[string]struct{}) {
	original := make([]string, 0, len(words))
	for word := range words {
		original = append(original, word)
	}
	// Map iteration order is randomized. Keep the capped feature set stable so
	// training and later classification of the same message cannot select
	// different CJK features merely because they ran at different times.
	sort.Strings(original)
	added := 0
	for _, word := range original {
		prefix, text := "", word
		if i := strings.IndexByte(word, ':'); i > 0 {
			prefix, text = word[:i+1], word[i+1:]
		}
		// Keep only the last three CJK runes. A maliciously long unbroken CJK
		// token must not allocate a second rune slice proportional to its size.
		run := make([]rune, 0, 3)
		add := func(feature string) bool {
			if _, exists := words[feature]; exists {
				return true
			}
			words[feature] = struct{}{}
			added++
			return added < maxCJKFeatures
		}
		for _, r := range text {
			if !isCJK(r) {
				run = run[:0]
				continue
			}
			run = append(run, r)
			if len(run) >= 2 && !add(prefix+"cjk:"+string(run[len(run)-2:])) {
				return
			}
			if len(run) >= 3 {
				if !add(prefix + "cjk:" + string(run[len(run)-3:])) {
					return
				}
				run = run[len(run)-2:]
			}
		}
	}
}

func isCJK(r rune) bool {
	return unicode.Is(unicode.Han, r) || unicode.Is(unicode.Hiragana, r) ||
		unicode.Is(unicode.Katakana, r) || unicode.Is(unicode.Hangul, r)
}

// Classify returns the spam probability [0,1], whether the classification is
// significant (enough trained ham), and whether it exceeds the junk threshold.
func (m *Manager) Classify(ctx context.Context, accountID int64, raw []byte) (prob float64, significant, isJunk bool, err error) {
	result, err := m.ClassifyDetailed(ctx, accountID, raw)
	return result.Probability, result.Significant, result.Junk, err
}

// ClassifyDetailed evaluates only the reviewed deployment-wide model. accountID
// remains in the signature for the protocol classifier interface, but runtime
// classification deliberately does not consult account-local word statistics.
func (m *Manager) ClassifyDetailed(ctx context.Context, _ int64, raw []byte) (Classification, error) {
	return m.ClassifyGlobalDetailed(ctx, raw)
}

// ClassifyGlobalDetailed evaluates only the deployment-wide curated model. It
// uses the same bounded-count math as production, so offline corpus evaluation
// cannot accidentally test a stronger raw-count model. Content classification
// only chooses Inbox versus Junk; malformed Content-Type remains the existing
// parser signal but does not gain reject authority.
func (m *Manager) ClassifyGlobalDetailed(ctx context.Context, raw []byte) (Classification, error) {
	words, badCT, err := m.tokenize(raw)
	if err != nil {
		return Classification{}, err
	}
	if badCT {
		return Classification{Probability: 1, Significant: true, Junk: true}, nil
	}
	global, err := m.loadGlobal(ctx, words)
	if err != nil {
		return Classification{}, err
	}
	if global.hams < globalMinClassLearns || global.spams < globalMinClassLearns {
		return Classification{Probability: 0.5}, nil
	}
	prior := make(map[string]wordCount, len(words))
	for word := range words {
		count := global.words[word]
		if count.ham != 0 || count.spam != 0 {
			prior[word] = wordCount{
				ham:  globalPriorPerClass * count.ham / global.hams,
				spam: globalPriorPerClass * count.spam / global.spams,
			}
		}
	}
	prob := m.probability(words, prior, globalPriorPerClass, globalPriorPerClass)
	return Classification{
		Probability: prob, Significant: true, Junk: prob >= m.sharedThreshold(),
	}, nil
}

func (m *Manager) sharedThreshold() float64 {
	if m.SharedThreshold > 0 {
		return m.SharedThreshold
	}
	return DefaultSharedThreshold
}

// GlobalStats returns the current shared corpus totals without loading its word
// table. It is intended for operator status and offline evaluation output.
func (m *Manager) GlobalStats(ctx context.Context) (GlobalStats, error) {
	var stats GlobalStats
	err := m.Pool.QueryRow(ctx,
		`SELECT hams, spams FROM junk_global_totals WHERE singleton=true`).Scan(&stats.Hams, &stats.Spams)
	if errors.Is(err, pgx.ErrNoRows) {
		return stats, nil
	}
	if err != nil {
		return GlobalStats{}, err
	}
	stats.Active = stats.Hams >= globalMinClassLearns && stats.Spams >= globalMinClassLearns
	return stats, nil
}

func (m *Manager) loadGlobal(ctx context.Context, words map[string]struct{}) (corpus, error) {
	result := corpus{words: map[string]wordCount{}}
	var hams, spams int64
	err := m.Pool.QueryRow(ctx,
		`SELECT hams, spams FROM junk_global_totals WHERE singleton=true`).Scan(&hams, &spams)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, nil
	}
	if err != nil {
		return corpus{}, err
	}
	result.hams, result.spams = float64(hams), float64(spams)
	// The bundled model stores only hashed feature identifiers, not readable
	// snippets from training email. Keep the original token as the in-memory key
	// because probability() iterates the message's original token set.
	wl := make([]string, 0, len(words))
	originalByFeature := make(map[string]string, len(words))
	for word := range words {
		feature := globalFeature(word)
		wl = append(wl, feature)
		originalByFeature[feature] = word
	}
	if len(wl) == 0 {
		return result, nil
	}
	rows, err := m.Pool.Query(ctx,
		`SELECT word, ham, spam FROM junk_global_words WHERE word = ANY($1)`, wl)
	if err != nil {
		return corpus{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var word string
		var ham, spam int64
		if err := rows.Scan(&word, &ham, &spam); err != nil {
			return corpus{}, err
		}
		if original, ok := originalByFeature[word]; ok {
			result.words[original] = wordCount{float64(ham), float64(spam)}
		}
	}
	return result, rows.Err()
}

// wordScore is a per-word spaminess used for the top-N selection.
type wordScore struct {
	word  string
	score float64
}

// probability ports the junk library's bayesian combination verbatim (see
// junk.Filter.ClassifyWords): per-word spaminess r = (spam/spams)/(spam/spams +
// ham/hams), clamped to [MaxPower, 1-MaxPower], with rare-word power reduction and
// near-neutral (IgnoreWords) skipping; the TopWords most hammy and spammy are
// combined via log-odds into a final probability.
func (m *Manager) probability(words map[string]struct{}, counts map[string]wordCount, hams, spams float64) float64 {
	p := m.Params
	var hamHigh float64 = 0
	var spamLow float64 = 1
	var topHam, topSpam []wordScore

	for w := range words {
		c, ok := counts[w]
		if !ok {
			continue
		}
		var wS, wH float64
		if spams > 0 {
			wS = c.spam / spams
		}
		if hams > 0 {
			wH = c.ham / hams
		}
		if wS+wH == 0 {
			continue
		}
		r := wS / (wS + wH)
		if r < p.MaxPower {
			r = p.MaxPower
		} else if r >= 1-p.MaxPower {
			r = 1 - p.MaxPower
		}
		if c.ham+c.spam <= float64(p.RareWords) {
			r += (1 + float64(p.RareWords) - (c.ham + c.spam)) * (0.5 - r) / 10
		}
		if math.Abs(0.5-r) < p.IgnoreWords {
			continue
		}
		if r < 0.5 {
			if len(topHam) >= p.TopWords && r > hamHigh {
				continue
			}
			topHam = append(topHam, wordScore{w, r})
			if r > hamHigh {
				hamHigh = r
			}
		} else if r > 0.5 {
			if len(topSpam) >= p.TopWords && r < spamLow {
				continue
			}
			topSpam = append(topSpam, wordScore{w, r})
			if r < spamLow {
				spamLow = r
			}
		}
	}

	sort.Slice(topHam, func(i, j int) bool {
		a, b := topHam[i], topHam[j]
		if a.score == b.score {
			return len(a.word) > len(b.word)
		}
		return a.score < b.score
	})
	sort.Slice(topSpam, func(i, j int) bool {
		a, b := topSpam[i], topSpam[j]
		if a.score == b.score {
			return len(a.word) > len(b.word)
		}
		return a.score > b.score
	})
	if len(topHam) > p.TopWords {
		topHam = topHam[:p.TopWords]
	}
	if len(topSpam) > p.TopWords {
		topSpam = topSpam[:p.TopWords]
	}

	var eta float64
	for _, x := range topHam {
		eta += math.Log(1-x.score) - math.Log(x.score)
	}
	for _, x := range topSpam {
		eta += math.Log(1-x.score) - math.Log(x.score)
	}
	return 1 / (1 + math.Pow(math.E, eta))
}

// Train updates legacy account-local counters. It remains available for source
// compatibility, but production IMAP/JMAP/WebAPI paths do not call it and
// ClassifyDetailed does not read those counters.
//
// A message that yields no trainable words is NOT trained at all (no totals bump):
// a bad Content-Type (tokenize's certain-spam shortcut) or a parse failure returns
// an empty word set, and bumping junk_totals.hams/spams without writing any
// junk_words rows would inflate the account's denominator with no matching word
// evidence — shrinking every other word's spam/ham ratio and skewing all future
// classifications. mox's TrainMessage likewise trains nothing on such messages.
func (m *Manager) Train(ctx context.Context, accountID int64, ham bool, raw []byte) error {
	words, badCT, err := m.tokenize(raw)
	if err != nil {
		return err
	}
	// No trainable words → train nothing (see the denominator-skew note above).
	// Covers both the bad-Content-Type shortcut and a swallowed parse failure.
	if badCT || len(words) == 0 {
		return nil
	}
	wl := sortedWords(words)

	return pgx.BeginFunc(ctx, m.Pool, func(tx pgx.Tx) error {
		hamDelta, spamDelta := 0, 1
		if ham {
			hamDelta, spamDelta = 1, 0
		}
		return applyPersonalDelta(ctx, tx, accountID, wl, hamDelta, spamDelta)
	})
}

func sortedWords(words map[string]struct{}) []string {
	// Stable order prevents concurrent training transactions from taking word-row
	// locks in opposite orders and deadlocking.
	wl := make([]string, 0, len(words))
	for word := range words {
		wl = append(wl, word)
	}
	sort.Strings(wl)
	return wl
}

func sortedGlobalFeatures(words map[string]struct{}) []string {
	features := make([]string, 0, len(words))
	for word := range words {
		features = append(features, globalFeature(word))
	}
	sort.Strings(features)
	return features
}

func globalFeature(word string) string {
	sum := sha256.Sum256([]byte(word))
	return hex.EncodeToString(sum[:])
}

func applyPersonalDelta(ctx context.Context, tx pgx.Tx, accountID int64, words []string, hamDelta, spamDelta int) error {
	if _, err := tx.Exec(ctx,
		`INSERT INTO junk_totals (account_id, hams, spams) VALUES ($1,$2,$3)
		 ON CONFLICT (account_id) DO UPDATE SET hams = junk_totals.hams + $2, spams = junk_totals.spams + $3`,
		accountID, hamDelta, spamDelta); err != nil {
		return err
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO junk_words (account_id, word, ham, spam)
		 SELECT $1, w, $3, $4 FROM unnest($2::text[]) AS w
		 ON CONFLICT (account_id, word) DO UPDATE SET ham = junk_words.ham + $3, spam = junk_words.spam + $4`,
		accountID, words, hamDelta, spamDelta)
	return err
}

func applyGlobalDelta(ctx context.Context, tx pgx.Tx, words []string, hamDelta, spamDelta int) error {
	if _, err := tx.Exec(ctx,
		`INSERT INTO junk_global_totals (singleton, hams, spams) VALUES (true,$1,$2)
		 ON CONFLICT (singleton) DO UPDATE SET hams = junk_global_totals.hams + $1, spams = junk_global_totals.spams + $2`,
		hamDelta, spamDelta); err != nil {
		return err
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO junk_global_words (word, ham, spam)
		 SELECT w, $2, $3 FROM unnest($1::text[]) AS w
		 ON CONFLICT (word) DO UPDATE SET ham = junk_global_words.ham + $2, spam = junk_global_words.spam + $3`,
		words, hamDelta, spamDelta)
	return err
}

// TrainGlobalSample adds or relabels one operator-curated sample in the
// deployment-wide model. sampleID must be stable (the CLI uses SHA-256 of the
// raw message), making repeated corpus imports safe.
func (m *Manager) TrainGlobalSample(ctx context.Context, sampleID string, ham bool, raw []byte) (bool, error) {
	if strings.TrimSpace(sampleID) == "" {
		return false, errors.New("global junk training requires a sample id")
	}
	words, badCT, err := m.tokenize(raw)
	if err != nil {
		return false, err
	}
	if badCT || len(words) == 0 {
		return false, nil
	}
	wl := sortedGlobalFeatures(words)
	changed := false
	err = pgx.BeginFunc(ctx, m.Pool, func(tx pgx.Tx) error {
		previous, exists, err := lockGlobalLearn(ctx, tx, sampleID, ham)
		if err != nil || exists && previous == ham {
			return err
		}
		hamDelta, spamDelta := 0, 0
		if exists {
			if previous {
				hamDelta--
			} else {
				spamDelta--
			}
		}
		if ham {
			hamDelta++
		} else {
			spamDelta++
		}
		if err := applyGlobalDelta(ctx, tx, wl, hamDelta, spamDelta); err != nil {
			return err
		}
		if exists {
			if _, err := tx.Exec(ctx,
				`UPDATE junk_global_learns SET ham=$2, updated_at=now() WHERE sample_id=$1`,
				sampleID, ham); err != nil {
				return err
			}
		}
		changed = true
		return nil
	})
	return changed, err
}

func lockGlobalLearn(ctx context.Context, tx pgx.Tx, sampleID string, ham bool) (previous, exists bool, err error) {
	err = tx.QueryRow(ctx,
		`INSERT INTO junk_global_learns (sample_id,ham) VALUES ($1,$2)
		 ON CONFLICT (sample_id) DO NOTHING RETURNING ham`, sampleID, ham).Scan(&previous)
	if err == nil {
		return previous, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return false, false, err
	}
	err = tx.QueryRow(ctx,
		`SELECT ham FROM junk_global_learns WHERE sample_id=$1 FOR UPDATE`, sampleID).Scan(&previous)
	return previous, true, err
}

// Close is a no-op: there is no per-node state to flush (the database owns it).
// Retained so existing call sites (defer mgr.Close()) keep working.
func (m *Manager) Close() error { return nil }
