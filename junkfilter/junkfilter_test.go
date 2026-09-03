package junkfilter_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/junkfilter"
	"github.com/jackc/pgx/v5/pgxpool"
)

func distinctCJKText(n int) string {
	runes := make([]rune, n)
	for i := range runes {
		runes[i] = rune(0x4e00 + i)
	}
	return string(runes)
}

func foldedCJKSubject(lines, runesPerLine int) string {
	text := []rune(distinctCJKText(lines * runesPerLine))
	var b strings.Builder
	for line := 0; line < lines; line++ {
		if line == 0 {
			b.WriteString("Subject: ")
		} else {
			b.WriteByte(' ')
		}
		start := line * runesPerLine
		b.WriteString(string(text[start : start+runesPerLine]))
		b.WriteString("\r\n")
	}
	return b.String()
}

func modelPackage(t *testing.T, version string, hams, spams int64, words map[string][2]int64) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	cw := csv.NewWriter(zw)
	if err := cw.Write([]string{"octo-junk-model", "1", version,
		strconv.FormatInt(hams, 10), strconv.FormatInt(spams, 10), strconv.Itoa(len(words))}); err != nil {
		t.Fatal(err)
	}
	for word, counts := range words {
		if err := cw.Write([]string{word, strconv.FormatInt(counts[0], 10), strconv.FormatInt(counts[1], 10)}); err != nil {
			t.Fatal(err)
		}
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func modelFeature(word string) string {
	sum := sha256.Sum256([]byte(word))
	return hex.EncodeToString(sum[:])
}

const testDSN = "postgres://octo_mail:octo_mail@localhost:55432/octo_mail"

func openJunkPool(t *testing.T, ctx context.Context) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(ctx, testDSN)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("postgres not available (%v)", err)
	}
	// DDL mirrors storage/postgres/schema/09_junkfilter.sql. These tests use a raw
	// pool (not postgres.Open, which applies the full schema and needs a blob store)
	// to stay self-contained — same pattern as the ha tests. Keep in sync with the
	// real schema; a column/index change there must be reflected here or a test
	// could pass against a table shape production never has.
	for _, ddl := range []string{
		`CREATE TABLE IF NOT EXISTS junk_words (account_id bigint NOT NULL, word text NOT NULL, ham bigint NOT NULL DEFAULT 0, spam bigint NOT NULL DEFAULT 0, PRIMARY KEY (account_id, word))`,
		`CREATE TABLE IF NOT EXISTS junk_totals (account_id bigint NOT NULL PRIMARY KEY, hams bigint NOT NULL DEFAULT 0, spams bigint NOT NULL DEFAULT 0)`,
		`CREATE TABLE IF NOT EXISTS junk_global_words (word text PRIMARY KEY, ham bigint NOT NULL DEFAULT 0, spam bigint NOT NULL DEFAULT 0)`,
		`CREATE TABLE IF NOT EXISTS junk_global_totals (singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton), hams bigint NOT NULL DEFAULT 0, spams bigint NOT NULL DEFAULT 0)`,
		`CREATE TABLE IF NOT EXISTS junk_global_learns (sample_id text PRIMARY KEY, ham boolean NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())`,
		`CREATE TABLE IF NOT EXISTS junk_sender_allowlist (account_id bigint NOT NULL, sender_address text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (account_id, sender_address)) PARTITION BY HASH (account_id)`,
		`CREATE TABLE IF NOT EXISTS junk_sender_allowlist_p0 PARTITION OF junk_sender_allowlist FOR VALUES WITH (MODULUS 4, REMAINDER 0)`,
		`CREATE TABLE IF NOT EXISTS junk_sender_allowlist_p1 PARTITION OF junk_sender_allowlist FOR VALUES WITH (MODULUS 4, REMAINDER 1)`,
		`CREATE TABLE IF NOT EXISTS junk_sender_allowlist_p2 PARTITION OF junk_sender_allowlist FOR VALUES WITH (MODULUS 4, REMAINDER 2)`,
		`CREATE TABLE IF NOT EXISTS junk_sender_allowlist_p3 PARTITION OF junk_sender_allowlist FOR VALUES WITH (MODULUS 4, REMAINDER 3)`,
	} {
		if _, err := pool.Exec(ctx, ddl); err != nil {
			pool.Close()
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `TRUNCATE junk_words, junk_totals, junk_global_words, junk_global_totals, junk_global_learns, junk_sender_allowlist`); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	return pool
}

func TestSenderAllowlistIsExactAndAccountScoped(t *testing.T) {
	ctx := context.Background()
	pool := openJunkPool(t, ctx)
	defer pool.Close()
	mgr := junkfilter.NewManager(pool, junkfilter.DefaultParams)
	if _, err := pool.Exec(ctx,
		`INSERT INTO junk_sender_allowlist (account_id,sender_address) VALUES (1,'trusted@example.com')`); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		accountID int64
		sender    string
		want      bool
	}{
		{1, "trusted@example.com", true},
		{1, "TRUSTED@EXAMPLE.COM", true},
		{1, "other@example.com", false},
		{2, "trusted@example.com", false},
		{1, "not an address", false},
	} {
		got, err := mgr.SenderAllowed(ctx, test.accountID, test.sender)
		if err != nil {
			t.Fatalf("SenderAllowed(%d,%q): %v", test.accountID, test.sender, err)
		}
		if got != test.want {
			t.Fatalf("SenderAllowed(%d,%q) = %v, want %v", test.accountID, test.sender, got, test.want)
		}
	}
}

func spamMsg(i int) []byte {
	return []byte(fmt.Sprintf("From: promo@deals.example\r\nSubject: WINNER buy cheap viagra pills now\r\n\r\n"+
		"Congratulations you WON a FREE prize! Click now to claim cheap meds, cheap loans, cheap watches. Limited offer %d. Act now!!!\r\n", i))
}

func hamMsg(i int) []byte {
	return []byte(fmt.Sprintf("From: alice@work.example\r\nSubject: project sync notes\r\n\r\n"+
		"Hi team, attached are the notes from today's engineering sync. Let's review the migration plan and schedule the deployment for next week. Item %d.\r\n", i))
}

// TestSharedModelAppliesToEveryAccount proves that the deployment model is
// account-independent: the same reviewed model classifies mail for an otherwise
// untrained mailbox, without creating account-local word statistics.
func TestSharedModelAppliesToEveryAccount(t *testing.T) {
	ctx := context.Background()
	pool := openJunkPool(t, ctx)
	defer pool.Close()
	mgr := junkfilter.NewManager(pool, junkfilter.DefaultParams)
	defer mgr.Close()

	const accA, accB = int64(1), int64(2)
	for i := 0; i < 200; i++ {
		if _, err := mgr.TrainGlobalSample(ctx, fmt.Sprintf("spam-%d", i), false, spamMsg(i)); err != nil {
			t.Fatalf("train shared spam %d: %v", i, err)
		}
		if _, err := mgr.TrainGlobalSample(ctx, fmt.Sprintf("ham-%d", i), true, hamMsg(i)); err != nil {
			t.Fatalf("train shared ham %d: %v", i, err)
		}
	}

	probSpam, sigSpam, isJunkSpam, err := mgr.Classify(ctx, accA, spamMsg(1000))
	if err != nil {
		t.Fatalf("classify spam: %v", err)
	}
	if !sigSpam {
		t.Fatalf("spam classification not significant (prob=%.3f)", probSpam)
	}
	if !isJunkSpam {
		t.Fatalf("held-out spam not classified as junk (prob=%.3f, want >= 0.95)", probSpam)
	}

	probHam, _, isJunkHam, err := mgr.Classify(ctx, accA, hamMsg(1000))
	if err != nil {
		t.Fatalf("classify ham: %v", err)
	}
	if isJunkHam {
		t.Fatalf("held-out ham misclassified as junk (prob=%.3f)", probHam)
	}
	if probHam >= probSpam {
		t.Fatalf("ham prob %.3f not below spam prob %.3f — filter not discriminating", probHam, probSpam)
	}

	probB, sigB, isJunkB, err := mgr.Classify(ctx, accB, spamMsg(1000))
	if err != nil {
		t.Fatalf("classify B: %v", err)
	}
	if !sigB || !isJunkB || probB != probSpam {
		t.Fatalf("account B classification = (%.6f,%v,%v), want same shared result as account A (%.6f,true,true)", probB, sigB, isJunkB, probSpam)
	}
	var personalRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM junk_words`).Scan(&personalRows); err != nil {
		t.Fatal(err)
	}
	if personalRows != 0 {
		t.Fatalf("classification created %d account-local word rows", personalRows)
	}
}

// TestJunkSharedAcrossNodes proves the #24-7 fix: junk state is shared via
// Postgres, so training performed by one node ("Manager") is visible to another
// node's Manager on the same database. Before the fix (per-node files) node B
// would classify with zero learned words.
func TestJunkSharedAcrossNodes(t *testing.T) {
	ctx := context.Background()
	pool := openJunkPool(t, ctx)
	defer pool.Close()

	nodeA := junkfilter.NewManager(pool, junkfilter.DefaultParams)
	nodeB := junkfilter.NewManager(pool, junkfilter.DefaultParams)

	for i := 0; i < 200; i++ {
		if _, err := nodeA.TrainGlobalSample(ctx, fmt.Sprintf("node-spam-%d", i), false, spamMsg(i)); err != nil {
			t.Fatalf("nodeA train shared spam %d: %v", i, err)
		}
		if _, err := nodeA.TrainGlobalSample(ctx, fmt.Sprintf("node-ham-%d", i), true, hamMsg(i)); err != nil {
			t.Fatalf("nodeA train shared ham %d: %v", i, err)
		}
	}

	// Classify on node B for any account — it must see node A's deployment model.
	prob, sig, isJunk, err := nodeB.Classify(ctx, 999, spamMsg(1000))
	if err != nil {
		t.Fatalf("nodeB classify: %v", err)
	}
	if !sig {
		t.Fatalf("nodeB classification not significant — training not shared across nodes (prob=%.3f)", prob)
	}
	if !isJunk {
		t.Fatalf("nodeB did not classify held-out spam as junk (prob=%.3f) — shared state broken", prob)
	}
	t.Logf("OK: node B classified spam as junk (prob=%.3f) from node A's training — junk state shared via Postgres", prob)
}

// TestTrainNothingOnNoWords proves the #42 review fix: a message that yields no
// trainable words (empty/wordless body, or a parse failure that tokenize turns
// into an empty word set) must NOT bump junk_totals. A denominator bumped without
// any junk_words rows would skew every other word's spam/ham ratio and drift all
// future classifications for the account. (The bad-Content-Type shortcut folds
// into the same guard; with the non-strict parser used here the reachable trigger
// is the empty-word set.)
func TestTrainNothingOnNoWords(t *testing.T) {
	ctx := context.Background()
	pool := openJunkPool(t, ctx)
	defer pool.Close()
	mgr := junkfilter.NewManager(pool, junkfilter.DefaultParams)
	defer mgr.Close()

	const acc = int64(7)
	// A message with no header/body tokens → empty word set (verified via the
	// tokenizer: headers are tokenized too, so this must carry no address/subject).
	noWords := []byte("\r\n\r\n")
	if err := mgr.Train(ctx, acc, false, noWords); err != nil {
		t.Fatalf("train no-words: %v", err)
	}

	// No totals row should have been written (train-nothing).
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM junk_totals WHERE account_id=$1`, acc).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("junk_totals bumped for a no-trainable-words train (rows=%d) — denominator skew", n)
	}
	var w int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM junk_words WHERE account_id=$1`, acc).Scan(&w); err != nil {
		t.Fatal(err)
	}
	if w != 0 {
		t.Fatalf("junk_words written for a no-trainable-words train (rows=%d)", w)
	}
	t.Logf("OK: a no-trainable-words message trains nothing (no denominator skew)")
}

func TestGlobalActivationAndAccountIndependence(t *testing.T) {
	ctx := context.Background()
	pool := openJunkPool(t, ctx)
	defer pool.Close()
	mgr := junkfilter.NewManager(pool, junkfilter.DefaultParams)

	for i := 0; i < 199; i++ {
		if _, err := mgr.TrainGlobalSample(ctx, fmt.Sprintf("spam-%d", i), false, spamMsg(i)); err != nil {
			t.Fatal(err)
		}
		if _, err := mgr.TrainGlobalSample(ctx, fmt.Sprintf("ham-%d", i), true, hamMsg(i)); err != nil {
			t.Fatal(err)
		}
	}

	const firstAccount, secondAccount = int64(101), int64(102)
	insufficient, err := mgr.ClassifyDetailed(ctx, firstAccount, spamMsg(1000))
	if err != nil {
		t.Fatal(err)
	}
	if insufficient.Significant || insufficient.Junk {
		t.Fatalf("199 samples per global class activated shared model: %#v", insufficient)
	}
	globalOnly, err := mgr.ClassifyGlobalDetailed(ctx, spamMsg(1000))
	if err != nil {
		t.Fatal(err)
	}
	if globalOnly.Significant || globalOnly.Junk {
		t.Fatalf("199 samples per class activated global-only evaluation: %#v", globalOnly)
	}
	if _, err := mgr.TrainGlobalSample(ctx, "spam-199", false, spamMsg(199)); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.TrainGlobalSample(ctx, "ham-199", true, hamMsg(199)); err != nil {
		t.Fatal(err)
	}

	before, err := mgr.ClassifyDetailed(ctx, firstAccount, spamMsg(1000))
	if err != nil {
		t.Fatal(err)
	}
	if !before.Significant || !before.Junk {
		t.Fatalf("shared classification = %#v, want significant Junk", before)
	}
	globalOnly, err = mgr.ClassifyGlobalDetailed(ctx, spamMsg(1000))
	if err != nil {
		t.Fatal(err)
	}
	if !globalOnly.Significant || !globalOnly.Junk {
		t.Fatalf("shared evaluation = %#v, want active Junk", globalOnly)
	}
	if globalOnly.Probability != before.Probability {
		t.Fatalf("global evaluation probability %.6f differs from production no-personal path %.6f", globalOnly.Probability, before.Probability)
	}
	stats, err := mgr.GlobalStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Hams != 200 || stats.Spams != 200 || !stats.Active {
		t.Fatalf("global stats = %#v, want 200/200 active", stats)
	}

	other, err := mgr.ClassifyDetailed(ctx, secondAccount, spamMsg(1000))
	if err != nil {
		t.Fatal(err)
	}
	if other != before {
		t.Fatalf("account-scoped inputs changed shared classification: first=%#v second=%#v", before, other)
	}
}

func TestGlobalTrainingIsIdempotentAndRelabelable(t *testing.T) {
	ctx := context.Background()
	pool := openJunkPool(t, ctx)
	defer pool.Close()
	mgr := junkfilter.NewManager(pool, junkfilter.DefaultParams)
	msg := spamMsg(1)

	var hams, spams int64
	changed, err := mgr.TrainGlobalSample(ctx, "same-sample", false, msg)
	if err != nil || !changed {
		t.Fatalf("first global train changed=%v err=%v", changed, err)
	}
	changed, err = mgr.TrainGlobalSample(ctx, "same-sample", false, msg)
	if err != nil || changed {
		t.Fatalf("duplicate global train changed=%v err=%v", changed, err)
	}
	changed, err = mgr.TrainGlobalSample(ctx, "same-sample", true, msg)
	if err != nil || !changed {
		t.Fatalf("global relabel changed=%v err=%v", changed, err)
	}
	if err := pool.QueryRow(ctx, `SELECT hams,spams FROM junk_global_totals WHERE singleton=true`).Scan(&hams, &spams); err != nil {
		t.Fatal(err)
	}
	if hams != 1 || spams != 0 {
		t.Fatalf("relabelled global totals = (%d,%d), want (1,0)", hams, spams)
	}
}

func TestGlobalModelExcludesIdentityHeaders(t *testing.T) {
	ctx := context.Background()
	pool := openJunkPool(t, ctx)
	defer pool.Close()
	mgr := junkfilter.NewManager(pool, junkfilter.DefaultParams)

	raw := []byte("From: globalfrommarker@example.test\r\n" +
		"To: globaltomarker@example.test\r\n" +
		"Cc: globalccmarker@example.test\r\n" +
		"Reply-To: globalreplymarker@example.test\r\n" +
		"Sender: globalsendermarker@example.test\r\n" +
		"Return-Path: <globalreturnmarker@example.test>\r\n" +
		"Subject: globalsubjectmarker\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n\r\n" +
		"weekly meeting agenda\r\n")
	if _, err := mgr.TrainGlobalSample(ctx, "identity-header-sample", true, raw); err != nil {
		t.Fatal(err)
	}

	for _, word := range []string{
		"From:globalfrommarker",
		"To:globaltomarker",
		"Cc:globalccmarker",
		"Reply-To:globalreplymarker",
		"Sender:globalsendermarker",
		"Return-Path:globalreturnmarker",
	} {
		var count int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM junk_global_words WHERE word=$1`, modelFeature(word)).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("global model stored identity-header feature %q", word)
		}
	}

	for _, word := range []string{"Subject:globalsubjectmarker", "meeting"} {
		var count int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM junk_global_words WHERE word=$1`, modelFeature(word)).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("global model feature %q count = %d, want 1", word, count)
		}
	}

	const accountID = int64(77)
	if err := mgr.Train(ctx, accountID, true, raw); err != nil {
		t.Fatal(err)
	}
	var personalFrom int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM junk_words WHERE account_id=$1 AND word=$2`,
		accountID, "From:globalfrommarker").Scan(&personalFrom); err != nil {
		t.Fatal(err)
	}
	if personalFrom != 1 {
		t.Fatalf("legacy personal model From feature count = %d, want 1", personalFrom)
	}
}

func TestCJKFeaturesMatchRelatedMessagesAndStayBounded(t *testing.T) {
	ctx := context.Background()
	pool := openJunkPool(t, ctx)
	defer pool.Close()
	mgr := junkfilter.NewManager(pool, junkfilter.DefaultParams)

	for i := 0; i < 200; i++ {
		spam := []byte(fmt.Sprintf("Subject: 限时优惠\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n免费领取优惠券点击链接立即领取 编号 %d\r\n", i))
		ham := []byte(fmt.Sprintf("Subject: 项目周会\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n今天讨论发布计划测试结果和会议纪要 编号 %d\r\n", i))
		if _, err := mgr.TrainGlobalSample(ctx, fmt.Sprintf("cjk-spam-%d", i), false, spam); err != nil {
			t.Fatal(err)
		}
		if _, err := mgr.TrainGlobalSample(ctx, fmt.Sprintf("cjk-ham-%d", i), true, ham); err != nil {
			t.Fatal(err)
		}
	}
	probe := []byte("Subject: 活动提醒\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n请立即免费领取优惠券，点击这里领取\r\n")
	result, err := mgr.ClassifyDetailed(ctx, 999, probe)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Junk {
		t.Fatalf("related Chinese spam not detected: %#v", result)
	}

	long := []byte("Subject: 中文\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + strings.Repeat("中", 10000) + "\r\n")
	if _, err := mgr.TrainGlobalSample(ctx, "long-cjk", true, long); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM junk_global_words`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	// The corpus above has a small fixed vocabulary. The long run must not add
	// more than the explicit feature cap (duplicates make the actual count lower).
	if count > 2200 {
		t.Fatalf("CJK feature count = %d, want bounded growth", count)
	}
}

func TestGlobalModelPackageImportsOnlyIntoEmptyDatabase(t *testing.T) {
	ctx := context.Background()
	pool := openJunkPool(t, ctx)
	defer pool.Close()
	mgr := junkfilter.NewManager(pool, junkfilter.DefaultParams)
	model := modelPackage(t, "test-v1", 200, 201, map[string][2]int64{
		modelFeature("ham-word"):  {150, 1},
		modelFeature("spam-word"): {2, 180},
	})

	imported, info, err := mgr.ImportGlobalModelIfEmpty(ctx, bytes.NewReader(model))
	if err != nil {
		t.Fatal(err)
	}
	if !imported || info.Version != "test-v1" || info.Hams != 200 || info.Spams != 201 || info.Words != 2 {
		t.Fatalf("first import = imported %v, info %#v", imported, info)
	}
	stats, err := mgr.GlobalStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !stats.Active || stats.Hams != 200 || stats.Spams != 201 {
		t.Fatalf("imported stats = %#v", stats)
	}

	replacement := modelFeature("replacement")
	other := modelPackage(t, "test-v2", 999, 999, map[string][2]int64{replacement: {999, 0}})
	imported, _, err = mgr.ImportGlobalModelIfEmpty(ctx, bytes.NewReader(other))
	if err != nil {
		t.Fatal(err)
	}
	if imported {
		t.Fatal("existing shared model was overwritten")
	}
	var replacementCount int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM junk_global_words WHERE word=$1`, replacement).Scan(&replacementCount); err != nil {
		t.Fatal(err)
	}
	if replacementCount != 0 {
		t.Fatal("replacement model data was inserted")
	}
}

func TestGlobalModelPackageFailureRollsBack(t *testing.T) {
	ctx := context.Background()
	pool := openJunkPool(t, ctx)
	defer pool.Close()
	mgr := junkfilter.NewManager(pool, junkfilter.DefaultParams)
	// The first 1,000 rows are flushed to PostgreSQL before EOF reveals that the
	// header promised one more row. The surrounding transaction must still undo
	// the already-issued INSERT.
	words := make(map[string][2]int64, 1001)
	for i := 0; i < 1001; i++ {
		words[modelFeature(fmt.Sprintf("broken-%d", i))] = [2]int64{1, 1}
	}
	broken := modelPackage(t, "broken", 200, 200, words)
	zr, err := gzip.NewReader(bytes.NewReader(broken))
	if err != nil {
		t.Fatal(err)
	}
	var plain bytes.Buffer
	if _, err := plain.ReadFrom(zr); err != nil {
		t.Fatal(err)
	}
	if err := zr.Close(); err != nil {
		t.Fatal(err)
	}
	cr := csv.NewReader(bytes.NewReader(plain.Bytes()))
	cr.FieldsPerRecord = -1
	records, err := cr.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	records[0][5] = "1002"
	var encoded bytes.Buffer
	zw := gzip.NewWriter(&encoded)
	cw := csv.NewWriter(zw)
	cw.WriteAll(records)
	if err := cw.Error(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	if _, _, err := mgr.ImportGlobalModelIfEmpty(ctx, bytes.NewReader(encoded.Bytes())); err == nil {
		t.Fatal("malformed model package imported")
	}
	var count int
	if err := pool.QueryRow(ctx,
		`SELECT (SELECT count(*) FROM junk_global_words) + (SELECT count(*) FROM junk_global_totals)`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("failed import left %d shared model rows", count)
	}
}

func TestGlobalModelPackageRejectsRowsBeyondDeclaredLimit(t *testing.T) {
	ctx := context.Background()
	pool := openJunkPool(t, ctx)
	defer pool.Close()
	mgr := junkfilter.NewManager(pool, junkfilter.DefaultParams)

	// Declare only one row so the early row limit, rather than the final exact-count
	// check, must reject the package before reading the remaining records.
	words := make(map[string][2]int64, 1001)
	for i := 0; i < 1001; i++ {
		words[modelFeature(fmt.Sprintf("excess-%d", i))] = [2]int64{1, 1}
	}
	model := modelPackage(t, "excess", 200, 200, words)
	zr, err := gzip.NewReader(bytes.NewReader(model))
	if err != nil {
		t.Fatal(err)
	}
	var plain bytes.Buffer
	if _, err := plain.ReadFrom(zr); err != nil {
		t.Fatal(err)
	}
	if err := zr.Close(); err != nil {
		t.Fatal(err)
	}
	reader := csv.NewReader(bytes.NewReader(plain.Bytes()))
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	records[0][5] = "1"
	var encoded bytes.Buffer
	zw := gzip.NewWriter(&encoded)
	cw := csv.NewWriter(zw)
	cw.WriteAll(records)
	if err := cw.Error(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	if _, _, err := mgr.ImportGlobalModelIfEmpty(ctx, bytes.NewReader(encoded.Bytes())); err == nil {
		t.Fatal("model with excess rows imported")
	} else if !strings.Contains(err.Error(), "exceeds declared feature count 1") {
		t.Fatalf("excess-row error = %q, want declared-word limit error", err)
	}
	var count int
	if err := pool.QueryRow(ctx,
		`SELECT (SELECT count(*) FROM junk_global_words) + (SELECT count(*) FROM junk_global_totals)`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("failed import left %d shared model rows", count)
	}
}

func TestConcurrentGlobalModelBootstrapImportsOnce(t *testing.T) {
	ctx := context.Background()
	pool := openJunkPool(t, ctx)
	defer pool.Close()
	model := modelPackage(t, "concurrent-v1", 200, 200, map[string][2]int64{
		modelFeature("ham"):  {180, 1},
		modelFeature("spam"): {1, 180},
	})

	start := make(chan struct{})
	results := make(chan bool, 2)
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			mgr := junkfilter.NewManager(pool, junkfilter.DefaultParams)
			imported, _, err := mgr.ImportGlobalModelIfEmpty(ctx, bytes.NewReader(model))
			results <- imported
			errs <- err
		}()
	}
	close(start)
	imports := 0
	for i := 0; i < 2; i++ {
		if <-results {
			imports++
		}
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if imports != 1 {
		t.Fatalf("concurrent startup imported model %d times, want 1", imports)
	}
	var hams, spams int64
	if err := pool.QueryRow(ctx,
		`SELECT hams,spams FROM junk_global_totals WHERE singleton=true`).Scan(&hams, &spams); err != nil {
		t.Fatal(err)
	}
	if hams != 200 || spams != 200 {
		t.Fatalf("concurrent import totals = (%d,%d), want (200,200)", hams, spams)
	}
}

func TestGlobalModelPackageExportImportRoundTrip(t *testing.T) {
	ctx := context.Background()
	pool := openJunkPool(t, ctx)
	defer pool.Close()
	mgr := junkfilter.NewManager(pool, junkfilter.DefaultParams)
	if _, err := mgr.TrainGlobalSample(ctx, "roundtrip-ham", true, hamMsg(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.TrainGlobalSample(ctx, "roundtrip-spam", false, spamMsg(1)); err != nil {
		t.Fatal(err)
	}
	var model bytes.Buffer
	info, err := mgr.ExportGlobalModel(ctx, &model, "roundtrip-v1")
	if err != nil {
		t.Fatal(err)
	}
	if info.Hams != 1 || info.Spams != 1 || info.Words == 0 {
		t.Fatalf("exported info = %#v", info)
	}
	if _, err := pool.Exec(ctx,
		`TRUNCATE junk_global_learns, junk_global_totals, junk_global_words`); err != nil {
		t.Fatal(err)
	}
	imported, got, err := mgr.ImportGlobalModelIfEmpty(ctx, bytes.NewReader(model.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if !imported || got != info {
		t.Fatalf("round-trip import = %v, %#v; want %#v", imported, got, info)
	}
	var words int64
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM junk_global_words`).Scan(&words); err != nil {
		t.Fatal(err)
	}
	if words != info.Words {
		t.Fatalf("round-trip words = %d, want %d", words, info.Words)
	}
}

func TestBundledGlobalModelWhenPresent(t *testing.T) {
	const (
		wantVersion = "2026-09-03-v4"
		wantHams    = int64(7212)
		wantSpams   = int64(7960)
		wantWords   = int64(83235)
		wantSHA256  = "5629bc3b5ddb81c499a6f16eed8f53741097d8b2369b970ee09146ec92e50bfe"
	)
	model, err := os.ReadFile("models/shared-junk-v1.csv.gz")
	if err != nil {
		if os.IsNotExist(err) {
			t.Skip("default shared model is not present in this build")
		}
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(model)); got != wantSHA256 {
		t.Fatalf("bundled model SHA-256 = %s, want %s", got, wantSHA256)
	}

	ctx := context.Background()
	pool := openJunkPool(t, ctx)
	defer pool.Close()
	mgr := junkfilter.NewManager(pool, junkfilter.DefaultParams)

	imported, info, err := mgr.BootstrapDefaultModel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	wantInfo := junkfilter.ModelInfo{Version: wantVersion, Hams: wantHams, Spams: wantSpams, Words: wantWords}
	if !imported || info != wantInfo {
		t.Fatalf("bundled model import = %v, %#v; want true, %#v", imported, info, wantInfo)
	}
	var readable int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM junk_global_words WHERE word !~ '^[0-9a-f]{64}$'`).Scan(&readable); err != nil {
		t.Fatal(err)
	}
	if readable != 0 {
		t.Fatalf("bundled model contains %d non-hash feature identifiers", readable)
	}
	second, _, err := mgr.BootstrapDefaultModel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if second {
		t.Fatal("bundled model imported twice")
	}

	for _, test := range []struct {
		name string
		raw  []byte
		junk bool
	}{
		{
			name: "verification code",
			raw: []byte("From: alerts@service.example\r\nTo: user@example.net\r\n" +
				"Subject: 登录验证码\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
				"您的登录验证码为 482915，五分钟内有效。如非本人操作，请忽略本邮件。\r\n"),
		},
		{
			name: "project meeting",
			raw: []byte("From: colleague@company.example\r\nTo: user@example.net\r\n" +
				"Subject: 项目周会安排\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
				"项目周会安排在明天下午三点，请提前阅读需求文档并准备进度说明。\r\n"),
		},
		{
			name: "chinese security review",
			raw: []byte("From: notice@service.example\r\nTo: user@example.net\r\n" +
				"Subject: 安全检查结果\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
				"系统发现一次异常登录并完成复核，相关访问来自已登记设备，当前没有需要立即处理的风险。您可自行打开官方应用查看安全记录。\r\n"),
		},
		{
			name: "chinese password changed",
			raw: []byte("From: notice@service.example\r\nTo: user@example.net\r\n" +
				"Subject: 登录密码修改完成\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
				"您的账户密码刚刚修改成功，安全日志已经更新。如由本人操作则无需处理；否则请直接通过应用内帮助中心核查。\r\n"),
		},
		{
			name: "chinese payroll",
			raw: []byte("From: notice@service.example\r\nTo: user@example.net\r\n" +
				"Subject: 本期薪资发放完成\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
				"本月工资已经完成发放，薪资和代扣明细可在员工自助系统查看。如有疑问，请按照内部流程联系薪酬服务团队。\r\n"),
		},
		{
			name: "chinese billing",
			raw: []byte("From: notice@service.example\r\nTo: user@example.net\r\n" +
				"Subject: 服务账单与发票通知\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
				"本期应付费用已经结算，电子账单、付款记录和发票可在官方客户门户查询。本邮件不会要求提供银行卡密码。\r\n"),
		},
		{
			name: "chinese system maintenance",
			raw: []byte("From: notice@service.example\r\nTo: user@example.net\r\n" +
				"Subject: 系统维护安排\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
				"信息技术团队将在今晚进行例行维护，部分页面可能短暂不可用。请提前保存工作，维护进度以内网状态页为准。\r\n"),
		},
		{
			name: "chinese order delivery",
			raw: []byte("From: notice@service.example\r\nTo: user@example.net\r\n" +
				"Subject: 订单配送进度\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
				"您的订单已经发货，预计两个工作日内送达。请从订单历史查看物流信息，本通知不要求额外付款。\r\n"),
		},
		{
			name: "password reset",
			raw: []byte("From: notification@service.example\r\nTo: user@example.net\r\n" +
				"Subject: Password reset requested\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
				"We received a request to reset your password. Use this secure one-time link within 20 minutes. " +
				"If you did not request it, ignore this email.\r\n"),
		},
		{
			name: "new sign-in alert",
			raw: []byte("From: notification@service.example\r\nTo: user@example.net\r\n" +
				"Subject: New sign-in to your account\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
				"A new sign-in was detected from a recognized browser. Review account activity in the official application if this was not you.\r\n"),
		},
		{
			name: "one-time code",
			raw: []byte("From: notification@service.example\r\nTo: user@example.net\r\n" +
				"Subject: Your verification code\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
				"Your one-time verification code is 482915. It expires in five minutes. Never share this code.\r\n"),
		},
		{
			name: "bank statement",
			raw: []byte("From: notification@service.example\r\nTo: user@example.net\r\n" +
				"Subject: Monthly bank statement available\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
				"Your monthly account statement is ready. Sign in to online banking using your saved bookmark to review it.\r\n"),
		},
		{
			name: "invoice",
			raw: []byte("From: notification@service.example\r\nTo: user@example.net\r\n" +
				"Subject: Invoice available\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
				"Invoice 10482 for your current subscription is available in the billing portal. Payment is due next Friday.\r\n"),
		},
		{
			name: "payment receipt",
			raw: []byte("From: notification@service.example\r\nTo: user@example.net\r\n" +
				"Subject: Payment receipt\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
				"We received your payment. Your receipt and transaction reference are available in your account.\r\n"),
		},
		{
			name: "order shipped",
			raw: []byte("From: notification@service.example\r\nTo: user@example.net\r\n" +
				"Subject: Order shipped\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
				"Your order has shipped and is expected to arrive Friday. Track the package from your order history.\r\n"),
		},
		{
			name: "payroll update",
			raw: []byte("From: notification@service.example\r\nTo: user@example.net\r\n" +
				"Subject: Payroll update\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
				"Your salary payment has been processed. The payslip is available in the employee self-service portal.\r\n"),
		},
		{
			name: "medical appointment",
			raw: []byte("From: notification@service.example\r\nTo: user@example.net\r\n" +
				"Subject: Medical appointment reminder\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
				"This is a reminder for your appointment tomorrow at 10:30. Reply to the clinic if you need to reschedule.\r\n"),
		},
		{
			name: "api token expiration",
			raw: []byte("From: notice@service.example\r\nTo: user@example.net\r\n" +
				"Subject: Your API token expires in 14 days\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
				"The API credential used by the reporting integration expires in fourteen days. " +
				"Generate a successor in developer settings and rotate the stored deployment credential before that date.\r\n"),
		},
		{
			name: "timesheet reminder",
			raw: []byte("From: notice@service.example\r\nTo: user@example.net\r\n" +
				"Subject: Reminder: timesheet due today\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
				"Please complete and submit this week's time entry in the employee system by close of business. " +
				"Check project codes and recorded hours before submitting.\r\n"),
		},
		{
			name: "laptop encryption check",
			raw: []byte("From: notice@service.example\r\nTo: user@example.net\r\n" +
				"Subject: Scheduled laptop encryption check\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
				"Corporate IT will run the scheduled disk encryption verification tonight. " +
				"Leave the managed laptop powered on and connected to the company network.\r\n"),
		},
		{
			name: "failed invoice payment",
			raw: []byte("From: notice@service.example\r\nTo: user@example.net\r\n" +
				"Subject: Payment failed for invoice 88123\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
				"We were unable to charge the payment method saved for invoice 88123. " +
				"Review billing settings in the official customer portal or speak with your account manager.\r\n"),
		},
		{
			name: "password changed",
			raw: []byte("From: notice@service.example\r\nTo: user@example.net\r\n" +
				"Subject: Password changed successfully\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
				"Your account password was updated successfully. If you performed this change, no further action is necessary. " +
				"Otherwise contact the official help desk.\r\n"),
		},
		{
			name: "loan and prize spam",
			raw: []byte("From: offer@random.example\r\nTo: user@example.net\r\n" +
				"Subject: 中奖奖金 无抵押贷款 娱乐城送彩金\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
				"恭喜中奖，现金大奖等待领取。无需征信即可办理大额贷款，当天审核立即到账。" +
				"注册博彩平台领取新人彩金，充值返利，立即扫码付款。请先汇款缴纳税费并发送身份证银行卡密码和短信验证码。\r\n"),
			junk: true,
		},
		{
			name: "mailbox phishing",
			raw: []byte("From: security@random.example\r\nTo: user@example.net\r\n" +
				"Subject: Urgent mailbox suspension and lottery prize\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
				"Your mailbox account will be permanently closed today. Verify your password and banking information " +
				"through the attached login form immediately. You also won a guaranteed cash jackpot. " +
				"Pay the processing fee with gift cards or cryptocurrency to claim the prize. Limited offer, act now.\r\n"),
			junk: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := mgr.ClassifyGlobalDetailed(ctx, test.raw)
			if err != nil {
				t.Fatal(err)
			}
			if result.Junk != test.junk {
				t.Fatalf("classification = %#v, want Junk=%v", result, test.junk)
			}
		})
	}

	t.Run("cjk spam with padded identity header", func(t *testing.T) {
		displayName := distinctCJKText(1300)
		raw := []byte("From: " + displayName + " <sender@example.test>\r\nTo: user@example.net\r\n" +
			"Subject: 中奖奖金 无抵押贷款 娱乐城送彩金\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
			"恭喜中奖，现金大奖等待领取。无需征信即可办理大额贷款，当天审核立即到账。" +
			"注册博彩平台领取新人彩金，充值返利，立即扫码付款。请先汇款缴纳税费并发送银行卡密码和短信验证码。\r\n")
		result, err := mgr.ClassifyGlobalDetailed(ctx, raw)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Junk {
			t.Fatalf("classification = %#v, want Junk=true", result)
		}
	})

	t.Run("cjk spam with padded folded subject", func(t *testing.T) {
		raw := []byte("From: offer@random.example\r\nTo: user@example.net\r\n" +
			foldedCJKSubject(40, 60) +
			"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
			"恭喜中奖，现金大奖等待领取。无需征信即可办理大额贷款，当天审核立即到账。" +
			"注册博彩平台领取新人彩金，充值返利，立即扫码付款。请先汇款缴纳税费并发送银行卡密码和短信验证码。\r\n")
		result, err := mgr.ClassifyGlobalDetailed(ctx, raw)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Junk {
			t.Fatalf("classification = %#v, want Junk=true", result)
		}
	})
}
