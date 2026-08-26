package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Mininglamp-OSS/octo-mail/junkfilter"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/deliverability"
	"github.com/Mininglamp-OSS/octo-mail/ops/mailboxops"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
)

// cmdJunk manages the deployment-wide curated junk corpus:
//
//	octo-mail junk train-global <ham|spam> <file-or-directory> [...]
//	octo-mail junk evaluate-global <ham-file-or-directory> <spam-file-or-directory>
//	octo-mail junk export-global <version> <output-file>
//
// Directories are walked recursively and only .eml files are read. The content
// digest is the stable sample id, so rerunning the same corpus is idempotent.
func cmdJunk(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: octo-mail junk <train-global|evaluate-global|export-global> ...")
	}
	if args[0] == "evaluate-global" {
		return cmdJunkEvaluateGlobal(args)
	}
	if args[0] == "export-global" {
		return cmdJunkExportGlobal(args)
	}
	if len(args) < 3 || args[0] != "train-global" || args[1] != "ham" && args[1] != "spam" {
		return fmt.Errorf("usage: octo-mail junk train-global <ham|spam> <file-or-directory> [...]")
	}
	ham := args[1] == "ham"
	paths, err := collectEMLPaths(args[2:])
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return errors.New("no .eml training files found")
	}

	ctx := context.Background()
	cfg := loadConfig()
	s, err := postgres.Open(ctx, cfg.dsn, nil)
	if err != nil {
		return err
	}
	defer s.Close()
	mgr := junkfilter.NewManager(s.Pool, junkfilter.DefaultParams)
	mgr.SharedThreshold = cfg.sharedJunkThreshold

	var changed, unchanged int
	for _, path := range paths {
		raw, err := readTrainingMessage(path, cfg.maxSize)
		if err != nil {
			return err
		}
		digest := fmt.Sprintf("%x", sha256.Sum256(raw))
		applied, err := mgr.TrainGlobalSample(ctx, digest, ham, raw)
		if err != nil {
			return fmt.Errorf("train %s: %w", path, err)
		}
		if applied {
			changed++
		} else {
			unchanged++
		}
	}
	fmt.Printf("global junk corpus: class=%s trained=%d unchanged=%d\n", args[1], changed, unchanged)
	return nil
}

func cmdJunkExportGlobal(args []string) error {
	if len(args) != 3 || strings.TrimSpace(args[1]) == "" || strings.TrimSpace(args[2]) == "" {
		return errors.New("usage: octo-mail junk export-global <version> <output-file>")
	}
	ctx := context.Background()
	cfg := loadConfig()
	s, err := postgres.Open(ctx, cfg.dsn, nil)
	if err != nil {
		return err
	}
	defer s.Close()
	mgr := junkfilter.NewManager(s.Pool, junkfilter.DefaultParams)

	output := args[2]
	tmp, err := os.CreateTemp(filepath.Dir(output), "."+filepath.Base(output)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create model package: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	info, exportErr := mgr.ExportGlobalModel(ctx, tmp, args[1])
	closeErr := tmp.Close()
	if exportErr != nil {
		return fmt.Errorf("export model package: %w", exportErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close model package: %w", closeErr)
	}
	if err := os.Rename(tmpPath, output); err != nil {
		return fmt.Errorf("publish model package: %w", err)
	}
	fmt.Printf("global junk model exported: version=%s ham=%d spam=%d words=%d path=%s\n",
		info.Version, info.Hams, info.Spams, info.Words, output)
	return nil
}

func cmdJunkEvaluateGlobal(args []string) error {
	opts, err := parseJunkEvaluateArgs(args)
	if err != nil {
		return err
	}
	hamPaths, err := collectEMLPaths([]string{opts.hamPath})
	if err != nil {
		return err
	}
	spamPaths, err := collectEMLPaths([]string{opts.spamPath})
	if err != nil {
		return err
	}
	if len(hamPaths) == 0 || len(spamPaths) == 0 {
		return errors.New("evaluation requires at least one ham and one spam .eml file")
	}
	seen := make(map[string]struct{}, len(hamPaths))
	for _, path := range hamPaths {
		seen[path] = struct{}{}
	}
	for _, path := range spamPaths {
		if _, ok := seen[path]; ok {
			return fmt.Errorf("same message path appears in ham and spam inputs: %s", path)
		}
	}

	ctx := context.Background()
	cfg := loadConfig()
	s, err := postgres.Open(ctx, cfg.dsn, nil)
	if err != nil {
		return err
	}
	defer s.Close()
	mgr := junkfilter.NewManager(s.Pool, junkfilter.DefaultParams)
	mgr.SharedThreshold = cfg.sharedJunkThreshold
	report, err := evaluateGlobalCorpus(ctx, mgr, cfg.maxSize, hamPaths, spamPaths)
	if err != nil {
		return err
	}
	if err := writeJunkEvaluationCSV(opts.csvPath, report.Results); err != nil {
		return fmt.Errorf("write evaluation csv: %w", err)
	}
	if err := writeJunkEvaluationJSON(opts.jsonPath, report); err != nil {
		return fmt.Errorf("write evaluation json: %w", err)
	}
	return nil
}

func collectEMLPaths(inputs []string) ([]string, error) {
	seen := map[string]struct{}{}
	for _, input := range inputs {
		info, err := os.Stat(input)
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", input, err)
		}
		if !info.IsDir() {
			if !strings.EqualFold(filepath.Ext(input), ".eml") {
				return nil, fmt.Errorf("training file must use .eml extension: %s", input)
			}
			seen[input] = struct{}{}
			continue
		}
		if err := filepath.WalkDir(input, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if !entry.IsDir() && entry.Type().IsRegular() && strings.EqualFold(filepath.Ext(path), ".eml") {
				seen[path] = struct{}{}
			}
			return nil
		}); err != nil {
			return nil, fmt.Errorf("walk %s: %w", input, err)
		}
	}
	paths := make([]string, 0, len(seen))
	for path := range seen {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths, nil
}

func readTrainingMessage(path string, maxSize int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	if maxSize <= 0 {
		maxSize = 50 * 1024 * 1024
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if int64(len(raw)) > maxSize {
		return nil, fmt.Errorf("training message exceeds %d bytes: %s", maxSize, path)
	}
	return raw, nil
}

// cmdPasswd sets a principal's password: octo-mail passwd <login> <password>.
// Provisioning helper so operators can create credentials without a separate
// tool. Uses the same argon2id+SCRAM hashing the auth path verifies against.
func cmdPasswd(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: octo-mail passwd <login> <password>")
	}
	login, password := args[0], args[1]
	ctx := context.Background()
	cfg := loadConfig()

	bs, err := openBlobStore(cfg, slog.Default())
	if err != nil {
		return err
	}
	s, err := postgres.Open(ctx, cfg.dsn, bs)
	if err != nil {
		return err
	}
	defer s.Close()

	if err := s.NewDirectory().SetPassword(ctx, login, password); err != nil {
		return err
	}
	fmt.Printf("password set for %s\n", login)
	return nil
}

// cmdAPIKey manages account-scoped API keys:
//
//	octo-mail apikey create <login> [name]
//
// It mints a bearer token (omk_...) that authenticates as the login's account on
// the JMAP/WebAPI HTTP surfaces. The token is printed ONCE and is not
// recoverable afterward.
func cmdAPIKey(args []string) error {
	if len(args) < 2 || args[0] != "create" {
		return fmt.Errorf("usage: octo-mail apikey create <login> [name]")
	}
	login := args[1]
	name := "api key"
	if len(args) >= 3 {
		name = args[2]
	}
	ctx := context.Background()
	cfg := loadConfig()

	// No blob store needed for key issuance (directory/DB only).
	s, err := postgres.Open(ctx, cfg.dsn, nil)
	if err != nil {
		return err
	}
	defer s.Close()

	token, err := s.NewDirectory().IssueAPIKey(ctx, login, name)
	if err != nil {
		return err
	}
	fmt.Printf("api key created for %s (%q)\nsecret (shown once): %s\n", login, name, token)
	return nil
}

// cmdGenDKIM generates a per-tenant DKIM key and prints the TXT record to
// publish: octo-mail gendkim <tenantID> <domain> <selector>.
func cmdGenDKIM(args []string) error {
	if len(args) != 3 {
		return fmt.Errorf("usage: octo-mail gendkim <tenantID> <domain> <selector>")
	}
	var tenantID int64
	if _, err := fmt.Sscan(args[0], &tenantID); err != nil {
		return fmt.Errorf("bad tenantID: %w", err)
	}
	domain, selector := args[1], args[2]
	ctx := context.Background()
	cfg := loadConfig()

	s, err := postgres.Open(ctx, cfg.dsn, nil)
	if err != nil {
		return err
	}
	defer s.Close()

	var cipher *deliverability.KeyCipher
	if secret := os.Getenv("OCTO_MAIL_KEY_SECRET"); secret != "" {
		cipher, err = deliverability.NewKeyCipher([]byte(secret))
		if err != nil {
			return err
		}
	}
	txt, err := deliverability.GenerateTenantKeyEnc(ctx, s.Pool, cipher, tenantID, domain, selector)
	if err != nil {
		return err
	}
	fmt.Printf("publish this TXT record at %s._domainkey.%s:\n%s\n", selector, domain, txt)
	return nil
}

// cmdExport writes a mailbox to an mbox file:
// octo-mail export <tenant> <account> <mailbox> <out.mbox>
func cmdExport(args []string) error {
	if len(args) != 4 {
		return fmt.Errorf("usage: octo-mail export <tenant> <account> <mailbox> <out.mbox>")
	}
	ctx := context.Background()
	cfg := loadConfig()
	bs, err := openBlobStore(cfg, slog.Default())
	if err != nil {
		return err
	}
	s, err := postgres.Open(ctx, cfg.dsn, bs)
	if err != nil {
		return err
	}
	defer s.Close()
	acc, err := s.OpenAccountForOps(ctx, args[0], args[1])
	if err != nil {
		return err
	}
	f, err := os.Create(args[3])
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := mailboxops.ExportMbox(ctx, acc, args[2], f)
	if err != nil {
		return err
	}
	fmt.Printf("exported %d messages from %s/%s/%s to %s\n", n, args[0], args[1], args[2], args[3])
	return nil
}

// cmdImport reads an mbox file into a mailbox:
// octo-mail import <tenant> <account> <mailbox> <in.mbox>
func cmdImport(args []string) error {
	if len(args) != 4 {
		return fmt.Errorf("usage: octo-mail import <tenant> <account> <mailbox> <in.mbox>")
	}
	ctx := context.Background()
	cfg := loadConfig()
	bs, err := openBlobStore(cfg, slog.Default())
	if err != nil {
		return err
	}
	s, err := postgres.Open(ctx, cfg.dsn, bs)
	if err != nil {
		return err
	}
	defer s.Close()
	acc, err := s.OpenAccountForOps(ctx, args[0], args[1])
	if err != nil {
		return err
	}
	f, err := os.Open(args[3])
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := mailboxops.ImportMbox(ctx, acc, args[2], f)
	if err != nil {
		return err
	}
	fmt.Printf("imported %d messages into %s/%s/%s\n", n, args[0], args[1], args[2])
	return nil
}
