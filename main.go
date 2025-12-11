package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Finding struct {
	File             string  `json:"file"`
	Line             int     `json:"line"`
	Type             string  `json:"type"`
	Snippet          string  `json:"snippet"`
	Entropy          float64 `json:"entropy,omitempty"`
	HashAlgo         string  `json:"hash_algo,omitempty"`
	HashCrackability string  `json:"hash_crackability,omitempty"`
}

var (
	reAWSAccessKey     = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	reGithubPAT        = regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`)
	reGenericKV        = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|apikey|api_key)\s*[:=]\s*['"]?([^'"\s]+)['"]?`)
	reEntropyCandidate = regexp.MustCompile(`[A-Za-z0-9/\+=]{20,}`)
	reHexHash          = regexp.MustCompile(`\b[0-9a-fA-F]{32,128}\b`)
)

func main() {
	pathFlag := flag.String("path", ".", "Path to scan (directory or single file)")
	jsonFlag := flag.Bool("json", false, "Output results as JSON")
	maxSize := flag.Int64("max-size", 1<<20, "Maximum file size to scan in bytes (default: 1MB)")
	entropyThreshold := flag.Float64("entropy", 4.0, "Shannon entropy threshold for generic high-entropy strings")
	flag.Parse()

	var findings []Finding

	info, err := os.Stat(*pathFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot stat %s: %v\n", *pathFlag, err)
		os.Exit(1)
	}

	if info.IsDir() {
		err = filepath.WalkDir(*pathFlag, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil // ignore permission errors etc.
			}

			if d.IsDir() {
				name := d.Name()
				if name == ".git" || name == "node_modules" || name == "venv" || name == ".venv" {
					return filepath.SkipDir
				}
				return nil
			}

			if !d.Type().IsRegular() {
				return nil
			}

			if fi, err := d.Info(); err == nil {
				if fi.Size() > *maxSize {
					return nil
				}
			}

			fs := scanFile(path, *entropyThreshold)
			if len(fs) > 0 {
				findings = append(findings, fs...)
			}

			return nil
		})
	} else {
		findings = scanFile(*pathFlag, *entropyThreshold)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while walking %s: %v\n", *pathFlag, err)
		os.Exit(1)
	}

	if *jsonFlag {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(findings); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Human-readable output
	if len(findings) == 0 {
		fmt.Println("No potential secrets found.")
		return
	}

	fmt.Printf("Found %d potential secrets / hashes:\n\n", len(findings))
	for _, f := range findings {
		lineBase := fmt.Sprintf("%s:%d [%s]", f.File, f.Line, f.Type)

		if f.HashAlgo != "" {
			// Hash finding
			fmt.Printf("%s (algo=%s, crackability=%s) %s\n",
				lineBase,
				f.HashAlgo,
				f.HashCrackability,
				f.Snippet,
			)
		} else if f.Entropy > 0 {
			// High-entropy secret
			fmt.Printf("%s [H=%.2f] %s\n", lineBase, f.Entropy, f.Snippet)
		} else {
			// Other secret types (AWS, PAT, generic kv)
			fmt.Printf("%s %s\n", lineBase, f.Snippet)
		}
	}
}

func scanFile(path string, entropyThreshold float64) []Finding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var findings []Finding
	scanner := bufio.NewScanner(f)
	// increase max line length just in case
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()

		snippet := strings.TrimSpace(line)
		if len(snippet) > 200 {
			snippet = snippet[:200] + "..."
		}

		if reAWSAccessKey.MatchString(line) {
			findings = append(findings, Finding{
				File:    path,
				Line:    lineNo,
				Type:    "AWS_ACCESS_KEY_ID",
				Snippet: snippet,
			})
		}

		if reGithubPAT.MatchString(line) {
			findings = append(findings, Finding{
				File:    path,
				Line:    lineNo,
				Type:    "GITHUB_PAT",
				Snippet: snippet,
			})
		}

		if reGenericKV.MatchString(line) {
			findings = append(findings, Finding{
				File:    path,
				Line:    lineNo,
				Type:    "GENERIC_KV_SECRET",
				Snippet: snippet,
			})
		}

		hashCandidates := reHexHash.FindAllString(line, -1)
		for _, h := range hashCandidates {
			algo, crack := classifyHash(h)
			if algo == "" {
				continue
			}
			findings = append(findings, Finding{
				File:             path,
				Line:             lineNo,
				Type:             "HASH",
				Snippet:          snippet,
				HashAlgo:         algo,
				HashCrackability: crack,
			})
		}

		candidates := reEntropyCandidate.FindAllString(line, -1)
		for _, cand := range candidates {
			if len(cand) < 20 {
				continue
			}
			h := shannonEntropy(cand)
			if h >= entropyThreshold {
				findings = append(findings, Finding{
					File:    path,
					Line:    lineNo,
					Type:    "HIGH_ENTROPY_STRING",
					Snippet: snippet,
					Entropy: h,
				})
			}
		}
	}

	return findings
}

func classifyHash(s string) (string, string) {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return "", ""
		}
	}

	l := len(s)
	switch l {
	case 32:
		return "MD5/NTLM (32 hex)", "WEAK – fast to crack with GPU / wordlists"
	case 40:
		return "SHA-1 (40 hex)", "WEAK – considered broken / collisions, use stronger hash"
	case 64:
		return "SHA-256 (64 hex)", "STRONGER – still crackable offline if unsalted & weak passwords"
	case 128:
		return "SHA-512 (128 hex)", "STRONGER – depends heavily on salting / KDF / password quality"
	default:
		return "", ""
	}
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	counts := make(map[rune]int)
	for _, r := range s {
		counts[r]++
	}

	var entropy float64
	length := float64(len([]rune(s)))
	for _, c := range counts {
		p := float64(c) / length
		entropy += -p * math.Log2(p)
	}
	return entropy
}
