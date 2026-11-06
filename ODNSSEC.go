// ============================================================================
// ODNSSEC — DNSSEC Chain Validator
// Author  : khaled.s.haddad
// Website : owlsec.org
// Language: Go (stdlib only, CGO disabled, static build)
// Category: ONet
// ============================================================================

package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"math/big"
	"math/rand"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---- OWL UI KIT (cyan "owl" house style) — stdlib only. Shared across the suite ----
// CYAN is the primary brand/frame colour; red is reserved for errors and
// CRITICAL/HIGH severities.
const (
	R   = "\033[91m"       // red     — errors / critical
	GRN = "\033[92m"       // green   — success / low
	YLW = "\033[93m"       // yellow  — prompts / warning text
	CY  = "\033[96m"       // cyan    — primary brand & frames
	W   = "\033[97m"       // white   — body text
	B   = "\033[1m"        // bold
	X   = "\033[0m"        // reset
	MG  = "\033[95m"       // magenta — suite name / accents
	BL  = "\033[94m"       // blue    — accents
	DIM = "\033[2m"        // dim     — secondary text
	OR  = "\033[38;5;208m" // orange  — warning markers
	GY  = "\033[90m"       // gray    — muted
	DR  = CY               // legacy alias: former frame colour → cyan
)

var noColor = os.Getenv("NO_COLOR") != "" || !isatty()

func isatty() bool { fi, _ := os.Stdout.Stat(); return (fi.Mode() & os.ModeCharDevice) != 0 }
func col(s string, c ...string) string {
	if noColor {
		return s
	}
	return strings.Join(c, "") + s + X
}
func clear()           { fmt.Print("\033[H\033[2J") }
func line(w int)       { fmt.Println(col(strings.Repeat("─", w), CY)) }
func okMsg(s string)   { fmt.Println("  " + col("[✔] ", GRN+B) + col(s, W)) }
func errMsg(s string)  { fmt.Println("  " + col("[✘] ", R+B) + col(s, R)) }
func warnMsg(s string) { fmt.Println("  " + col("[!] ", OR+B) + col(s, YLW)) }
func info(s string)    { fmt.Println("  " + col("[*] ", CY) + col(s, DIM+W)) }

// banner prints the cyan ANSI-Shadow wordmark and the suite identity block.
func banner() {
	fmt.Println(col(BANNER, CY))
	fmt.Println("  " + col(SUITE+"  ", B+MG) + col("v"+VERSION, YLW))
	fmt.Println("  " + col(SUBLINE, W))
	fmt.Println()
	fmt.Println("  " + col("Developer : ", DIM) + col(AUTHOR, CY) +
		col("   |   Website : ", DIM) + col(WEBSITE, CY))
	fmt.Println(col(strings.Repeat("─", 66), CY))
	fmt.Println()
}
func prompt(label string) string {
	fmt.Print("  " + col("[»] ", YLW) + col(label+": ", W))
	s, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && s == "" {
		fmt.Println()
		os.Exit(0) // stdin closed (Ctrl-D / end of piped input)
	}
	return strings.TrimSpace(s)
}
func pause() {
	fmt.Print(col("\n  [↩] Press Enter to continue...", YLW))
	bufio.NewReader(os.Stdin).ReadString('\n')
}

// sectionHeader prints a ⬡ heading between two cyan rules.
func sectionHeader(s string) {
	fmt.Println(col(strings.Repeat("─", 66), CY))
	fmt.Println("  " + col("⬡  "+s, B+CY))
	fmt.Println(col(strings.Repeat("─", 66), CY))
	fmt.Println()
}

type menuItem struct {
	key, name, desc, clr string
}

// menu renders the ONode-style main menu and returns the raw selection.
func menu(title string, items []menuItem) string {
	clear()
	banner()
	fmt.Println("  " + col("⬡  "+title, B+CY))
	fmt.Println()
	for _, it := range items {
		fmt.Println("  " + col(pad("["+it.key+"]", 4), it.clr) + "  " +
			col(pad(it.name, 32), W) + col("─ "+it.desc, DIM))
	}
	fmt.Println()
	fmt.Println("  " + col(pad("[H]", 4), YLW+B) + "  " + col(pad("Help & Usage", 32), W) + col("─ How to use, every option, CLI flags & examples", DIM))
	fmt.Println("  " + col(pad("[0]", 4), R) + "  " + col(pad("Exit", 32), W) + col("─ Quit "+APPNAME, DIM))
	fmt.Println()
	fmt.Println(col(strings.Repeat("─", 66), CY))
	return prompt("Select option")
}
func pad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}
func table(headers []string, rows [][]string) {
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = len(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(w) && len(c) > w[i] {
				w[i] = len(c)
			}
		}
	}
	var hb strings.Builder
	for i, h := range headers {
		hb.WriteString(col(pad(h, w[i]), CY+B))
		if i < len(headers)-1 {
			hb.WriteString(col(" │ ", DR))
		}
	}
	fmt.Println("  " + hb.String())
	seg := make([]string, len(w))
	for i := range w {
		seg[i] = strings.Repeat("─", w[i])
	}
	fmt.Println("  " + col(strings.Join(seg, "─┼─"), DR))
	for _, r := range rows {
		var rb strings.Builder
		for i := range headers {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			rb.WriteString(col(pad(v, w[i]), W))
			if i < len(headers)-1 {
				rb.WriteString(col(" │ ", DR))
			}
		}
		fmt.Println("  " + rb.String())
	}
}

const APPNAME = "ODNSSEC"
const SUITE = "Owl DNSSEC Suite"
const TAGLINE = "DNSSEC Chain Validator"
const SUBLINE = "Parse · Key Tags · DS Digests · RRSIG Crypto · Chain of Trust · Grade"
const VERSION = "1.0"
const AUTHOR = "khaled.s.haddad"
const WEBSITE = "owlsec.org"

const BANNER = `
 ██████╗ ██████╗ ███╗   ██╗███████╗███████╗███████╗ ██████╗
██╔═══██╗██╔══██╗████╗  ██║██╔════╝██╔════╝██╔════╝██╔════╝
██║   ██║██║  ██║██╔██╗ ██║███████╗███████╗█████╗  ██║
██║   ██║██║  ██║██║╚██╗██║╚════██║╚════██║██╔══╝  ██║
╚██████╔╝██████╔╝██║ ╚████║███████║███████║███████╗╚██████╗
 ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚══════╝╚══════╝ ╚═════╝
`

// ============================================================================
// OWL SHARED CORE  — Finding model, grading, MITRE ATT&CK, 5-format export,
// output engine, and numeric/byte/stat utilities. Stdlib only.
// ============================================================================

// Severity levels used across all OWL v2 tools.
const (
	SevInfo     = "INFO"
	SevLow      = "LOW"
	SevMedium   = "MEDIUM"
	SevHigh     = "HIGH"
	SevCritical = "CRITICAL"
)

// Finding is the universal result record every OWL tool emits.
type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Score       float64  `json:"score"`
	Category    string   `json:"category"`
	Subject     string   `json:"subject"`
	Description string   `json:"description"`
	Evidence    string   `json:"evidence"`
	ATTCK       []string `json:"attck,omitempty"`
	CWE         string   `json:"cwe,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Reference   string   `json:"reference,omitempty"`
}

// Report bundles findings plus run metadata for export.
type Report struct {
	Tool      string     `json:"tool"`
	Tagline   string     `json:"tagline"`
	Target    string     `json:"target"`
	Generated string     `json:"generated"`
	Records   int        `json:"records_parsed"`
	Chain     []chainRow `json:"chain"`
	Findings  []Finding  `json:"findings"`
	Summary   Summary    `json:"summary"`
	Warnings  []string   `json:"warnings,omitempty"`
}

// Summary is the aggregate posture for a run.
type Summary struct {
	Total     int     `json:"total"`
	Critical  int     `json:"critical"`
	High      int     `json:"high"`
	Medium    int     `json:"medium"`
	Low       int     `json:"low"`
	Info      int     `json:"info"`
	RiskScore float64 `json:"risk_score"`
	Grade     string  `json:"grade"`
}

func sevRank(s string) int {
	switch strings.ToUpper(s) {
	case SevCritical:
		return 5
	case SevHigh:
		return 4
	case SevMedium:
		return 3
	case SevLow:
		return 2
	case SevInfo:
		return 1
	}
	return 0
}

func sevWeight(s string) float64 {
	switch strings.ToUpper(s) {
	case SevCritical:
		return 10.0
	case SevHigh:
		return 7.0
	case SevMedium:
		return 4.0
	case SevLow:
		return 1.5
	case SevInfo:
		return 0.2
	}
	return 0.0
}

// summarize computes the aggregate posture and letter grade for a finding set.
func summarize(fs []Finding) Summary {
	var s Summary
	s.Total = len(fs)
	var raw float64
	for _, f := range fs {
		switch strings.ToUpper(f.Severity) {
		case SevCritical:
			s.Critical++
		case SevHigh:
			s.High++
		case SevMedium:
			s.Medium++
		case SevLow:
			s.Low++
		default:
			s.Info++
		}
		raw += sevWeight(f.Severity)
	}
	s.RiskScore = raw
	s.Grade = gradeFor(s)
	return s
}

// gradeFor maps weighted risk to an A+..F posture grade.
func gradeFor(s Summary) string {
	if s.Critical > 0 {
		if s.Critical >= 3 {
			return "F"
		}
		return "E"
	}
	switch {
	case s.High >= 3:
		return "D"
	case s.High >= 1:
		return "C"
	case s.Medium >= 3:
		return "C"
	case s.Medium >= 1:
		return "B"
	case s.Low >= 1:
		return "A"
	default:
		return "A+"
	}
}

func gradeColor(g string) string {
	switch g {
	case "A+", "A":
		return GRN + B
	case "B":
		return GRN
	case "C":
		return YLW
	case "D", "E":
		return R
	case "F":
		return R + B
	}
	return W
}

// ---------------------------------------------------------------------------
// MITRE ATT&CK technique descriptions (curated subset used by OWL tools).
// ---------------------------------------------------------------------------
var attckDB = map[string]string{
	"T1557":     "Adversary-in-the-Middle",
	"T1584.002": "Compromise Infrastructure: DNS Server",
	"T1590.002": "Gather Victim Network Information: DNS",
	"T1600":     "Weaken Encryption",
}

func attckName(id string) string {
	if n, ok := attckDB[id]; ok {
		return n
	}
	return id
}

func attckTag(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	var parts []string
	for _, id := range ids {
		parts = append(parts, id+" ("+attckName(id)+")")
	}
	return strings.Join(parts, ", ")
}

// ---------------------------------------------------------------------------
// Export engine: TXT, MD, JSON, CSV, SARIF 2.1.0
// ---------------------------------------------------------------------------

func buildReport(target string, fs []Finding) Report {
	sort.SliceStable(fs, func(i, j int) bool {
		if sevRank(fs[i].Severity) != sevRank(fs[j].Severity) {
			return sevRank(fs[i].Severity) > sevRank(fs[j].Severity)
		}
		return fs[i].Score > fs[j].Score
	})
	return Report{
		Tool:      APPNAME,
		Tagline:   TAGLINE,
		Target:    target,
		Generated: time.Now().Format(time.RFC3339),
		Findings:  append([]Finding{}, fs...),
		Summary:   summarize(fs),
	}
}

func exportTXT(r Report) string {
	var b strings.Builder
	b.WriteString("================================================================\n")
	b.WriteString(" " + r.Tool + " — " + r.Tagline + "\n")
	b.WriteString(" Author: khaled.s.haddad    Website: owlsec.org\n")
	b.WriteString("================================================================\n")
	b.WriteString("Target     : " + r.Target + "\n")
	b.WriteString("Generated  : " + r.Generated + "\n")
	b.WriteString(fmt.Sprintf("Grade      : %s   RiskScore: %.1f\n", r.Summary.Grade, r.Summary.RiskScore))
	b.WriteString(fmt.Sprintf("Findings   : %d  (C:%d H:%d M:%d L:%d I:%d)\n",
		r.Summary.Total, r.Summary.Critical, r.Summary.High, r.Summary.Medium, r.Summary.Low, r.Summary.Info))
	b.WriteString("----------------------------------------------------------------\n\n")
	if len(r.Chain) > 0 {
		b.WriteString("CHAIN OF TRUST\n")
		for _, c := range r.Chain {
			b.WriteString(fmt.Sprintf("  %-9s %-28s via %-16s sigs %d ok / %d bad\n", strings.ToUpper(c.Status), c.Zone, c.Via, c.SigsOK, c.SigsBad))
			b.WriteString("            keys " + nonEmptyStr(c.Keys, "-") + "\n")
			if c.DS != "" {
				b.WriteString("            DS   " + c.DS + "\n")
			}
			if c.Denial != "" {
				b.WriteString("            " + c.Denial + "\n")
			}
			if c.Reason != "" {
				b.WriteString("            why  " + c.Reason + "\n")
			}
		}
		b.WriteString("\n")
	}
	for i, f := range r.Findings {
		b.WriteString(fmt.Sprintf("[%03d] %-8s %s\n", i+1, f.Severity, f.Title))
		if f.Subject != "" {
			b.WriteString("      Subject    : " + f.Subject + "\n")
		}
		if f.Category != "" {
			b.WriteString("      Category   : " + f.Category + "\n")
		}
		b.WriteString(fmt.Sprintf("      Score      : %.1f\n", f.Score))
		if f.Description != "" {
			b.WriteString("      Description: " + f.Description + "\n")
		}
		if f.Evidence != "" {
			b.WriteString("      Evidence   : " + f.Evidence + "\n")
		}
		if len(f.ATTCK) > 0 {
			b.WriteString("      ATT&CK     : " + attckTag(f.ATTCK) + "\n")
		}
		if f.CWE != "" {
			b.WriteString("      CWE        : " + f.CWE + "\n")
		}
		if f.Remediation != "" {
			b.WriteString("      Remediation: " + f.Remediation + "\n")
		}
		if f.Reference != "" {
			b.WriteString("      Reference  : " + f.Reference + "\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

func exportMD(r Report) string {
	var b strings.Builder
	b.WriteString("# " + r.Tool + " Report\n\n")
	b.WriteString("*" + r.Tagline + "*\n\n")
	b.WriteString("- **Target:** " + r.Target + "\n")
	b.WriteString("- **Generated:** " + r.Generated + "\n")
	b.WriteString(fmt.Sprintf("- **Grade:** %s (risk score %.1f)\n", r.Summary.Grade, r.Summary.RiskScore))
	b.WriteString(fmt.Sprintf("- **Findings:** %d — Critical %d, High %d, Medium %d, Low %d, Info %d\n\n",
		r.Summary.Total, r.Summary.Critical, r.Summary.High, r.Summary.Medium, r.Summary.Low, r.Summary.Info))
	if len(r.Chain) > 0 {
		b.WriteString("## Chain of trust\n\n| Zone | Status | Trust via | Keys | DS | Sigs ok/bad |\n|---|---|---|---|---|---|\n")
		for _, c := range r.Chain {
			b.WriteString(fmt.Sprintf("| %s | **%s** | %s | %s | %s | %d / %d |\n", mdEsc(c.Zone), c.Status, c.Via, mdEsc(c.Keys), mdEsc(c.DS), c.SigsOK, c.SigsBad))
		}
		b.WriteString("\n")
	}
	b.WriteString("| # | Severity | Title | Score | ATT&CK |\n")
	b.WriteString("|---|----------|-------|-------|--------|\n")
	for i, f := range r.Findings {
		b.WriteString(fmt.Sprintf("| %d | %s | %s | %.1f | %s |\n",
			i+1, f.Severity, mdEsc(f.Title), f.Score, mdEsc(strings.Join(f.ATTCK, " "))))
	}
	b.WriteString("\n## Details\n\n")
	for i, f := range r.Findings {
		b.WriteString(fmt.Sprintf("### %d. %s (%s)\n\n", i+1, f.Title, f.Severity))
		if f.Subject != "" {
			b.WriteString("- **Subject:** " + mdEsc(f.Subject) + "\n")
		}
		if f.Category != "" {
			b.WriteString("- **Category:** " + mdEsc(f.Category) + "\n")
		}
		b.WriteString(fmt.Sprintf("- **Score:** %.1f\n", f.Score))
		if f.Description != "" {
			b.WriteString("- **Description:** " + mdEsc(f.Description) + "\n")
		}
		if f.Evidence != "" {
			b.WriteString("- **Evidence:** `" + f.Evidence + "`\n")
		}
		if len(f.ATTCK) > 0 {
			b.WriteString("- **ATT&CK:** " + mdEsc(attckTag(f.ATTCK)) + "\n")
		}
		if f.CWE != "" {
			b.WriteString("- **CWE:** " + f.CWE + "\n")
		}
		if f.Remediation != "" {
			b.WriteString("- **Remediation:** " + mdEsc(f.Remediation) + "\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

func mdEsc(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func exportJSON(r Report) string {
	buf, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(buf)
}

func exportCSV(r Report) string {
	var sb strings.Builder
	w := csv.NewWriter(&sb)
	w.Write([]string{"id", "severity", "score", "category", "subject", "title", "description", "evidence", "attck", "cwe", "remediation"})
	for _, f := range r.Findings {
		w.Write([]string{f.ID, f.Severity, fmt.Sprintf("%.1f", f.Score), f.Category, f.Subject, f.Title, f.Description, f.Evidence, strings.Join(f.ATTCK, " "), f.CWE, f.Remediation})
	}
	w.Flush()
	return sb.String()
}

func sarifLevel(sev string) string {
	switch strings.ToUpper(sev) {
	case SevCritical, SevHigh:
		return "error"
	case SevMedium:
		return "warning"
	case SevLow, SevInfo:
		return "note"
	}
	return "none"
}

func exportSARIF(r Report) string {
	type sarifMsg struct {
		Text string `json:"text"`
	}
	type sarifRule struct {
		ID               string   `json:"id"`
		Name             string   `json:"name"`
		ShortDescription sarifMsg `json:"shortDescription"`
	}
	type sarifResult struct {
		RuleID  string   `json:"ruleId"`
		Level   string   `json:"level"`
		Message sarifMsg `json:"message"`
	}
	type driver struct {
		Name    string      `json:"name"`
		Version string      `json:"version"`
		Rules   []sarifRule `json:"rules"`
	}
	type tool struct {
		Driver driver `json:"driver"`
	}
	type run struct {
		Tool    tool          `json:"tool"`
		Results []sarifResult `json:"results"`
	}
	type doc struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []run  `json:"runs"`
	}
	seen := map[string]bool{}
	var rules []sarifRule
	var results []sarifResult
	for _, f := range r.Findings {
		rid := f.ID
		if rid == "" {
			rid = "OWL-" + strings.ToUpper(APPNAME)
		}
		if !seen[rid] {
			seen[rid] = true
			rules = append(rules, sarifRule{ID: rid, Name: f.Title, ShortDescription: sarifMsg{Text: f.Title}})
		}
		msg := f.Description
		if f.Evidence != "" {
			msg += " | evidence: " + f.Evidence
		}
		if len(f.ATTCK) > 0 {
			msg += " | ATT&CK: " + strings.Join(f.ATTCK, ",")
		}
		results = append(results, sarifResult{RuleID: rid, Level: sarifLevel(f.Severity), Message: sarifMsg{Text: msg}})
	}
	d := doc{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []run{{
			Tool:    tool{Driver: driver{Name: APPNAME, Version: VERSION, Rules: rules}},
			Results: results,
		}},
	}
	buf, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(buf)
}

func renderReport(format string, r Report) string {
	switch strings.ToLower(format) {
	case "md", "markdown":
		return exportMD(r)
	case "json":
		return exportJSON(r)
	case "csv":
		return exportCSV(r)
	case "sarif":
		return exportSARIF(r)
	default:
		return exportTXT(r)
	}
}

func writeOutput(path, content string) error {
	if path == "" || path == "-" {
		fmt.Print(content)
		if !strings.HasSuffix(content, "\n") {
			fmt.Println()
		}
		return nil
	}
	return os.WriteFile(path, []byte(content), 0644)
}

// ---------------------------------------------------------------------------
// Console helpers
// ---------------------------------------------------------------------------

func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n < 4 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

func printFindingsTable(fs []Finding) {
	if len(fs) == 0 {
		info("no findings")
		return
	}
	var rows [][]string
	for i, f := range fs {
		rows = append(rows, []string{fmt.Sprintf("%d", i+1), f.Severity, truncStr(f.Title, 48), fmt.Sprintf("%.1f", f.Score), strings.Join(f.ATTCK, " ")})
	}
	table([]string{"#", "SEV", "TITLE", "SCORE", "ATT&CK"}, rows)
}

func printSummary(s Summary) {
	fmt.Println()
	fmt.Println("  " + col("Posture Grade: ", W) + col(s.Grade, gradeColor(s.Grade)+B) +
		col(fmt.Sprintf("   Risk Score: %.1f", s.RiskScore), GY))
	fmt.Printf("  %s C:%d  H:%d  M:%d  L:%d  I:%d\n", col("Findings", DIM),
		s.Critical, s.High, s.Medium, s.Low, s.Info)
}

func kv(k, v string) {
	fmt.Printf("  %s %s\n", col(pad(k+":", 16), DIM), col(v, W))
}

// ---- DNSSEC algorithm names (IANA registry) ---------------------------------

var dnssecAlgs = map[int]string{
	1: "RSAMD5(deprecated)", 3: "DSA/SHA1(deprecated)", 5: "RSASHA1",
	6: "DSA-NSEC3-SHA1", 7: "RSASHA1-NSEC3-SHA1", 8: "RSASHA256",
	10: "RSASHA512", 12: "ECC-GOST", 13: "ECDSAP256SHA256", 14: "ECDSAP384SHA384",
	15: "ED25519", 16: "ED448", 253: "PRIVATEDNS", 254: "PRIVATEOID",
}

func dnssecAlgName(n int) string {
	if s, ok := dnssecAlgs[n]; ok {
		return s
	}
	return fmt.Sprintf("ALG%d", n)
}

// ============================================================================
// ODNSSEC DOMAIN ENGINE — DNSSEC Chain Validator
// Parses zone files / dig output into wire-format RRs, computes RFC 4034 key
// tags and DS digests, cryptographically verifies RRSIGs (RSA/SHA-1/256/512,
// ECDSA P-256/P-384, Ed25519) over canonical RRsets, and walks the chain of
// trust from configured trust anchors (IANA root KSKs built in) down through
// DS → DNSKEY → RRSIG for every zone present in the input.
// ============================================================================

// ---- RR model --------------------------------------------------------------

var rrTypeNums = map[string]uint16{"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "HINFO": 13, "MX": 15,
	"TXT": 16, "AAAA": 28, "SRV": 33, "NAPTR": 35, "DNAME": 39, "OPT": 41, "DS": 43, "SSHFP": 44, "RRSIG": 46,
	"NSEC": 47, "DNSKEY": 48, "NSEC3": 50, "NSEC3PARAM": 51, "TLSA": 52, "CDS": 59, "CDNSKEY": 60,
	"SVCB": 64, "HTTPS": 65, "CAA": 257}

const (
	tA, tNS, tCNAME, tSOA, tPTR, tMX, tTXT, tAAAA, tSRV, tDNAME  = 1, 2, 5, 6, 12, 15, 16, 28, 33, 39
	tDS, tRRSIG, tNSEC, tDNSKEY, tNSEC3, tNSEC3P, tCDS, tCDNSKEY = 43, 46, 47, 48, 50, 51, 59, 60
)

func rrTypeName(t uint16) string {
	for k, v := range rrTypeNums {
		if v == t {
			return k
		}
	}
	return fmt.Sprintf("TYPE%d", t)
}

func rrTypeNum(s string) (uint16, bool) {
	s = strings.ToUpper(s)
	if v, ok := rrTypeNums[s]; ok {
		return v, true
	}
	if strings.HasPrefix(s, "TYPE") {
		if n, err := strconv.Atoi(s[4:]); err == nil && n > 0 && n < 65536 {
			return uint16(n), true
		}
	}
	return 0, false
}

// RR is one resource record with uncompressed wire-format RDATA.
type RR struct {
	Owner string // canonical: lowercase, absolute ("example.com.", root ".")
	Type  uint16
	Class uint16
	TTL   uint32
	Rdata []byte
	Src   int // source line (0 = fetched)
}

type dnsKey struct {
	Owner     string
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	Key       []byte
	Rdata     []byte
	Tag       uint16
}

func (k dnsKey) zoneKey() bool { return k.Flags&0x0100 != 0 }
func (k dnsKey) sep() bool     { return k.Flags&0x0001 != 0 }
func (k dnsKey) revoked() bool { return k.Flags&0x0080 != 0 }
func (k dnsKey) role() string {
	if k.sep() {
		return "KSK"
	}
	return "ZSK"
}

type dsRec struct {
	Owner      string
	Tag        uint16
	Algorithm  uint8
	DigestType uint8
	Digest     []byte
}

type rrsig struct {
	Owner      string
	Covered    uint16
	Algorithm  uint8
	Labels     uint8
	OrigTTL    uint32
	Expiration uint32
	Inception  uint32
	Tag        uint16
	Signer     string
	Signature  []byte
	Rdata      []byte
}

// ---- names -----------------------------------------------------------------

// splitLabels splits a presentation-format name into raw labels, decoding
// \DDD and \X escapes. The root name yields no labels.
func splitLabels(n string) ([][]byte, error) {
	if n == "." || n == "" {
		return nil, nil
	}
	var labels [][]byte
	var cur []byte
	for i := 0; i < len(n); i++ {
		c := n[i]
		switch {
		case c == '\\' && isDigit3(n[i+1:]):
			v, _ := strconv.Atoi(n[i+1 : i+4])
			if v > 255 {
				return nil, fmt.Errorf("bad escape in %q", n)
			}
			cur = append(cur, byte(v))
			i += 3
		case c == '\\' && i+1 < len(n):
			cur = append(cur, n[i+1])
			i++
		case c == '.':
			if len(cur) == 0 && i != len(n)-1 {
				return nil, fmt.Errorf("empty label in %q", n)
			}
			if len(cur) > 0 {
				labels = append(labels, cur)
			}
			cur = nil
		default:
			cur = append(cur, c)
		}
	}
	if len(cur) > 0 {
		labels = append(labels, cur)
	}
	for _, l := range labels {
		if len(l) > 63 {
			return nil, fmt.Errorf("label too long in %q", n)
		}
	}
	return labels, nil
}

func isDigit3(s string) bool {
	return len(s) >= 3 && s[0] >= '0' && s[0] <= '9' && s[1] >= '0' && s[1] <= '9' && s[2] >= '0' && s[2] <= '9'
}

func lowerASCII(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		out[i] = c
	}
	return out
}

// nameWire encodes a presentation name (absolute) to uncompressed wire form.
func nameWire(n string) ([]byte, error) {
	labels, err := splitLabels(n)
	if err != nil {
		return nil, err
	}
	var b []byte
	for _, l := range labels {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0)
	if len(b) > 255 {
		return nil, fmt.Errorf("name too long: %q", n)
	}
	return b, nil
}

// labelText renders one raw label with presentation escapes.
func labelText(l []byte) string {
	var sb strings.Builder
	for _, c := range l {
		switch {
		case c == '.' || c == '\\' || c == '"' || c == '(' || c == ')' || c == ';' || c == '@' || c == '$':
			sb.WriteByte('\\')
			sb.WriteByte(c)
		case c < 0x21 || c > 0x7e:
			sb.WriteString(fmt.Sprintf("\\%03d", c))
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

// wireNameAt reads an uncompressed wire name at b[off:], returning the
// presentation form and the offset just past it.
func wireNameAt(b []byte, off int) (string, int, error) {
	var parts []string
	for {
		if off >= len(b) {
			return "", 0, errors.New("truncated name")
		}
		l := int(b[off])
		if l&0xc0 != 0 {
			return "", 0, errors.New("compressed name in RDATA")
		}
		off++
		if l == 0 {
			break
		}
		if off+l > len(b) {
			return "", 0, errors.New("truncated label")
		}
		parts = append(parts, labelText(b[off:off+l]))
		off += l
	}
	if len(parts) == 0 {
		return ".", off, nil
	}
	return strings.Join(parts, ".") + ".", off, nil
}

// canonName lowercases and makes a name absolute relative to origin.
func canonName(n, origin string) string {
	switch {
	case n == "@":
		n = origin
	case n == ".":
	case !strings.HasSuffix(n, ".") || strings.HasSuffix(n, "\\."):
		if origin == "." || origin == "" {
			n += "."
		} else {
			n += "." + origin
		}
	}
	return strings.ToLower(n)
}

// absName makes a name absolute relative to origin without changing case.
func absName(n, origin string) string {
	switch {
	case n == "@":
		return origin
	case n == ".":
		return n
	case !strings.HasSuffix(n, ".") || strings.HasSuffix(n, "\\."):
		if origin == "." || origin == "" {
			return n + "."
		}
		return n + "." + origin
	}
	return n
}

func labelCount(n string) int {
	l, _ := splitLabels(n)
	c := len(l)
	if c > 0 && string(l[0]) == "*" {
		c--
	}
	return c
}

// parentName drops the leftmost label ("a.b." → "b.", "b." → ".").
func parentName(n string) string {
	if n == "." {
		return ""
	}
	l, _ := splitLabels(n)
	if len(l) <= 1 {
		return "."
	}
	var parts []string
	for _, x := range l[1:] {
		parts = append(parts, labelText(x))
	}
	return strings.ToLower(strings.Join(parts, ".") + ".")
}

func isSubdomain(child, parent string) bool {
	if parent == "." {
		return true
	}
	return child == parent || strings.HasSuffix(child, "."+parent)
}

// ---- presentation → wire ---------------------------------------------------

// zoneTokens tokenises one logical record line, honouring quotes.
func zoneTokens(s string) []string {
	var out []string
	var cur strings.Builder
	inQ, have := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			cur.WriteByte(c)
			cur.WriteByte(s[i+1])
			i++
			have = true
		case c == '"':
			inQ = !inQ
			have = true
		case !inQ && (c == ' ' || c == '\t'):
			if have {
				out = append(out, cur.String())
				cur.Reset()
				have = false
			}
		default:
			cur.WriteByte(c)
			have = true
		}
	}
	if have {
		out = append(out, cur.String())
	}
	return out
}

// charString decodes escapes in a TXT/CAA token into raw bytes.
func charString(t string) []byte {
	var b []byte
	for i := 0; i < len(t); i++ {
		if t[i] == '\\' && i+1 < len(t) {
			if isDigit3(t[i+1:]) {
				v, _ := strconv.Atoi(t[i+1 : i+4])
				b = append(b, byte(v))
				i += 3
				continue
			}
			b = append(b, t[i+1])
			i++
			continue
		}
		b = append(b, t[i])
	}
	return b
}

func u16b(v int) []byte { return []byte{byte(v >> 8), byte(v)} }
func u32b(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func parseU(s string, max uint64) (uint64, error) {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || v > max {
		return 0, fmt.Errorf("bad number %q", s)
	}
	return v, nil
}

// parseSigTime accepts YYYYMMDDHHmmSS or a decimal epoch (RFC 4034 §3.2).
func parseSigTime(s string) (uint32, error) {
	if len(s) == 14 {
		t, err := time.Parse("20060102150405", s)
		if err != nil {
			return 0, err
		}
		return uint32(t.Unix()), nil
	}
	v, err := parseU(s, math.MaxUint32)
	return uint32(v), err
}

// typeBitmap encodes the NSEC/NSEC3 type bit maps field.
func typeBitmap(tokens []string) ([]byte, error) {
	var ts []int
	for _, t := range tokens {
		n, ok := rrTypeNum(t)
		if !ok {
			return nil, fmt.Errorf("unknown type %q in bitmap", t)
		}
		ts = append(ts, int(n))
	}
	sort.Ints(ts)
	var out []byte
	for i := 0; i < len(ts); {
		win := ts[i] >> 8
		var bm [32]byte
		maxb := 0
		for ; i < len(ts) && ts[i]>>8 == win; i++ {
			lo := ts[i] & 0xff
			bm[lo/8] |= 0x80 >> uint(lo%8)
			if lo/8+1 > maxb {
				maxb = lo/8 + 1
			}
		}
		out = append(out, byte(win), byte(maxb))
		out = append(out, bm[:maxb]...)
	}
	return out, nil
}

func bitmapTypes(b []byte) []string {
	var out []string
	for i := 0; i+2 <= len(b); {
		win, l := int(b[i]), int(b[i+1])
		i += 2
		if i+l > len(b) {
			break
		}
		for j := 0; j < l; j++ {
			for k := 0; k < 8; k++ {
				if b[i+j]&(0x80>>uint(k)) != 0 {
					out = append(out, rrTypeName(uint16(win<<8|j*8+k)))
				}
			}
		}
		i += l
	}
	return out
}

var b32hex = base32.NewEncoding("0123456789ABCDEFGHIJKLMNOPQRSTUV").WithPadding(base32.NoPadding)

// rdataFromText encodes the RDATA tokens of a record of type t.
func rdataFromText(t uint16, f []string, origin string) ([]byte, error) {
	need := func(n int) error {
		if len(f) < n {
			return fmt.Errorf("%s needs %d fields", rrTypeName(t), n)
		}
		return nil
	}
	if len(f) >= 2 && f[0] == "\\#" { // RFC 3597 generic form
		n, err := parseU(f[1], 65535)
		if err != nil {
			return nil, err
		}
		b, err := hex.DecodeString(strings.Join(f[2:], ""))
		if err != nil || uint64(len(b)) != n {
			return nil, errors.New("bad \\# RDATA")
		}
		return b, nil
	}
	name := func(s string) ([]byte, error) { return nameWire(absName(s, origin)) }
	switch t {
	case tA:
		if err := need(1); err != nil {
			return nil, err
		}
		ip := net.ParseIP(f[0]).To4()
		if ip == nil {
			return nil, fmt.Errorf("bad A %q", f[0])
		}
		return []byte(ip), nil
	case tAAAA:
		if err := need(1); err != nil {
			return nil, err
		}
		ip := net.ParseIP(f[0])
		if ip == nil || ip.To4() != nil && !strings.Contains(f[0], ":") {
			return nil, fmt.Errorf("bad AAAA %q", f[0])
		}
		return []byte(ip.To16()), nil
	case tNS, tCNAME, tPTR, tDNAME:
		if err := need(1); err != nil {
			return nil, err
		}
		return name(f[0])
	case tMX:
		if err := need(2); err != nil {
			return nil, err
		}
		p, err := parseU(f[0], 65535)
		if err != nil {
			return nil, err
		}
		n, err := name(f[1])
		return append(u16b(int(p)), n...), err
	case tSRV:
		if err := need(4); err != nil {
			return nil, err
		}
		var b []byte
		for _, s := range f[:3] {
			v, err := parseU(s, 65535)
			if err != nil {
				return nil, err
			}
			b = append(b, u16b(int(v))...)
		}
		n, err := name(f[3])
		return append(b, n...), err
	case tSOA:
		if err := need(7); err != nil {
			return nil, err
		}
		m, err := name(f[0])
		if err != nil {
			return nil, err
		}
		r, err := name(f[1])
		if err != nil {
			return nil, err
		}
		b := append(m, r...)
		for _, s := range f[2:7] {
			v, err := parseU(s, math.MaxUint32)
			if err != nil {
				return nil, err
			}
			b = append(b, u32b(uint32(v))...)
		}
		return b, nil
	case tTXT:
		var b []byte
		for _, s := range f {
			cs := charString(s)
			for len(cs) > 255 {
				b = append(b, 255)
				b = append(b, cs[:255]...)
				cs = cs[255:]
			}
			b = append(b, byte(len(cs)))
			b = append(b, cs...)
		}
		return b, nil
	case 257: // CAA
		if err := need(3); err != nil {
			return nil, err
		}
		fl, err := parseU(f[0], 255)
		if err != nil {
			return nil, err
		}
		b := []byte{byte(fl), byte(len(f[1]))}
		b = append(b, f[1]...)
		return append(b, charString(strings.Join(f[2:], " "))...), nil
	case tDS, tCDS:
		if err := need(4); err != nil {
			return nil, err
		}
		tag, e1 := parseU(f[0], 65535)
		alg, e2 := parseU(f[1], 255)
		dt, e3 := parseU(f[2], 255)
		d, e4 := hex.DecodeString(strings.Join(f[3:], ""))
		if err := firstErr(e1, e2, e3, e4); err != nil {
			return nil, err
		}
		return append(append(u16b(int(tag)), byte(alg), byte(dt)), d...), nil
	case tDNSKEY, tCDNSKEY:
		if err := need(4); err != nil {
			return nil, err
		}
		fl, e1 := parseU(f[0], 65535)
		pr, e2 := parseU(f[1], 255)
		alg, e3 := parseU(f[2], 255)
		k, e4 := base64.StdEncoding.DecodeString(strings.Join(f[3:], ""))
		if err := firstErr(e1, e2, e3, e4); err != nil {
			return nil, err
		}
		return append(append(u16b(int(fl)), byte(pr), byte(alg)), k...), nil
	case tRRSIG:
		if err := need(9); err != nil {
			return nil, err
		}
		cov, ok := rrTypeNum(f[0])
		if !ok {
			return nil, fmt.Errorf("RRSIG covers unknown type %q", f[0])
		}
		alg, e1 := parseU(f[1], 255)
		lab, e2 := parseU(f[2], 255)
		ttl, e3 := parseU(f[3], math.MaxUint32)
		exp, e4 := parseSigTime(f[4])
		inc, e5 := parseSigTime(f[5])
		tag, e6 := parseU(f[6], 65535)
		signer, e7 := name(f[7])
		sig, e8 := base64.StdEncoding.DecodeString(strings.Join(f[8:], ""))
		if err := firstErr(e1, e2, e3, e4, e5, e6, e7, e8); err != nil {
			return nil, err
		}
		b := append(u16b(int(cov)), byte(alg), byte(lab))
		b = append(b, u32b(uint32(ttl))...)
		b = append(b, u32b(exp)...)
		b = append(b, u32b(inc)...)
		b = append(b, u16b(int(tag))...)
		b = append(b, signer...)
		return append(b, sig...), nil
	case tNSEC:
		if err := need(1); err != nil {
			return nil, err
		}
		n, err := name(f[0])
		if err != nil {
			return nil, err
		}
		bm, err := typeBitmap(f[1:])
		return append(n, bm...), err
	case tNSEC3, tNSEC3P:
		if err := need(4); err != nil {
			return nil, err
		}
		ha, e1 := parseU(f[0], 255)
		fl, e2 := parseU(f[1], 255)
		it, e3 := parseU(f[2], 65535)
		var salt []byte
		var e4 error
		if f[3] != "-" {
			salt, e4 = hex.DecodeString(f[3])
		}
		if err := firstErr(e1, e2, e3, e4); err != nil {
			return nil, err
		}
		b := append([]byte{byte(ha), byte(fl)}, u16b(int(it))...)
		b = append(b, byte(len(salt)))
		b = append(b, salt...)
		if t == tNSEC3P {
			return b, nil
		}
		if err := need(5); err != nil {
			return nil, err
		}
		nx, err := b32hex.DecodeString(strings.ToUpper(f[4]))
		if err != nil {
			return nil, err
		}
		b = append(b, byte(len(nx)))
		b = append(b, nx...)
		bm, err := typeBitmap(f[5:])
		return append(b, bm...), err
	case 44, 52: // SSHFP (alg fp-type hex) / TLSA (usage selector mtype hex)
		n := 2
		if t == 52 {
			n = 3
		}
		if err := need(n + 1); err != nil {
			return nil, err
		}
		var b []byte
		for _, s := range f[:n] {
			v, err := parseU(s, 255)
			if err != nil {
				return nil, err
			}
			b = append(b, byte(v))
		}
		d, err := hex.DecodeString(strings.Join(f[n:], ""))
		return append(b, d...), err
	}
	return nil, fmt.Errorf("type %s not supported in text form (use \\# generic RDATA)", rrTypeName(t))
}

func firstErr(es ...error) error {
	for _, e := range es {
		if e != nil {
			return e
		}
	}
	return nil
}

// zoneLines joins parenthesised continuations and strips comments, returning
// logical lines with their starting line numbers.
func zoneLines(text string) ([]string, []int) {
	var out []string
	var nums []int
	var cur strings.Builder
	depth, start := 0, 0
	for i, raw := range strings.Split(text, "\n") {
		ln := raw
		// strip ; comments outside quotes
		inQ := false
		for j := 0; j < len(ln); j++ {
			if ln[j] == '\\' {
				j++
				continue
			}
			if ln[j] == '"' {
				inQ = !inQ
			}
			if ln[j] == ';' && !inQ {
				ln = ln[:j]
				break
			}
		}
		if depth == 0 {
			start = i + 1
			cur.Reset()
		}
		for _, c := range ln {
			switch c {
			case '(':
				depth++
				cur.WriteByte(' ')
			case ')':
				if depth > 0 {
					depth--
				}
				cur.WriteByte(' ')
			default:
				cur.WriteRune(c)
			}
		}
		if depth == 0 {
			s := strings.TrimRight(cur.String(), " \t\r")
			if strings.TrimSpace(s) != "" {
				out = append(out, s)
				nums = append(nums, start)
			}
		} else {
			cur.WriteByte(' ')
		}
	}
	return out, nums
}

// parseZoneText reads a zone file or dig output into RRs. Unsupported or
// malformed records are skipped and reported as warnings.
func parseZoneText(text, origin string) ([]RR, []string) {
	if origin == "" {
		origin = "."
	}
	origin = canonName(origin, ".")
	var rrs []RR
	var warns []string
	lines, nums := zoneLines(text)
	prevOwner := origin
	var defTTL uint32 = 3600
	for i, ln := range lines {
		f := zoneTokens(ln)
		if len(f) == 0 {
			continue
		}
		switch strings.ToUpper(f[0]) {
		case "$ORIGIN":
			if len(f) > 1 {
				origin = canonName(f[1], origin)
			}
			continue
		case "$TTL":
			if len(f) > 1 {
				if v, err := parseU(f[1], math.MaxUint32); err == nil {
					defTTL = uint32(v)
				}
			}
			continue
		case "$INCLUDE", "$GENERATE":
			warns = append(warns, fmt.Sprintf("line %d: %s not supported, skipped", nums[i], f[0]))
			continue
		}
		owner := prevOwner
		idx := 0
		if ln[0] != ' ' && ln[0] != '\t' {
			owner = canonName(f[0], origin)
			idx = 1
		}
		ttl, class := defTTL, uint16(1)
		var typ uint16
		ok := false
		for ; idx < len(f); idx++ {
			tok := strings.ToUpper(f[idx])
			if v, err := strconv.ParseUint(tok, 10, 32); err == nil {
				ttl = uint32(v)
				continue
			}
			if tok == "IN" {
				continue
			}
			if tok == "CH" || tok == "HS" || tok == "CS" {
				class = map[string]uint16{"CS": 2, "CH": 3, "HS": 4}[tok]
				continue
			}
			if t, known := rrTypeNum(tok); known {
				typ, ok = t, true
				idx++
				break
			}
			break
		}
		if !ok {
			warns = append(warns, fmt.Sprintf("line %d: no record type found, skipped", nums[i]))
			continue
		}
		prevOwner = owner
		if typ == 41 { // OPT pseudo-records in dig output
			continue
		}
		rd, err := rdataFromText(typ, f[idx:], origin)
		if err != nil {
			warns = append(warns, fmt.Sprintf("line %d: %s %s: %v", nums[i], owner, rrTypeName(typ), err))
			continue
		}
		rrs = append(rrs, RR{Owner: owner, Type: typ, Class: class, TTL: ttl, Rdata: rd, Src: nums[i]})
	}
	return dedupeRRs(rrs), warns
}

func dedupeRRs(rrs []RR) []RR {
	seen := map[string]bool{}
	var out []RR
	for _, r := range rrs {
		k := fmt.Sprintf("%s|%d|%d|%x", r.Owner, r.Type, r.Class, r.Rdata)
		if !seen[k] {
			seen[k] = true
			out = append(out, r)
		}
	}
	return out
}

// ---- wire → presentation (for display and --save) -------------------------

func rdataText(t uint16, b []byte) string {
	generic := fmt.Sprintf("\\# %d %s", len(b), strings.ToUpper(hex.EncodeToString(b)))
	nameOr := func(off int) (string, int, bool) {
		n, o, err := wireNameAt(b, off)
		return n, o, err == nil
	}
	switch t {
	case tA:
		if len(b) == 4 {
			return net.IP(b).String()
		}
	case tAAAA:
		if len(b) == 16 {
			return net.IP(b).String()
		}
	case tNS, tCNAME, tPTR, tDNAME:
		if n, _, ok := nameOr(0); ok {
			return n
		}
	case tMX:
		if len(b) > 2 {
			if n, _, ok := nameOr(2); ok {
				return fmt.Sprintf("%d %s", binary.BigEndian.Uint16(b), n)
			}
		}
	case tSRV:
		if len(b) > 6 {
			if n, _, ok := nameOr(6); ok {
				return fmt.Sprintf("%d %d %d %s", binary.BigEndian.Uint16(b), binary.BigEndian.Uint16(b[2:]), binary.BigEndian.Uint16(b[4:]), n)
			}
		}
	case tSOA:
		m, o, ok := nameOr(0)
		r, o2, ok2 := nameOr(o)
		if ok && ok2 && len(b) == o2+20 {
			v := func(i int) uint32 { return binary.BigEndian.Uint32(b[o2+4*i:]) }
			return fmt.Sprintf("%s %s %d %d %d %d %d", m, r, v(0), v(1), v(2), v(3), v(4))
		}
	case tTXT:
		var parts []string
		for i := 0; i < len(b); {
			l := int(b[i])
			if i+1+l > len(b) {
				return generic
			}
			parts = append(parts, strconv.Quote(string(b[i+1:i+1+l])))
			i += 1 + l
		}
		return strings.Join(parts, " ")
	case tDS, tCDS:
		if len(b) >= 4 {
			return fmt.Sprintf("%d %d %d %s", binary.BigEndian.Uint16(b), b[2], b[3], strings.ToUpper(hex.EncodeToString(b[4:])))
		}
	case tDNSKEY, tCDNSKEY:
		if len(b) >= 4 {
			return fmt.Sprintf("%d %d %d %s", binary.BigEndian.Uint16(b), b[2], b[3], base64.StdEncoding.EncodeToString(b[4:]))
		}
	case tRRSIG:
		if s, ok := parseRRSIG(".", b); ok {
			ts := func(v uint32) string { return time.Unix(int64(v), 0).UTC().Format("20060102150405") }
			return fmt.Sprintf("%s %d %d %d %s %s %d %s %s", rrTypeName(s.Covered), s.Algorithm, s.Labels, s.OrigTTL,
				ts(s.Expiration), ts(s.Inception), s.Tag, s.Signer, base64.StdEncoding.EncodeToString(s.Signature))
		}
	case tNSEC:
		if n, o, ok := nameOr(0); ok {
			return strings.TrimSpace(n + " " + strings.Join(bitmapTypes(b[o:]), " "))
		}
	case tNSEC3, tNSEC3P:
		if len(b) >= 5 {
			sl := int(b[4])
			if 5+sl <= len(b) {
				salt := "-"
				if sl > 0 {
					salt = strings.ToUpper(hex.EncodeToString(b[5 : 5+sl]))
				}
				head := fmt.Sprintf("%d %d %d %s", b[0], b[1], binary.BigEndian.Uint16(b[2:]), salt)
				if t == tNSEC3P {
					return head
				}
				o := 5 + sl
				if o < len(b) && o+1+int(b[o]) <= len(b) {
					nx := b32hex.EncodeToString(b[o+1 : o+1+int(b[o])])
					return strings.TrimSpace(head + " " + nx + " " + strings.Join(bitmapTypes(b[o+1+int(b[o]):]), " "))
				}
			}
		}
	}
	return generic
}

func rrText(r RR) string {
	return fmt.Sprintf("%s\t%d\tIN\t%s\t%s", r.Owner, r.TTL, rrTypeName(r.Type), rdataText(r.Type, r.Rdata))
}

// ---- typed views -----------------------------------------------------------

func parseDNSKEY(owner string, b []byte) (dnsKey, bool) {
	if len(b) < 4 {
		return dnsKey{}, false
	}
	k := dnsKey{Owner: owner, Flags: binary.BigEndian.Uint16(b), Protocol: b[2], Algorithm: b[3], Key: b[4:], Rdata: b}
	k.Tag = keyTag(b)
	return k, true
}

// keyTag implements RFC 4034 Appendix B (with the algorithm-1 special case).
func keyTag(rdata []byte) uint16 {
	if len(rdata) >= 4 && rdata[3] == 1 {
		if len(rdata) < 7 {
			return 0
		}
		return binary.BigEndian.Uint16(rdata[len(rdata)-3:])
	}
	var ac uint32
	for i, c := range rdata {
		if i&1 == 0 {
			ac += uint32(c) << 8
		} else {
			ac += uint32(c)
		}
	}
	ac += ac >> 16 & 0xffff
	return uint16(ac & 0xffff)
}

func parseDS(owner string, b []byte) (dsRec, bool) {
	if len(b) < 5 {
		return dsRec{}, false
	}
	return dsRec{Owner: owner, Tag: binary.BigEndian.Uint16(b), Algorithm: b[2], DigestType: b[3], Digest: b[4:]}, true
}

func parseRRSIG(owner string, b []byte) (rrsig, bool) {
	if len(b) < 19 {
		return rrsig{}, false
	}
	s := rrsig{Owner: owner, Covered: binary.BigEndian.Uint16(b), Algorithm: b[2], Labels: b[3],
		OrigTTL: binary.BigEndian.Uint32(b[4:]), Expiration: binary.BigEndian.Uint32(b[8:]),
		Inception: binary.BigEndian.Uint32(b[12:]), Tag: binary.BigEndian.Uint16(b[16:]), Rdata: b}
	n, o, err := wireNameAt(b, 18)
	if err != nil {
		return rrsig{}, false
	}
	s.Signer, s.Signature = strings.ToLower(n), b[o:]
	return s, true
}

// dsDigest computes the DS digest of key under digest type dt.
func dsDigest(k dnsKey, dt uint8) ([]byte, bool) {
	ow, err := nameWire(k.Owner)
	if err != nil {
		return nil, false
	}
	data := append(lowerASCII(ow), k.Rdata...)
	switch dt {
	case 1:
		h := sha1.Sum(data)
		return h[:], true
	case 2:
		h := sha256.Sum256(data)
		return h[:], true
	case 4:
		h := sha512.Sum384(data)
		return h[:], true
	}
	return nil, false
}

// ---- canonical form + signature verification -------------------------------

// canonRdata lowercases embedded domain names for the types listed in
// RFC 4034 §6.2 (as amended by RFC 6840 §5.1: NSEC's next name is excluded).
func canonRdata(t uint16, b []byte) []byte {
	lowerName := func(out []byte, off int) int {
		for off < len(out) {
			l := int(out[off])
			if l == 0 || l&0xc0 != 0 {
				return off + 1
			}
			for i := off + 1; i <= off+l && i < len(out); i++ {
				if out[i] >= 'A' && out[i] <= 'Z' {
					out[i] += 32
				}
			}
			off += 1 + l
		}
		return off
	}
	out := append([]byte{}, b...)
	switch t {
	case tNS, tCNAME, tPTR, tDNAME:
		lowerName(out, 0)
	case tMX:
		if len(out) > 2 {
			lowerName(out, 2)
		}
	case tSRV:
		if len(out) > 6 {
			lowerName(out, 6)
		}
	case tSOA:
		lowerName(out, lowerName(out, 0))
	case tRRSIG:
		if len(out) > 18 {
			lowerName(out, 18)
		}
	}
	return out
}

type verifyResult int

const (
	vOK verifyResult = iota
	vBad
	vUnsupported
	vWeak
)

// signedData builds the RRSIG signing input (RFC 4034 §3.1.8.1) for an RRset.
func signedData(s rrsig, set []RR) ([]byte, error) {
	sn, err := nameWire(s.Signer)
	if err != nil {
		return nil, err
	}
	var b []byte
	b = append(b, s.Rdata[:18]...)
	b = append(b, lowerASCII(sn)...)
	owner := set[0].Owner
	if lc := labelCount(owner); int(s.Labels) < lc { // wildcard expansion
		l, _ := splitLabels(owner)
		keep := l[len(l)-int(s.Labels):]
		var parts []string
		for _, x := range keep {
			parts = append(parts, labelText(x))
		}
		owner = "*." + strings.Join(parts, ".") + "."
		if s.Labels == 0 {
			owner = "*."
		}
	}
	ow, err := nameWire(owner)
	if err != nil {
		return nil, err
	}
	ow = lowerASCII(ow)
	rds := make([][]byte, 0, len(set))
	seen := map[string]bool{}
	for _, r := range set {
		c := canonRdata(r.Type, r.Rdata)
		if !seen[string(c)] {
			seen[string(c)] = true
			rds = append(rds, c)
		}
	}
	sort.Slice(rds, func(i, j int) bool { return bytes.Compare(rds[i], rds[j]) < 0 })
	for _, rd := range rds {
		b = append(b, ow...)
		b = append(b, u16b(int(set[0].Type))...)
		b = append(b, u16b(int(set[0].Class))...)
		b = append(b, u32b(s.OrigTTL)...)
		b = append(b, u16b(len(rd))...)
		b = append(b, rd...)
	}
	return b, nil
}

func rsaKey(k []byte) (*rsa.PublicKey, bool) {
	if len(k) < 3 {
		return nil, false
	}
	el, off := int(k[0]), 1
	if el == 0 {
		el, off = int(binary.BigEndian.Uint16(k[1:3])), 3
	}
	if off+el >= len(k) || el > 8 {
		return nil, false
	}
	e := new(big.Int).SetBytes(k[off : off+el])
	if !e.IsInt64() || e.Int64() > math.MaxInt32 || e.Int64() < 3 {
		return nil, false
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(k[off+el:]), E: int(e.Int64())}, true
}

// rsaBits returns the modulus size of an RSA DNSKEY (0 when not RSA).
func rsaBits(k dnsKey) int {
	switch k.Algorithm {
	case 1, 5, 7, 8, 10:
		if pk, ok := rsaKey(k.Key); ok {
			return pk.N.BitLen()
		}
	}
	return 0
}

// verifySig checks one RRSIG over data with the given key.
func verifySig(k dnsKey, s rrsig, data []byte) verifyResult {
	switch k.Algorithm {
	case 5, 7, 8, 10:
		pk, ok := rsaKey(k.Key)
		if !ok {
			return vBad
		}
		if pk.N.BitLen() < 1024 {
			return vWeak
		}
		var h crypto.Hash
		var sum []byte
		switch k.Algorithm {
		case 5, 7:
			x := sha1.Sum(data)
			h, sum = crypto.SHA1, x[:]
		case 8:
			x := sha256.Sum256(data)
			h, sum = crypto.SHA256, x[:]
		default:
			x := sha512.Sum512(data)
			h, sum = crypto.SHA512, x[:]
		}
		if rsa.VerifyPKCS1v15(pk, h, sum, s.Signature) == nil {
			return vOK
		}
		return vBad
	case 13, 14:
		curve, n := elliptic.P256(), 32
		var sum []byte
		if k.Algorithm == 14 {
			curve, n = elliptic.P384(), 48
			x := sha512.Sum384(data)
			sum = x[:]
		} else {
			x := sha256.Sum256(data)
			sum = x[:]
		}
		if len(k.Key) != 2*n || len(s.Signature) != 2*n {
			return vBad
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(k.Key[:n]), Y: new(big.Int).SetBytes(k.Key[n:])}
		if ecdsa.Verify(pub, sum, new(big.Int).SetBytes(s.Signature[:n]), new(big.Int).SetBytes(s.Signature[n:])) {
			return vOK
		}
		return vBad
	case 15:
		if len(k.Key) != ed25519.PublicKeySize {
			return vBad
		}
		if ed25519.Verify(ed25519.PublicKey(k.Key), data, s.Signature) {
			return vOK
		}
		return vBad
	}
	return vUnsupported
}

// ---- trust anchors -----------------------------------------------------------

// TrustAnchor is a DS-style anchor (or a full DNSKEY when Key is set).
type TrustAnchor struct {
	Zone       string
	Tag        uint16
	Alg        uint8
	DigestType uint8
	Digest     []byte
	Key        []byte // DNSKEY RDATA for key-style anchors
	Source     string
}

// IANA root KSK-2017 and KSK-2024 (root-anchors.xml).
var builtinAnchors = []TrustAnchor{
	{Zone: ".", Tag: 20326, Alg: 8, DigestType: 2, Digest: mustHex("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"), Source: "IANA KSK-2017"},
	{Zone: ".", Tag: 38696, Alg: 8, DigestType: 2, Digest: mustHex("683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"), Source: "IANA KSK-2024"},
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// parseAnchors accepts DS lines ("zone [ttl] [IN] DS tag alg dt digest"),
// DNSKEY lines, or the short form "zone tag alg [dt] digest".
func parseAnchors(text string) ([]TrustAnchor, []string) {
	var out []TrustAnchor
	rrs, warns := parseZoneText(text, ".")
	for _, r := range rrs {
		switch r.Type {
		case tDS:
			if d, ok := parseDS(r.Owner, r.Rdata); ok {
				out = append(out, TrustAnchor{Zone: r.Owner, Tag: d.Tag, Alg: d.Algorithm, DigestType: d.DigestType, Digest: d.Digest, Source: "anchor file (DS)"})
			}
		case tDNSKEY:
			if k, ok := parseDNSKEY(r.Owner, r.Rdata); ok {
				out = append(out, TrustAnchor{Zone: r.Owner, Tag: k.Tag, Alg: k.Algorithm, Key: k.Rdata, Source: "anchor file (DNSKEY)"})
			}
		}
	}
	if len(out) > 0 {
		return out, nil
	}
	warns = nil
	for _, ln := range strings.Split(text, "\n") {
		f := strings.Fields(strings.SplitN(ln, ";", 2)[0])
		if len(f) < 4 || strings.HasPrefix(f[0], "#") {
			continue
		}
		tag, e1 := parseU(f[1], 65535)
		alg, e2 := parseU(f[2], 255)
		dig := f[len(f)-1]
		d, e3 := hex.DecodeString(dig)
		if firstErr(e1, e2, e3) != nil {
			warns = append(warns, "anchor: cannot parse "+strings.TrimSpace(ln))
			continue
		}
		dt := map[int]uint8{20: 1, 32: 2, 48: 4}[len(d)]
		if len(f) >= 5 {
			if v, err := parseU(f[3], 255); err == nil {
				dt = uint8(v)
			}
		}
		out = append(out, TrustAnchor{Zone: canonName(f[0], "."), Tag: uint16(tag), Alg: uint8(alg), DigestType: dt, Digest: d, Source: "anchor file"})
	}
	return out, warns
}

func (a TrustAnchor) matches(k dnsKey) bool {
	if a.Zone != k.Owner {
		return false
	}
	if a.Key != nil {
		return bytes.Equal(a.Key, k.Rdata)
	}
	if a.Tag != k.Tag || a.Alg != k.Algorithm {
		return false
	}
	d, ok := dsDigest(k, a.DigestType)
	return ok && bytes.Equal(d, a.Digest)
}

// ---- chain validation ----------------------------------------------------------

type rrsetKey struct {
	Owner string
	Type  uint16
}

type sigCheck struct {
	Owner, Signer string
	Covered       uint16
	Tag           uint16
	Alg           uint8
	Result        string // valid | bogus | expired | not-yet-valid | no-key | unsupported | weak-key | no-rrset
	Expires       time.Time
	Inception     time.Time
}

type zoneResult struct {
	Zone        string
	Status      string // secure | island | partial | insecure | bogus | unsigned
	Keys        []dnsKey
	DS          []dsRec
	DSVia       string // anchor | parent-verified | parent-missing | parent-bogus | none
	TrustKeys   []uint16
	Reasons     []string
	SigsOK      int
	SigsBad     int
	NSEC        bool
	NSEC3       bool
	NSEC3Iter   int
	NSEC3Salt   int
	NSEC3OptOut bool
}

type chainReport struct {
	Zones    []*zoneResult
	Sigs     []sigCheck
	Unsigned []rrsetKey // RRsets inside a signed zone that carry no RRSIG
	Insecure []rrsetKey // RRsets that sit under an unsigned delegation
	Warnings []string
	Records  int
	Now      time.Time
}

func serialTime(v uint32, now time.Time) time.Time {
	// RFC 4034 §3.1.5: serial-number arithmetic in a 2^32 window around now.
	n := uint32(now.Unix())
	d := int64(int32(v - n))
	return now.Add(time.Duration(d) * time.Second).Truncate(time.Second)
}

// closestZone returns the deepest zone apex (from zones) that encloses name.
func closestZone(name string, zones map[string]*zoneResult) string {
	for n := name; n != ""; n = parentName(n) {
		if _, ok := zones[n]; ok {
			return n
		}
		if n == "." {
			break
		}
	}
	return ""
}

// validateChain authenticates every zone in rrs top-down from the anchors and
// checks every RRSIG present.
func validateChain(rrs []RR, anchors []TrustAnchor, now time.Time) *chainReport {
	cr := &chainReport{Records: len(rrs), Now: now}
	sets := map[rrsetKey][]RR{}
	sigsBy := map[rrsetKey][]rrsig{}
	for _, r := range rrs {
		if r.Type == tRRSIG {
			if s, ok := parseRRSIG(r.Owner, r.Rdata); ok {
				k := rrsetKey{r.Owner, s.Covered}
				sigsBy[k] = append(sigsBy[k], s)
			}
			continue
		}
		k := rrsetKey{r.Owner, r.Type}
		sets[k] = append(sets[k], r)
	}
	zones := map[string]*zoneResult{}
	addZone := func(z string) *zoneResult {
		if zones[z] == nil {
			zones[z] = &zoneResult{Zone: z}
		}
		return zones[z]
	}
	for k, set := range sets {
		switch k.Type {
		case tDNSKEY:
			z := addZone(k.Owner)
			for _, r := range set {
				if key, ok := parseDNSKEY(r.Owner, r.Rdata); ok {
					z.Keys = append(z.Keys, key)
				}
			}
		case tDS:
			z := addZone(k.Owner)
			for _, r := range set {
				if d, ok := parseDS(r.Owner, r.Rdata); ok {
					z.DS = append(z.DS, d)
				}
			}
		}
	}
	for _, a := range anchors {
		if zones[a.Zone] == nil {
			continue // anchor for a zone that is not in the data
		}
		addZone(a.Zone)
	}
	names := make([]string, 0, len(zones))
	for n := range zones {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		if labelCount(names[i]) != labelCount(names[j]) {
			return labelCount(names[i]) < labelCount(names[j])
		}
		return names[i] < names[j]
	})
	authKeys := map[string][]dnsKey{}

	// check verifies one RRSIG against candidate keys; records the outcome.
	check := func(s rrsig, set []RR, keys []dnsKey) string {
		exp, inc := serialTime(s.Expiration, now), serialTime(s.Inception, now)
		sc := sigCheck{Owner: s.Owner, Signer: s.Signer, Covered: s.Covered, Tag: s.Tag, Alg: s.Algorithm, Expires: exp, Inception: inc}
		defer func() { cr.Sigs = append(cr.Sigs, sc) }()
		if len(set) == 0 {
			sc.Result = "no-rrset"
			return sc.Result
		}
		data, err := signedData(s, set)
		if err != nil {
			sc.Result = "bogus"
			return sc.Result
		}
		found := false
		res := "no-key"
		for _, k := range keys {
			if k.Tag != s.Tag || k.Algorithm != s.Algorithm || !k.zoneKey() || k.revoked() || k.Owner != s.Signer {
				continue
			}
			found = true
			switch verifySig(k, s, data) {
			case vOK:
				res = "valid"
			case vUnsupported:
				if res != "valid" {
					res = "unsupported"
				}
			case vWeak:
				if res != "valid" {
					res = "weak-key"
				}
			default:
				if res == "no-key" {
					res = "bogus"
				}
			}
			if res == "valid" {
				break
			}
		}
		if !found {
			res = "no-key"
		}
		if res == "valid" {
			switch {
			case now.After(exp):
				res = "expired"
			case now.Before(inc):
				res = "not-yet-valid"
			}
		}
		sc.Result = res
		return res
	}

	for _, zn := range names {
		z := zones[zn]
		if len(z.Keys) == 0 {
			z.Status = "unsigned"
			// A DS with no child data is just a delegation — unless records in
			// the input claim to be signed by this zone, whose keys are missing.
			for _, sl := range sigsBy {
				for _, s := range sl {
					if s.Signer == zn && len(z.Reasons) == 0 {
						z.Reasons = append(z.Reasons, "records are signed by this zone but its DNSKEY RRset was not supplied")
					}
				}
			}
			continue
		}
		// 1. trust points from anchors
		trust := map[uint16]bool{}
		hasAnchor := false
		for _, a := range anchors {
			if a.Zone != zn {
				continue
			}
			hasAnchor = true
			for _, k := range z.Keys {
				if a.matches(k) {
					trust[k.Tag] = true
					z.DSVia = "anchor"
				}
			}
		}
		// 2. trust points from DS at the parent
		dsAuth := "none"
		if !hasAnchor && len(z.DS) > 0 {
			dsAuth = "parent-missing"
			for _, s := range sigsBy[rrsetKey{zn, tDS}] {
				if pk, ok := authKeys[s.Signer]; ok && isSubdomain(zn, s.Signer) && zn != s.Signer {
					switch check(s, sets[rrsetKey{zn, tDS}], pk) {
					case "valid":
						dsAuth = "parent-verified"
					default:
						if dsAuth != "parent-verified" {
							dsAuth = "parent-bogus"
						}
					}
				}
			}
			for _, d := range z.DS {
				for _, k := range z.Keys {
					if d.Tag != k.Tag || d.Algorithm != k.Algorithm {
						continue
					}
					if dg, ok := dsDigest(k, d.DigestType); ok && bytes.Equal(dg, d.Digest) {
						trust[k.Tag] = true
					} else if ok {
						z.Reasons = append(z.Reasons, fmt.Sprintf("DS %d digest does not match DNSKEY %d", d.Tag, k.Tag))
					}
				}
			}
			z.DSVia = dsAuth
		}
		if z.DSVia == "" {
			z.DSVia = "none"
		}
		// 3. the DNSKEY RRset must be signed by a trust point (or, lacking any,
		// at least self-consistently by one of its own keys)
		selfOK, trustOK := false, false
		for _, s := range sigsBy[rrsetKey{zn, tDNSKEY}] {
			res := check(s, sets[rrsetKey{zn, tDNSKEY}], z.Keys)
			if res == "valid" {
				selfOK = true
				if trust[s.Tag] {
					trustOK = true
				}
			}
		}
		for t := range trust {
			z.TrustKeys = append(z.TrustKeys, t)
		}
		sort.Slice(z.TrustKeys, func(i, j int) bool { return z.TrustKeys[i] < z.TrustKeys[j] })
		parentSecure := false
		if p := parentName(zn); p != "" {
			if pz := zones[closestZone(p, zones)]; pz != nil && pz.Status == "secure" {
				parentSecure = true
			}
		}
		switch {
		case hasAnchor && trustOK:
			z.Status = "secure"
		case hasAnchor:
			z.Status = "bogus"
			if len(trust) == 0 {
				z.Reasons = append(z.Reasons, "no DNSKEY matches the configured trust anchor")
			} else {
				z.Reasons = append(z.Reasons, "DNSKEY RRset is not validly signed by the anchored key")
			}
		case dsAuth == "parent-verified" && trustOK:
			z.Status = "secure"
		case dsAuth == "parent-verified" || dsAuth == "parent-bogus":
			z.Status = "bogus"
			if dsAuth == "parent-bogus" {
				z.Reasons = append(z.Reasons, "DS RRset signature from the parent does not verify")
			} else if len(trust) == 0 {
				z.Reasons = append(z.Reasons, "no DNSKEY matches any DS published by the parent")
			} else {
				z.Reasons = append(z.Reasons, "DNSKEY RRset is not signed by a key referenced from the parent DS")
			}
		case dsAuth == "parent-missing" && trustOK:
			z.Status = "partial"
			z.Reasons = append(z.Reasons, "DS matches and signs the DNSKEY RRset, but the parent zone is not authenticated (not supplied, or not itself secure)")
		case dsAuth == "parent-missing":
			z.Status = "bogus"
			z.Reasons = append(z.Reasons, "DS present but no DS-referenced key signs the DNSKEY RRset")
		case parentSecure && len(z.DS) == 0:
			z.Status = "island"
			z.Reasons = append(z.Reasons, "parent is secure but publishes no DS for this zone — validators treat it as insecure")
		case selfOK:
			z.Status = "island"
			z.Reasons = append(z.Reasons, "DNSKEY RRset is self-signed but no anchor or DS links it to a trusted parent")
		default:
			z.Status = "bogus"
			z.Reasons = append(z.Reasons, "DNSKEY RRset has no valid signature")
		}
		if z.Status == "secure" {
			for _, k := range z.Keys {
				if k.zoneKey() && !k.revoked() {
					authKeys[zn] = append(authKeys[zn], k)
				}
			}
		}
	}
	// 4. every other signed RRset, against its signer zone's keys
	for k, sigs := range sigsBy {
		if k.Type == tDNSKEY {
			continue
		}
		if k.Type == tDS {
			if z := zones[k.Owner]; z != nil && (z.DSVia == "parent-verified" || z.DSVia == "parent-bogus") {
				continue // already checked while walking the chain
			}
		}
		for _, s := range sigs {
			keys := authKeys[s.Signer]
			if keys == nil && zones[s.Signer] != nil {
				keys = zones[s.Signer].Keys // island/partial: still check self-consistency
			}
			check(s, sets[k], keys)
		}
	}
	// 5. per-zone signature tallies, NSEC/NSEC3 posture, unsigned RRsets
	for _, sc := range cr.Sigs {
		if z := zones[sc.Signer]; z != nil && sc.Result != "no-rrset" {
			if sc.Result == "valid" {
				z.SigsOK++
			} else {
				z.SigsBad++
			}
		}
	}
	for k, set := range sets {
		zn := closestZone(k.Owner, zones)
		z := zones[zn]
		if z == nil {
			continue
		}
		switch k.Type {
		case tNSEC:
			z.NSEC = true
		case tNSEC3, tNSEC3P:
			z.NSEC3 = true
			for _, r := range set {
				if len(r.Rdata) >= 5 {
					it := int(binary.BigEndian.Uint16(r.Rdata[2:]))
					if it > z.NSEC3Iter {
						z.NSEC3Iter = it
					}
					if int(r.Rdata[4]) > z.NSEC3Salt {
						z.NSEC3Salt = int(r.Rdata[4])
					}
					if k.Type == tNSEC3 && r.Rdata[1]&1 != 0 {
						z.NSEC3OptOut = true
					}
				}
			}
		}
		if len(z.Keys) > 0 && len(sigsBy[k]) == 0 && k.Type != tDS {
			delegation := k.Owner != zn && k.Type == tNS
			// glue / occluded data: at or below a non-apex NS cut inside zn
			glue := false
			for n := k.Owner; n != zn && n != "" && n != "."; n = parentName(n) {
				if len(sets[rrsetKey{n, tNS}]) > 0 {
					glue = true
					break
				}
			}
			if delegation || glue {
				continue
			}
			// Evidence the owner really belongs to zn: it is the apex, or zn
			// signs something at/below it. Otherwise it most likely lives in an
			// unsigned child zone (insecure delegation), which is not an error.
			inZone := k.Owner == zn
			for sk := range sigsBy {
				if inZone {
					break
				}
				if isSubdomain(sk.Owner, k.Owner) {
					for _, s := range sigsBy[sk] {
						if s.Signer == zn {
							inZone = true
							break
						}
					}
				}
			}
			if inZone {
				cr.Unsigned = append(cr.Unsigned, k)
			} else {
				cr.Insecure = append(cr.Insecure, k)
			}
		}
	}
	sort.Slice(cr.Unsigned, func(i, j int) bool {
		if cr.Unsigned[i].Owner != cr.Unsigned[j].Owner {
			return cr.Unsigned[i].Owner < cr.Unsigned[j].Owner
		}
		return cr.Unsigned[i].Type < cr.Unsigned[j].Type
	})
	sort.SliceStable(cr.Sigs, func(i, j int) bool {
		if cr.Sigs[i].Owner != cr.Sigs[j].Owner {
			return labelCount(cr.Sigs[i].Owner) < labelCount(cr.Sigs[j].Owner) || labelCount(cr.Sigs[i].Owner) == labelCount(cr.Sigs[j].Owner) && cr.Sigs[i].Owner < cr.Sigs[j].Owner
		}
		return cr.Sigs[i].Covered < cr.Sigs[j].Covered
	})
	for _, n := range names {
		cr.Zones = append(cr.Zones, zones[n])
	}
	return cr
}

// ---- findings -----------------------------------------------------------------

func dnssecAlgStatus(a uint8) (string, string) {
	switch a {
	case 1, 3, 6, 12:
		return SevHigh, "MUST NOT be used (RFC 8624)"
	case 5, 7:
		return SevMedium, "SHA-1 based, NOT RECOMMENDED for signing (RFC 8624)"
	case 10:
		return SevLow, "NOT RECOMMENDED for signing (RFC 8624)"
	case 8, 13, 14, 15, 16:
		return "", ""
	}
	return SevLow, "unknown / private algorithm"
}

func chainFindings(cr *chainReport) []Finding {
	var fs []Finding
	add := func(id, title, sev, subj, desc, evid, fix string, attck []string) {
		fs = append(fs, Finding{ID: id, Title: title, Severity: sev, Score: sevWeight(sev), Category: "dnssec",
			Subject: subj, Description: desc, Evidence: evid, Remediation: fix, ATTCK: attck, Reference: "RFC 4033/4034/4035, RFC 8624, RFC 9276"})
	}
	spoof := []string{"T1557", "T1584.002"}
	for _, z := range cr.Zones {
		tags := []string{}
		for _, k := range z.Keys {
			tags = append(tags, fmt.Sprintf("%s %d (%s)", k.role(), k.Tag, dnssecAlgName(int(k.Algorithm))))
		}
		ev := strings.Join(tags, ", ")
		switch z.Status {
		case "bogus":
			add("DS-BOGUS", "DNSSEC validation fails (bogus)", SevCritical, z.Zone,
				"Validating resolvers will return SERVFAIL for this zone: "+strings.Join(z.Reasons, "; ")+".", ev,
				"Fix the DS/DNSKEY linkage or re-sign the zone; check recent key rollovers.", spoof)
		case "island":
			add("DS-ISLAND", "Zone signed but not chained to a trust anchor", SevMedium, z.Zone,
				strings.Join(z.Reasons, "; ")+". Responses are not protected against spoofing.", ev,
				"Publish a DS record for the KSK at the parent (registrar), or supply the parent data / anchor.", spoof)
		case "partial":
			add("DS-PARTIAL", "DS → DNSKEY verified; parent not supplied", SevInfo, z.Zone,
				strings.Join(z.Reasons, "; ")+".", ev, "Include the parent zone's DNSKEY/DS data (or use --fetch) to complete the chain.", nil)
		case "unsigned":
			if len(z.Reasons) > 0 {
				add("DS-NOKEYDATA", "Signer's DNSKEY RRset missing", SevMedium, z.Zone,
					strings.Join(z.Reasons, "; ")+".", "",
					"Supply the zone's DNSKEY RRset (dig +dnssec DNSKEY "+z.Zone+").", nil)
			}
		}
		for _, k := range z.Keys {
			if sev, why := dnssecAlgStatus(k.Algorithm); sev != "" {
				add("DS-ALG", "Weak or deprecated DNSSEC algorithm", sev, z.Zone,
					fmt.Sprintf("%s %d uses %s — %s.", k.role(), k.Tag, dnssecAlgName(int(k.Algorithm)), why), "",
					"Roll to ECDSAP256SHA256 (13) or ED25519 (15).", []string{"T1600"})
				break
			}
		}
		for _, k := range z.Keys {
			if bits := rsaBits(k); bits > 0 && (bits < 1024 || (k.sep() && bits < 2048)) {
				sev := SevMedium
				if bits < 1024 {
					sev = SevHigh
				}
				add("DS-RSA-SIZE", "Short RSA key", sev, z.Zone, fmt.Sprintf("%s %d is a %d-bit RSA key.", k.role(), k.Tag, bits), "",
					"Use ≥2048-bit RSA for KSKs, or move to ECDSA/Ed25519.", []string{"T1600"})
			}
			if k.revoked() {
				add("DS-REVOKED", "Revoked key still published", SevInfo, z.Zone, fmt.Sprintf("Key %d has the REVOKE bit set (RFC 5011 rollover).", k.Tag), "", "Remove it once the rollover completes.", nil)
			}
		}
		for _, d := range z.DS {
			switch d.DigestType {
			case 1:
				add("DS-SHA1-DIGEST", "SHA-1 DS digest", SevLow, z.Zone, fmt.Sprintf("DS %d uses digest type 1 (SHA-1), which MUST NOT be used for new DS records (RFC 8624).", d.Tag), "",
					"Publish a SHA-256 (type 2) DS and withdraw the SHA-1 one.", []string{"T1600"})
			case 3:
				add("DS-GOST-DIGEST", "GOST DS digest", SevHigh, z.Zone, fmt.Sprintf("DS %d uses GOST R 34.11-94 (type 3), MUST NOT (RFC 8624).", d.Tag), "", "Replace with a SHA-256 DS.", []string{"T1600"})
			}
			found := false
			for _, k := range z.Keys {
				if k.Tag == d.Tag && k.Algorithm == d.Algorithm {
					found = true
				}
			}
			if !found && len(z.Keys) > 0 && z.Status != "bogus" {
				add("DS-STALE", "DS points at a key that is not published", SevLow, z.Zone,
					fmt.Sprintf("DS %d (alg %d) has no matching DNSKEY; harmless while another DS validates, but it is left over from a rollover.", d.Tag, d.Algorithm), "",
					"Remove the stale DS at the parent.", nil)
			}
		}
		if z.NSEC {
			add("DS-NSEC-WALK", "NSEC allows zone walking", SevLow, z.Zone,
				"Plain NSEC chains link every name in the zone, so its full contents can be enumerated.", "",
				"Use NSEC3 (0 iterations, no salt) or online signing with compact denial if zone privacy matters.", []string{"T1590.002"})
		}
		if z.NSEC3 && (z.NSEC3Iter > 0 || z.NSEC3Salt > 0) {
			add("DS-NSEC3-PARAMS", "NSEC3 iterations/salt above RFC 9276 guidance", SevLow, z.Zone,
				fmt.Sprintf("NSEC3 uses %d extra iterations and a %d-byte salt; RFC 9276 recommends 0 and none (resolvers may treat high counts as insecure).", z.NSEC3Iter, z.NSEC3Salt), "",
				"Set NSEC3PARAM to 1 0 0 -.", nil)
		}
	}
	// signature-level problems
	type agg struct {
		n     int
		first sigCheck
	}
	bad := map[string]*agg{}
	for _, s := range cr.Sigs {
		if s.Result == "valid" || s.Result == "no-rrset" {
			continue
		}
		k := s.Result + "|" + s.Signer
		if bad[k] == nil {
			bad[k] = &agg{first: s}
		}
		bad[k].n++
	}
	keys := make([]string, 0, len(bad))
	for k := range bad {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		a := bad[k]
		s := a.first
		ev := fmt.Sprintf("%s %s RRSIG key %d alg %d (+%d more)", s.Owner, rrTypeName(s.Covered), s.Tag, s.Alg, a.n-1)
		switch s.Result {
		case "expired":
			add("DS-EXP", "Expired RRSIG", SevCritical, s.Signer, fmt.Sprintf("%d signature(s) expired (first: %s, expired %s).", a.n, rrTypeName(s.Covered), s.Expires.Format(time.RFC3339)), ev,
				"Re-sign the zone and fix the signer's refresh schedule.", spoof)
		case "not-yet-valid":
			add("DS-FUT", "RRSIG not yet valid", SevMedium, s.Signer, fmt.Sprintf("%d signature(s) have an inception in the future (%s) — clock skew on the signer?", a.n, s.Inception.Format(time.RFC3339)), ev,
				"Check the signer's clock; inception should be backdated by about an hour.", nil)
		case "bogus":
			add("DS-SIG-BAD", "RRSIG does not verify", SevCritical, s.Signer, fmt.Sprintf("%d signature(s) fail cryptographic verification against the signer's key.", a.n), ev,
				"The data was altered after signing or signed with a different key — re-sign the zone.", spoof)
		case "no-key":
			add("DS-SIG-NOKEY", "RRSIG references an unknown key", SevMedium, s.Signer, fmt.Sprintf("%d signature(s) name key %d, which is not in the signer's DNSKEY set (or the signer's keys were not supplied).", a.n, s.Tag), ev,
				"Supply the signer's DNSKEY RRset, or check for a botched key rollover.", nil)
		case "unsupported":
			add("DS-SIG-UNSUPPORTED", "Signature algorithm not verifiable offline", SevInfo, s.Signer, fmt.Sprintf("Algorithm %s cannot be verified by this build.", dnssecAlgName(int(s.Alg))), ev, "", nil)
		case "weak-key":
			add("DS-SIG-WEAKKEY", "Signature made with a sub-1024-bit RSA key", SevHigh, s.Signer, "The key is too short to verify safely.", ev, "Replace the key.", []string{"T1600"})
		}
	}
	// Short validity is normal for online signers, so only warn when a
	// signature is in the last fifth of its window and nearly out of time.
	for _, s := range cr.Sigs {
		if s.Result != "valid" {
			continue
		}
		left, window := s.Expires.Sub(cr.Now), s.Expires.Sub(s.Inception)
		if left < 24*time.Hour || (left < 3*24*time.Hour && window > 0 && left < window/5) {
			sev := SevLow
			if left < 24*time.Hour {
				sev = SevMedium
			}
			add("DS-SOON", "RRSIG close to expiry", sev, s.Signer,
				fmt.Sprintf("%s %s signature expires in %.1f hours (%.0f%% of its validity window left).", s.Owner, rrTypeName(s.Covered), left.Hours(), 100*left.Hours()/math.Max(window.Hours(), 1)), "",
				"Check that the signer is re-signing on schedule.", nil)
			break
		}
	}
	if len(cr.Insecure) > 0 {
		var ev []string
		for i, u := range cr.Insecure {
			if i >= 8 {
				ev = append(ev, fmt.Sprintf("… %d more", len(cr.Insecure)-8))
				break
			}
			ev = append(ev, u.Owner+" "+rrTypeName(u.Type))
		}
		add("DS-INSECURE", "Records under an unsigned (insecure) delegation", SevLow, cr.Insecure[0].Owner,
			"These records are not covered by DNSSEC: the nearest signed ancestor publishes no DS for their zone, so validators accept them unauthenticated and they can be spoofed.",
			strings.Join(ev, ", "), "Sign the zone and publish its DS at the registrar.", spoof)
	}
	if len(cr.Unsigned) > 0 {
		var ev []string
		for i, u := range cr.Unsigned {
			if i >= 8 {
				ev = append(ev, fmt.Sprintf("… %d more", len(cr.Unsigned)-8))
				break
			}
			ev = append(ev, u.Owner+" "+rrTypeName(u.Type))
		}
		add("DS-UNSIGNED-RRSET", "RRsets without signatures in a signed zone", SevMedium, "", fmt.Sprintf("%d RRset(s) have no RRSIG; a validator treats them as bogus (or they were captured without +dnssec).", len(cr.Unsigned)),
			strings.Join(ev, ", "), "Re-sign the zone, or re-capture with dig +dnssec.", nil)
	}
	return fs
}

// ---- online fetch (optional) -------------------------------------------------

// resolverAddr picks --resolver, then /etc/resolv.conf, then 1.1.1.1.
func resolverAddr(flagv string) string {
	if flagv != "" {
		if _, _, err := net.SplitHostPort(flagv); err != nil {
			return net.JoinHostPort(flagv, "53")
		}
		return flagv
	}
	if b, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			f := strings.Fields(ln)
			if len(f) >= 2 && f[0] == "nameserver" {
				return net.JoinHostPort(f[1], "53")
			}
		}
	}
	return "1.1.1.1:53"
}

func buildQuery(id uint16, name string, qtype uint16) ([]byte, error) {
	qn, err := nameWire(name)
	if err != nil {
		return nil, err
	}
	// RD + CD: the resolver recurses but does not filter bogus data, so the
	// offline validator sees exactly what an attacker or a broken zone serves.
	m := []byte{byte(id >> 8), byte(id), 0x01, 0x10, 0, 1, 0, 0, 0, 0, 0, 1}
	m = append(m, qn...)
	m = append(m, u16b(int(qtype))...)
	m = append(m, 0, 1)
	m = append(m, 0, 0, 41, 0x10, 0x00, 0, 0, 0x80, 0x00, 0, 0) // OPT: 4096, DO=1
	return m, nil
}

// readMsgName reads a possibly compressed name from a DNS message and returns
// it as uncompressed wire bytes.
func readMsgName(msg []byte, off int) ([]byte, int, error) {
	var out []byte
	end, jumps := -1, 0
	for {
		if off >= len(msg) {
			return nil, 0, errors.New("truncated name")
		}
		l := int(msg[off])
		switch {
		case l == 0:
			out = append(out, 0)
			if end < 0 {
				end = off + 1
			}
			return out, end, nil
		case l&0xc0 == 0xc0:
			if off+1 >= len(msg) || jumps > 32 {
				return nil, 0, errors.New("bad compression pointer")
			}
			if end < 0 {
				end = off + 2
			}
			off = int(binary.BigEndian.Uint16(msg[off:]) & 0x3fff)
			jumps++
		default:
			if off+1+l > len(msg) {
				return nil, 0, errors.New("truncated label")
			}
			out = append(out, msg[off:off+1+l]...)
			off += 1 + l
		}
	}
}

// parseMsg extracts the answer and authority RRs of a response, decompressing
// names embedded in RDATA so every RR is canonical-ready.
func parseMsg(msg []byte) ([]RR, int, bool, error) {
	if len(msg) < 12 {
		return nil, 0, false, errors.New("short response")
	}
	tc := msg[2]&0x02 != 0
	rcode := int(msg[3] & 0x0f)
	qd, an, ns := int(binary.BigEndian.Uint16(msg[4:])), int(binary.BigEndian.Uint16(msg[6:])), int(binary.BigEndian.Uint16(msg[8:]))
	off := 12
	for i := 0; i < qd; i++ {
		_, o, err := readMsgName(msg, off)
		if err != nil {
			return nil, rcode, tc, err
		}
		off = o + 4
	}
	var out []RR
	for i := 0; i < an+ns; i++ {
		nw, o, err := readMsgName(msg, off)
		if err != nil {
			return out, rcode, tc, err
		}
		if o+10 > len(msg) {
			return out, rcode, tc, errors.New("truncated RR")
		}
		t := binary.BigEndian.Uint16(msg[o:])
		cl := binary.BigEndian.Uint16(msg[o+2:])
		ttl := binary.BigEndian.Uint32(msg[o+4:])
		rl := int(binary.BigEndian.Uint16(msg[o+8:]))
		rs := o + 10
		if rs+rl > len(msg) {
			return out, rcode, tc, errors.New("truncated RDATA")
		}
		rd := append([]byte{}, msg[rs:rs+rl]...)
		decomp := func(prefix int, names int) {
			b := append([]byte{}, msg[rs:rs+prefix]...)
			p := rs + prefix
			for k := 0; k < names; k++ {
				n, np, err := readMsgName(msg, p)
				if err != nil {
					return
				}
				b = append(b, n...)
				p = np
			}
			b = append(b, msg[p:rs+rl]...)
			rd = b
		}
		switch t {
		case tNS, tCNAME, tPTR, tDNAME:
			decomp(0, 1)
		case tMX:
			decomp(2, 1)
		case tSOA:
			decomp(0, 2)
		}
		owner, _, _ := wireNameAt(nw, 0)
		out = append(out, RR{Owner: strings.ToLower(owner), Type: t, Class: cl, TTL: ttl, Rdata: rd})
		off = rs + rl
	}
	return out, rcode, tc, nil
}

func exchange(server, name string, qtype uint16) ([]RR, int, error) {
	id := uint16(rand.Intn(65536))
	q, err := buildQuery(id, name, qtype)
	if err != nil {
		return nil, 0, err
	}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		c, err := net.DialTimeout("udp", server, 4*time.Second)
		if err != nil {
			return nil, 0, err
		}
		c.SetDeadline(time.Now().Add(4 * time.Second))
		c.Write(q)
		buf := make([]byte, 65535)
		n, err := c.Read(buf)
		c.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if n < 2 || binary.BigEndian.Uint16(buf) != id {
			lastErr = errors.New("mismatched response id")
			continue
		}
		rrs, rc, tc, err := parseMsg(buf[:n])
		if !tc {
			return rrs, rc, err
		}
		// truncated: retry over TCP
		tcp, err := net.DialTimeout("tcp", server, 6*time.Second)
		if err != nil {
			return nil, 0, err
		}
		tcp.SetDeadline(time.Now().Add(8 * time.Second))
		tcp.Write(append(u16b(len(q)), q...))
		lb := make([]byte, 2)
		if _, err := io.ReadFull(tcp, lb); err != nil {
			tcp.Close()
			return nil, 0, err
		}
		resp := make([]byte, binary.BigEndian.Uint16(lb))
		_, err = io.ReadFull(tcp, resp)
		tcp.Close()
		if err != nil {
			return nil, 0, err
		}
		rrs, rc, _, err = parseMsg(resp)
		return rrs, rc, err
	}
	return nil, 0, lastErr
}

// fetchChain queries DNSKEY and DS for every ancestor of name (root first)
// plus the requested RRset, returning everything needed to validate offline.
func fetchChain(name string, qtype uint16, server string, progress func(string)) ([]RR, []string) {
	name = canonName(name, ".")
	var chain []string
	for n := name; n != ""; n = parentName(n) {
		chain = append([]string{n}, chain...)
		if n == "." {
			break
		}
	}
	var all []RR
	var warns []string
	ask := func(n string, t uint16) {
		progress(fmt.Sprintf("%s %s", n, rrTypeName(t)))
		rrs, rc, err := exchange(server, n, t)
		if err != nil {
			warns = append(warns, fmt.Sprintf("%s %s: %v", n, rrTypeName(t), err))
			return
		}
		if rc != 0 && rc != 3 {
			warns = append(warns, fmt.Sprintf("%s %s: rcode %d", n, rrTypeName(t), rc))
		}
		keep := func(tt uint16) bool {
			return tt == tDNSKEY || tt == tDS || tt == tNSEC || tt == tNSEC3 || tt == t
		}
		for _, r := range rrs {
			if r.Type == tRRSIG {
				if len(r.Rdata) >= 2 && keep(binary.BigEndian.Uint16(r.Rdata)) {
					all = append(all, r)
				}
			} else if keep(r.Type) {
				all = append(all, r)
			}
		}
	}
	for _, n := range chain {
		if n != "." {
			ask(n, tDS)
		}
		ask(n, tDNSKEY)
	}
	if qtype != tDNSKEY && qtype != tDS {
		ask(name, qtype)
	}
	all = dedupeRRs(all)
	sigs := 0
	for _, r := range all {
		if r.Type == tRRSIG {
			sigs++
		}
	}
	if sigs == 0 && len(all) > 0 {
		warns = append(warns, "the resolver returned no RRSIGs — it may strip DNSSEC data; try --resolver 1.1.1.1 or 9.9.9.9")
	}
	return all, warns
}

// ---- demo + self-test data (synthetic, signed at run time) -------------------

type demoSigner struct {
	zone string
	alg  uint8
	ecK  *ecdsa.PrivateKey
	edK  ed25519.PrivateKey
	key  dnsKey
}

func newDemoKey(zone string, flags uint16, alg uint8) *demoSigner {
	d := &demoSigner{zone: zone, alg: alg}
	var pub []byte
	if alg == 15 {
		p, k, _ := ed25519.GenerateKey(crand.Reader)
		d.edK, pub = k, p
	} else {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
		d.ecK = k
		x, y := make([]byte, 32), make([]byte, 32)
		k.X.FillBytes(x)
		k.Y.FillBytes(y)
		pub = append(x, y...)
	}
	rd := append(append(u16b(int(flags)), 3, alg), pub...)
	d.key, _ = parseDNSKEY(zone, rd)
	return d
}

func (d *demoSigner) rr() RR {
	return RR{Owner: d.zone, Type: tDNSKEY, Class: 1, TTL: 3600, Rdata: d.key.Rdata}
}

// sign produces an RRSIG RR over set, valid from inc to exp.
func (d *demoSigner) sign(set []RR, inc, exp time.Time) RR {
	sn, _ := nameWire(d.zone)
	rd := append(u16b(int(set[0].Type)), d.alg, byte(labelCount(set[0].Owner)))
	rd = append(rd, u32b(set[0].TTL)...)
	rd = append(rd, u32b(uint32(exp.Unix()))...)
	rd = append(rd, u32b(uint32(inc.Unix()))...)
	rd = append(rd, u16b(int(d.key.Tag))...)
	rd = append(rd, sn...)
	s, _ := parseRRSIG(set[0].Owner, rd)
	data, _ := signedData(s, set)
	var sig []byte
	if d.alg == 15 {
		sig = ed25519.Sign(d.edK, data)
	} else {
		h := sha256.Sum256(data)
		r, ss, _ := ecdsa.Sign(crand.Reader, d.ecK, h[:])
		rb, sb := make([]byte, 32), make([]byte, 32)
		r.FillBytes(rb)
		ss.FillBytes(sb)
		sig = append(rb, sb...)
	}
	return RR{Owner: set[0].Owner, Type: tRRSIG, Class: 1, TTL: set[0].TTL, Rdata: append(rd, sig...)}
}

func dsFor(k dnsKey, owner string) RR {
	d, _ := dsDigest(k, 2)
	return RR{Owner: owner, Type: tDS, Class: 1, TTL: 3600, Rdata: append(append(u16b(int(k.Tag)), k.Algorithm, 2), d...)}
}

// demoChain builds a signed hierarchy rooted at "lab.": a secure child,
// a child whose DS no longer matches (bogus), a zone with an expired
// signature, a tampered A record, and an unanchored island.
func demoChain(now time.Time) ([]RR, []TrustAnchor) {
	inc, exp := now.Add(-time.Hour), now.Add(20*24*time.Hour)
	var rrs []RR
	signSet := func(s *demoSigner, set []RR, i, e time.Time) {
		rrs = append(rrs, set...)
		rrs = append(rrs, s.sign(set, i, e))
	}
	zone := func(name string, alg uint8) (*demoSigner, *demoSigner) {
		ksk, zsk := newDemoKey(name, 257, alg), newDemoKey(name, 256, alg)
		signSet(ksk, []RR{ksk.rr(), zsk.rr()}, inc, exp)
		return ksk, zsk
	}
	rootK, rootZ := zone("lab.", 13)
	anchor := TrustAnchor{Zone: "lab.", Tag: rootK.key.Tag, Alg: 13, DigestType: 2, Source: "demo anchor"}
	anchor.Digest, _ = dsDigest(rootK.key, 2)
	_ = rootK
	child := func(name string, alg uint8, ds RR) (*demoSigner, *demoSigner) {
		signSet(rootZ, []RR{ds}, inc, exp)
		return zone(name, alg)
	}
	// secure.lab. — ED25519, correct DS
	sk := newDemoKey("secure.lab.", 257, 15)
	sz := newDemoKey("secure.lab.", 256, 15)
	signSet(rootZ, []RR{dsFor(sk.key, "secure.lab.")}, inc, exp)
	signSet(sk, []RR{sk.rr(), sz.rr()}, inc, exp)
	www := RR{Owner: "www.secure.lab.", Type: tA, Class: 1, TTL: 300, Rdata: []byte{192, 0, 2, 10}}
	signSet(sz, []RR{www}, inc, exp)
	mx := RR{Owner: "secure.lab.", Type: tMX, Class: 1, TTL: 300}
	mx.Rdata, _ = rdataFromText(tMX, []string{"10", "Mail.Secure.LAB."}, ".")
	signSet(sz, []RR{mx}, inc, exp)
	// broken.lab. — parent DS refers to an old key
	old := newDemoKey("broken.lab.", 257, 13)
	child("broken.lab.", 13, dsFor(old.key, "broken.lab."))
	// stale.lab. — correct chain, but one RRSIG expired yesterday and one
	// RRset tampered after signing
	stK := newDemoKey("stale.lab.", 257, 13)
	stZ := newDemoKey("stale.lab.", 256, 13)
	signSet(rootZ, []RR{dsFor(stK.key, "stale.lab.")}, inc, exp)
	signSet(stK, []RR{stK.rr(), stZ.rr()}, inc, exp)
	txt := RR{Owner: "stale.lab.", Type: tTXT, Class: 1, TTL: 300}
	txt.Rdata, _ = rdataFromText(tTXT, []string{"v=spf1 -all"}, ".")
	signSet(stZ, []RR{txt}, now.Add(-30*24*time.Hour), now.Add(-24*time.Hour))
	api := RR{Owner: "api.stale.lab.", Type: tA, Class: 1, TTL: 300, Rdata: []byte{192, 0, 2, 20}}
	sig := stZ.sign([]RR{api}, inc, exp)
	api.Rdata = []byte{203, 0, 113, 66} // altered after signing → bogus
	rrs = append(rrs, api, sig)
	// island.test. — self-signed, nothing links it to an anchor
	zone("island.test.", 13)
	return rrs, []TrustAnchor{anchor}
}

// rrsToText renders RRs as a zone-file style listing (used by --save and the demo).
func rrsToText(rrs []RR) string {
	sorted := append([]RR{}, rrs...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Owner != sorted[j].Owner {
			return labelCount(sorted[i].Owner) < labelCount(sorted[j].Owner) || labelCount(sorted[i].Owner) == labelCount(sorted[j].Owner) && sorted[i].Owner < sorted[j].Owner
		}
		return sorted[i].Type < sorted[j].Type
	})
	var sb strings.Builder
	for _, r := range sorted {
		sb.WriteString(rrText(r) + "\n")
	}
	return sb.String()
}

// ---- report glue ----------------------------------------------------------------

type chainRow struct {
	Zone      string `json:"zone"`
	Status    string `json:"status"`
	Via       string `json:"trust_via"`
	Keys      string `json:"keys"`
	TrustKeys string `json:"trusted_keys,omitempty"`
	DS        string `json:"ds,omitempty"`
	SigsOK    int    `json:"sigs_valid"`
	SigsBad   int    `json:"sigs_failed"`
	Denial    string `json:"denial,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

func chainRows(cr *chainReport) []chainRow {
	var rows []chainRow
	for _, z := range cr.Zones {
		if len(z.Keys) == 0 && z.Status == "unsigned" && len(z.Reasons) == 0 {
			continue // bare delegation (DS only, child not supplied)
		}
		var ks, ts, ds []string
		for _, k := range z.Keys {
			ks = append(ks, fmt.Sprintf("%s:%d/%d", k.role(), k.Tag, k.Algorithm))
		}
		for _, t := range z.TrustKeys {
			ts = append(ts, strconv.Itoa(int(t)))
		}
		for _, d := range z.DS {
			ds = append(ds, fmt.Sprintf("%d/%d/%d", d.Tag, d.Algorithm, d.DigestType))
		}
		den := ""
		switch {
		case z.NSEC3:
			den = fmt.Sprintf("NSEC3 it=%d salt=%d", z.NSEC3Iter, z.NSEC3Salt)
		case z.NSEC:
			den = "NSEC"
		}
		rows = append(rows, chainRow{Zone: z.Zone, Status: z.Status, Via: z.DSVia, Keys: strings.Join(ks, " "),
			TrustKeys: strings.Join(ts, ","), DS: strings.Join(ds, " "), SigsOK: z.SigsOK, SigsBad: z.SigsBad,
			Denial: den, Reason: strings.Join(z.Reasons, "; ")})
	}
	return rows
}

func statusColor(s string) string {
	switch s {
	case "secure":
		return GRN + B
	case "partial":
		return CY
	case "island", "insecure":
		return YLW
	case "bogus":
		return R + B
	}
	return GY
}

func printChain(rows []chainRow) {
	if len(rows) == 0 {
		info("no DNSKEY/DS data found")
		return
	}
	for _, r := range rows {
		fmt.Println("  " + col(pad("["+strings.ToUpper(r.Status)+"]", 10), statusColor(r.Status)) + " " + col(r.Zone, W+B) +
			col("   via "+r.Via, DIM))
		kv("   keys", nonEmptyStr(r.Keys, "-"))
		if r.DS != "" {
			kv("   DS at parent", r.DS)
		}
		if r.TrustKeys != "" {
			kv("   trust point", r.TrustKeys)
		}
		kv("   signatures", fmt.Sprintf("%d valid, %d failed", r.SigsOK, r.SigsBad))
		if r.Denial != "" {
			kv("   denial", r.Denial)
		}
		if r.Reason != "" {
			kv("   why", r.Reason)
		}
	}
}

func nonEmptyStr(a, b string) string {
	if strings.TrimSpace(a) == "" {
		return b
	}
	return a
}

// analysis bundles one validation run for display and export.
type analysis struct {
	target string
	rrs    []RR
	cr     *chainReport
	fs     []Finding
	warns  []string
}

func analyze(target string, rrs []RR, anchors []TrustAnchor, now time.Time, warns []string) *analysis {
	cr := validateChain(rrs, anchors, now)
	cr.Warnings = warns
	return &analysis{target: target, rrs: rrs, cr: cr, fs: chainFindings(cr), warns: warns}
}

func (a *analysis) report() Report {
	r := buildReport(a.target, append([]Finding{}, a.fs...))
	r.Chain = chainRows(a.cr)
	r.Records = a.cr.Records
	r.Warnings = a.warns
	return r
}

var lastAnalysis *analysis

// ---- CLI ------------------------------------------------------------------------

var (
	fZone     = flag.String("zone", "", "zone file / dig output to validate")
	fAnchor   = flag.String("anchor", "", "trust anchor file (DS / DNSKEY lines)")
	fNoRoot   = flag.Bool("no-root-anchor", false, "do not use the built-in IANA root anchors")
	fName     = flag.String("origin", "", "origin for relative names in --zone")
	fFetch    = flag.String("fetch", "", "fetch the chain for NAME from a resolver, then validate")
	fType     = flag.String("type", "A", "record type to fetch with --fetch")
	fResolver = flag.String("resolver", "", "resolver for --fetch (default: /etc/resolv.conf)")
	fSave     = flag.String("save", "", "save fetched records as a zone file")
	fNow      = flag.String("now", "", "validate as of this time (RFC3339 / YYYYMMDDHHMMSS)")
	fFormat   = flag.String("format", "txt", "report format")
	fOutput   = flag.String("output", "", "write to FILE")
	fNoColor  = flag.Bool("no-color", false, "disable colour")
	fDemo     = flag.Bool("demo", false, "run demonstration")
	fSelfTest = flag.Bool("selftest", false, "run self-tests")
	fVersion  = flag.Bool("version", false, "print version")
)

func usage() {
	banner()
	section := func(t string) { fmt.Println("  " + col(t, CY+B)) }
	section("USAGE")
	fmt.Println("    ODNSSEC [flags]            (no flags → interactive TUI)")
	fmt.Println()
	section("DESCRIPTION")
	fmt.Println("    DNSSEC chain-of-trust validator. Parses DNSKEY / DS / RRSIG / NSEC(3) from")
	fmt.Println("    zone files or dig output, computes RFC 4034 key tags and DS digests,")
	fmt.Println("    cryptographically verifies RRSIGs (RSA, ECDSA P-256/384, Ed25519) and walks")
	fmt.Println("    trust from the IANA root anchors down to every zone in the input.")
	fmt.Println()
	section("INPUT")
	fmt.Println("    --zone FILE         zone file or `dig +dnssec` output (any number of zones)")
	fmt.Println("    --origin ZONE       origin for relative names (default .)")
	fmt.Println("    --fetch NAME        query the chain root→NAME from a resolver (CD+DO set)")
	fmt.Println("    --type T            record type to fetch for NAME (default A)")
	fmt.Println("    --resolver IP[:P]   resolver for --fetch (default /etc/resolv.conf)")
	fmt.Println("    --save FILE         write fetched records as a zone file (re-check offline)")
	fmt.Println()
	section("TRUST")
	fmt.Println("    --anchor FILE       extra trust anchors (DS or DNSKEY lines)")
	fmt.Println("    --no-root-anchor    ignore the built-in IANA KSK-2017 / KSK-2024 anchors")
	fmt.Println("    --now TIME          evaluate signature validity at TIME (forensics)")
	fmt.Println()
	section("REPORTING")
	fmt.Println("    --format txt|md|json|csv|sarif   --output FILE   --no-color")
	fmt.Println()
	section("GENERAL")
	fmt.Println("    --demo   --selftest   --version   -h")
	fmt.Println()
	section("EXAMPLES")
	fmt.Println("    ODNSSEC --fetch cloudflare.com")
	fmt.Println("    ODNSSEC --fetch example.org --save chain.zone && ODNSSEC --zone chain.zone")
	fmt.Println("    dig +dnssec DNSKEY example.com > k.txt && ODNSSEC --zone k.txt --format json")
	fmt.Println()
	fmt.Println("  " + col("ATT&CK", CY+B) + "  T1557 Adversary-in-the-Middle · T1584.002 DNS Server · T1600 · T1590.002")
	line(66)
}

func parseNow(s string) (time.Time, error) {
	if s == "" {
		return time.Now(), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("20060102150405", s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("cannot parse --now %q", s)
}

func loadAnchorFile(path string, noRoot bool) ([]TrustAnchor, []string, error) {
	var anchors []TrustAnchor
	if !noRoot {
		anchors = append(anchors, builtinAnchors...)
	}
	if path == "" {
		return anchors, nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	extra, warns := parseAnchors(string(b))
	if len(extra) == 0 {
		return nil, warns, fmt.Errorf("no usable anchors in %s", path)
	}
	return append(anchors, extra...), warns, nil
}

func main() {
	flag.Usage = usage
	for _, a := range os.Args[1:] {
		if a == "-h" || a == "--help" || a == "help" {
			usage()
			return
		}
	}
	flag.Parse()
	if *fNoColor {
		noColor = true
	}
	switch {
	case *fVersion:
		fmt.Printf("%s v%s — %s\n", APPNAME, VERSION, SUITE)
		fmt.Printf("Author : %s\nWebsite: %s\n", AUTHOR, WEBSITE)
		fmt.Println("Build  : Go stdlib, static (CGO disabled)")
		return
	case *fSelfTest:
		if !runSelfTest() {
			os.Exit(1)
		}
		return
	case *fDemo:
		runDemo()
		return
	case *fZone != "" || *fFetch != "":
		runCLI()
		return
	}
	if len(os.Args) > 1 {
		usage()
		return
	}
	interactive()
}

func runCLI() {
	now, err := parseNow(*fNow)
	if err != nil {
		errMsg(err.Error())
		os.Exit(2)
	}
	anchors, aw, err := loadAnchorFile(*fAnchor, *fNoRoot)
	if err != nil {
		errMsg(err.Error())
		os.Exit(2)
	}
	var rrs []RR
	var warns []string
	target := *fZone
	if *fFetch != "" {
		qt, ok := rrTypeNum(*fType)
		if !ok {
			errMsg("unknown --type " + *fType)
			os.Exit(2)
		}
		srv := resolverAddr(*fResolver)
		quiet := *fOutput == "" && strings.ToLower(*fFormat) != "txt"
		rrs, warns = fetchChain(*fFetch, qt, srv, func(s string) {
			if !quiet {
				fmt.Fprintln(os.Stderr, col("  [*] ", CY)+col("query "+s+" @"+srv, DIM+W))
			}
		})
		target = canonName(*fFetch, ".")
		if *fSave != "" {
			if err := os.WriteFile(*fSave, []byte("; ODNSSEC fetch of "+target+" via "+srv+" at "+time.Now().UTC().Format(time.RFC3339)+"\n"+rrsToText(rrs)), 0644); err != nil {
				errMsg(err.Error())
			}
		}
	} else {
		b, err := os.ReadFile(*fZone)
		if err != nil {
			errMsg(err.Error())
			os.Exit(1)
		}
		rrs, warns = parseZoneText(string(b), nonEmptyStr(*fName, "."))
	}
	if len(rrs) == 0 {
		errMsg("no DNS records parsed")
		for _, w := range warns {
			warnMsg(w)
		}
		os.Exit(1)
	}
	a := analyze(target, rrs, anchors, now, append(aw, warns...))
	if err := writeOutput(*fOutput, renderReport(*fFormat, a.report())); err != nil {
		errMsg(err.Error())
		os.Exit(1)
	}
	if a.report().Summary.Critical > 0 {
		os.Exit(3) // bogus chain: lets scripts and CI gate on the result
	}
}

// ---- demo -----------------------------------------------------------------------

func runDemo() {
	// Machine-readable output to stdout must not be mixed with the TUI view.
	if *fOutput == "" && strings.ToLower(*fFormat) != "txt" {
		now := time.Now()
		rrs, anchors := demoChain(now)
		a := analyze("lab. (synthetic)", rrs, anchors, now, nil)
		writeOutput("", renderReport(*fFormat, a.report()))
		return
	}
	banner()
	okMsg("ODNSSEC demonstration — a synthetic hierarchy signed at run time")
	info("lab. is anchored; secure.lab. is fine; broken.lab. has a stale DS; stale.lab. has an expired and a tampered RRSIG; island.test. is unanchored")
	now := time.Now()
	rrs, anchors := demoChain(now)
	a := analyze("lab. (synthetic)", rrs, anchors, now, nil)
	lastAnalysis = a
	fmt.Println()
	sectionHeader("Chain of trust")
	printChain(chainRows(a.cr))
	fmt.Println()
	sectionHeader("Findings")
	r := a.report()
	printFindingsTable(r.Findings)
	printSummary(r.Summary)
	fmt.Println()
	okMsg("demo complete — export it from the menu, or re-run with --demo --format json")
	if *fOutput != "" || strings.ToLower(*fFormat) != "txt" {
		writeOutput(*fOutput, renderReport(*fFormat, r))
	}
}

// ---- self-test ------------------------------------------------------------------

// rootKSK2017 is the live IANA root KSK (tag 20326) as served by the root.
const rootKSK2017 = ".\t172800\tIN\tDNSKEY\t257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3 +/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kv ArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF 0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+e oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfd RUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwN R1AkUTV74bU="

func runSelfTest() bool {
	banner()
	pass, fail := 0, 0
	check := func(n string, ok bool, got string) {
		if ok {
			okMsg(n)
			pass++
		} else {
			errMsg(n + "  →  " + got)
			fail++
		}
	}
	// Known answer: the real root KSK-2017 must hash to the built-in anchor.
	rrs, w := parseZoneText(rootKSK2017, ".")
	if len(rrs) == 1 {
		k, _ := parseDNSKEY(rrs[0].Owner, rrs[0].Rdata)
		check("RFC 4034 key tag of root KSK-2017 = 20326", k.Tag == 20326, strconv.Itoa(int(k.Tag)))
		check("root KSK matches built-in IANA anchor (SHA-256 DS)", builtinAnchors[0].matches(k), "")
		check("RSA modulus size 2048", rsaBits(k) == 2048, strconv.Itoa(rsaBits(k)))
	} else {
		check("parse tab-separated dig DNSKEY line", false, fmt.Sprint(w))
	}
	// Parser: multi-line parentheses, comments, $ORIGIN, relative + blank owners.
	zf := "$ORIGIN example.\n$TTL 300\n@ IN SOA ns1 hostmaster ( 1 7200 3600 1209600 300 ) ; soa\n  IN NS ns1\nns1 A 192.0.2.1\nwww 60 IN CNAME @\n" +
		"txt IN TXT \"hello world\" \"two\"\n"
	zr, zw := parseZoneText(zf, ".")
	types := map[uint16]int{}
	for _, r := range zr {
		types[r.Type]++
	}
	check("zone parser: SOA/NS/A/CNAME/TXT with parens + $ORIGIN", len(zw) == 0 && types[tSOA] == 1 && types[tNS] == 1 && types[tA] == 1 && types[tCNAME] == 1 && types[tTXT] == 1, fmt.Sprint(types, zw))
	check("relative owner + blank owner resolve", len(zr) > 1 && zr[1].Owner == "example." && zr[2].Owner == "ns1.example.", fmt.Sprint(zr[1].Owner, zr[2].Owner))
	// An "RRSIG DNSKEY" line must not be mistaken for a DNSKEY (old bug).
	rr2, _ := parseZoneText("example. 300 IN RRSIG DNSKEY 13 1 300 20300101000000 20200101000000 12345 example. AAAA", ".")
	check("RRSIG covering DNSKEY parsed as RRSIG", len(rr2) == 1 && rr2[0].Type == tRRSIG, fmt.Sprint(len(rr2)))
	// Round trip: text → wire → text → wire.
	for _, l := range []string{"a. 1 IN NSEC3 1 1 0 - 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR A RRSIG", "a. 1 IN NSEC b. A NS SOA RRSIG NSEC DNSKEY TYPE65534", "a. 1 IN MX 10 mail.a."} {
		x, _ := parseZoneText(l, ".")
		y, _ := parseZoneText(rrsToText(x), ".")
		check("round-trip "+strings.Fields(l)[3], len(x) == 1 && len(y) == 1 && bytes.Equal(x[0].Rdata, y[0].Rdata), rrsToText(x))
	}
	// Full synthetic chain (ECDSA P-256 + Ed25519, signed now).
	now := time.Now()
	drrs, anchors := demoChain(now)
	cr := validateChain(drrs, anchors, now)
	st := map[string]string{}
	for _, z := range cr.Zones {
		st[z.Zone] = z.Status
	}
	check("anchored root zone is secure", st["lab."] == "secure", st["lab."])
	check("child with verified DS is secure (Ed25519)", st["secure.lab."] == "secure", st["secure.lab."])
	check("stale DS → bogus", st["broken.lab."] == "bogus", st["broken.lab."])
	check("unanchored zone → island", st["island.test."] == "island", st["island.test."])
	res := map[string]string{}
	for _, s := range cr.Sigs {
		res[s.Owner+"/"+rrTypeName(s.Covered)] = s.Result
	}
	check("mixed-case MX verifies (canonical lowercasing)", res["secure.lab./MX"] == "valid", res["secure.lab./MX"])
	check("tampered A record detected", res["api.stale.lab./A"] == "bogus", res["api.stale.lab./A"])
	check("expired RRSIG detected", res["stale.lab./TXT"] == "expired", res["stale.lab./TXT"])
	check("--now in the past makes it valid", validateChainResult(drrs, anchors, now.Add(-48*time.Hour), "stale.lab./TXT") == "valid", "")
	fs := chainFindings(cr)
	ids := map[string]bool{}
	for _, f := range fs {
		ids[f.ID] = true
	}
	check("findings: DS-BOGUS, DS-EXP, DS-SIG-BAD, DS-ISLAND", ids["DS-BOGUS"] && ids["DS-EXP"] && ids["DS-SIG-BAD"] && ids["DS-ISLAND"], fmt.Sprint(ids))
	check("no root anchor → lab. not secure", validateChainStatus(drrs, nil, now, "lab.") != "secure", "")
	// RSA/SHA-256 (algorithm 8) end to end.
	if pk, err := rsa.GenerateKey(crand.Reader, 2048); err == nil {
		e := big.NewInt(int64(pk.E)).Bytes()
		rd := append(append(u16b(257), 3, 8), byte(len(e)))
		rd = append(append(rd, e...), pk.N.Bytes()...)
		k, _ := parseDNSKEY("rsa.", rd)
		set := []RR{{Owner: "rsa.", Type: tDNSKEY, Class: 1, TTL: 60, Rdata: rd}}
		sr := append(u16b(tDNSKEY), 8, 1)
		sr = append(sr, u32b(60)...)
		sr = append(sr, u32b(uint32(now.Add(time.Hour).Unix()))...)
		sr = append(sr, u32b(uint32(now.Add(-time.Hour).Unix()))...)
		sr = append(sr, u16b(int(k.Tag))...)
		sn, _ := nameWire("rsa.")
		sr = append(sr, sn...)
		s, _ := parseRRSIG("rsa.", sr)
		data, _ := signedData(s, set)
		h := sha256.Sum256(data)
		sig, _ := rsa.SignPKCS1v15(crand.Reader, pk, crypto.SHA256, h[:])
		s.Signature = sig
		check("RSASHA256 signature verifies", verifySig(k, s, data) == vOK, "")
		data[len(data)-1] ^= 1
		check("RSASHA256 rejects altered data", verifySig(k, s, data) == vBad, "")
	}
	fmt.Println()
	if fail == 0 {
		okMsg(fmt.Sprintf("all %d self-tests passed", pass))
	} else {
		errMsg(fmt.Sprintf("%d passed, %d failed", pass, fail))
	}
	return fail == 0
}

func validateChainResult(rrs []RR, anchors []TrustAnchor, now time.Time, key string) string {
	for _, s := range validateChain(rrs, anchors, now).Sigs {
		if s.Owner+"/"+rrTypeName(s.Covered) == key {
			return s.Result
		}
	}
	return ""
}

func validateChainStatus(rrs []RR, anchors []TrustAnchor, now time.Time, zone string) string {
	for _, z := range validateChain(rrs, anchors, now).Zones {
		if z.Zone == zone {
			return z.Status
		}
	}
	return ""
}

// ---- interactive TUI -------------------------------------------------------------

func showAnalysis(a *analysis) {
	lastAnalysis = a
	sectionHeader("Chain of trust — " + a.target)
	printChain(chainRows(a.cr))
	for i, w := range a.warns {
		if i >= 6 {
			info(fmt.Sprintf("… %d more parser warnings", len(a.warns)-6))
			break
		}
		warnMsg(w)
	}
	fmt.Println()
	sectionHeader("Findings")
	r := a.report()
	printFindingsTable(r.Findings)
	printSummary(r.Summary)
}

var tuiActions = []struct {
	name, desc string
	run        func()
}{
	{"Validate a zone / dig file", "Offline chain check from a file", func() {
		p := prompt("zone or dig output file")
		b, err := os.ReadFile(p)
		if err != nil {
			errMsg(err.Error())
			pause()
			return
		}
		rrs, warns := parseZoneText(string(b), nonEmptyStr(prompt("origin for relative names (blank = .)"), "."))
		anchors, aw, err := loadAnchorFile(prompt("extra anchor file (blank = IANA root only)"), false)
		if err != nil {
			errMsg(err.Error())
			pause()
			return
		}
		showAnalysis(analyze(p, rrs, anchors, time.Now(), append(aw, warns...)))
		pause()
	}},
	{"Fetch & validate a domain", "Query root → domain from a resolver", func() {
		n := prompt("domain name")
		if n == "" {
			return
		}
		srv := resolverAddr(prompt("resolver (blank = system)"))
		rrs, warns := fetchChain(n, tA, srv, func(s string) { info("query " + s) })
		showAnalysis(analyze(canonName(n, "."), rrs, builtinAnchors, time.Now(), warns))
		if p := prompt("save records to file (blank = skip)"); p != "" {
			if err := os.WriteFile(p, []byte(rrsToText(rrs)), 0644); err != nil {
				errMsg(err.Error())
			} else {
				okMsg("saved " + p)
			}
		}
		pause()
	}},
	{"Signature details", "Every RRSIG of the last run", func() {
		if lastAnalysis == nil {
			warnMsg("run a validation first")
			pause()
			return
		}
		sectionHeader("RRSIGs")
		var rows [][]string
		for _, s := range lastAnalysis.cr.Sigs {
			rows = append(rows, []string{truncStr(s.Owner, 28), rrTypeName(s.Covered), strconv.Itoa(int(s.Tag)), strconv.Itoa(int(s.Alg)), s.Expires.Format("2006-01-02"), s.Result})
		}
		table([]string{"OWNER", "TYPE", "KEY", "ALG", "EXPIRES", "RESULT"}, rows)
		pause()
	}},
	{"Run synthetic demo", "Signed lab hierarchy with faults", func() { runDemo(); pause() }},
	{"Algorithm catalogue", "DNSSEC algorithms + RFC 8624 status", func() {
		sectionHeader("DNSSEC algorithms (RFC 8624)")
		var rows [][]string
		for _, id := range []int{1, 3, 5, 6, 7, 8, 10, 12, 13, 14, 15, 16} {
			sev, why := dnssecAlgStatus(uint8(id))
			if sev == "" {
				why = "recommended / acceptable"
			}
			v := "yes"
			if id < 5 || id == 6 || id == 12 || id == 16 {
				v = "no"
			}
			rows = append(rows, []string{strconv.Itoa(id), dnssecAlgName(id), v, why})
		}
		table([]string{"ID", "NAME", "VERIFIED HERE", "STATUS"}, rows)
		pause()
	}},
	{"Trust anchors", "Built-in IANA root KSKs", func() {
		sectionHeader("Built-in trust anchors")
		for _, a := range builtinAnchors {
			kv(a.Source, fmt.Sprintf("%s DS %d %d %d %X", a.Zone, a.Tag, a.Alg, a.DigestType, a.Digest))
		}
		pause()
	}},
	{"Explain the checks", "What a validator verifies", func() {
		sectionHeader("Chain-of-trust checks")
		for i, s := range []string{
			"Trust anchor (IANA root KSK) → hashes to a DNSKEY of the root zone",
			"That KSK signs the DNSKEY RRset → all root keys become trusted",
			"Root ZSK signs the child's DS RRset → DS digest = SHA-256(owner|DNSKEY)",
			"Child KSK matching the DS signs the child's DNSKEY RRset → repeat downwards",
			"Every RRSIG: key tag + algorithm match, crypto verifies, now ∈ [inception, expiry]",
			"Posture: algorithms (RFC 8624), RSA size, SHA-1 DS, NSEC walking, NSEC3 params (RFC 9276)",
			"Statuses: secure · partial (parent not supplied) · island (no DS) · bogus (SERVFAIL)",
		} {
			fmt.Printf("   %s %s\n", col(fmt.Sprintf("%d.", i+1), CY+B), col(s, W))
		}
		pause()
	}},
	{"Export last report", "txt / md / json / csv / sarif", func() {
		if lastAnalysis == nil {
			warnMsg("run a validation first")
			pause()
			return
		}
		f := nonEmptyStr(prompt("format txt/md/json/csv/sarif"), "txt")
		if err := writeOutput(prompt("output file (blank = screen)"), renderReport(f, lastAnalysis.report())); err != nil {
			errMsg(err.Error())
		}
		pause()
	}},
	{"Self-test", "Known-answer + crypto checks", func() { runSelfTest(); pause() }},
}

func interactive() {
	for {
		items := make([]menuItem, len(tuiActions))
		for i, a := range tuiActions {
			items[i] = menuItem{key: fmt.Sprintf("%02d", i+1), name: a.name, desc: a.desc, clr: CY + B}
		}
		choice := strings.TrimSpace(menu(TAGLINE, items))
		if choice == "0" || choice == "00" || strings.EqualFold(choice, "q") || strings.EqualFold(choice, "exit") {
			clear()
			banner()
			okMsg("Session closed.")
			return
		}
		if strings.EqualFold(choice, "h") || strings.EqualFold(choice, "help") || choice == "?" {
			tuiHelp()
			continue
		}
		n, err := strconv.Atoi(choice)
		if err != nil || n < 1 || n > len(tuiActions) {
			if choice != "" {
				warnMsg("unknown selection")
				pause()
			}
			continue
		}
		clear()
		banner()
		tuiActions[n-1].run()
	}
}

// ---------------------------------------------------------------------------
// Help & Usage  (interactive menu [H])
// Page 1: in-app guide (what the tool does, every menu option, tips).
// Page 2: the full command-line reference (same text as --help).
// ---------------------------------------------------------------------------

type owlHelpItem struct{ key, text string }

func owlHelpWrap(s string, width int) []string {
	var out []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		cur := ""
		for _, w := range words {
			if cur != "" && len([]rune(cur))+1+len([]rune(w)) > width {
				out = append(out, cur)
				cur = w
			} else if cur == "" {
				cur = w
			} else {
				cur += " " + w
			}
		}
		out = append(out, cur)
	}
	return out
}

func owlHelpTitle(t string) {
	fmt.Println()
	fmt.Println("  " + col("▸ "+t, B+CY))
}

func owlHelpPara(lines []string) {
	for _, l := range lines {
		for _, w := range owlHelpWrap(l, 60) {
			fmt.Println("    " + col(w, W))
		}
	}
}

func owlHelpRows(items []owlHelpItem) {
	kw := 0
	for _, it := range items {
		if n := len([]rune(it.key)); n > kw {
			kw = n
		}
	}
	for _, it := range items {
		k := "[" + it.key + "]" + strings.Repeat(" ", kw-len([]rune(it.key)))
		for i, w := range owlHelpWrap(it.text, 56-kw) {
			if i == 0 {
				fmt.Println("    " + col(k, YLW+B) + "  " + col(w, W))
			} else {
				fmt.Println("    " + strings.Repeat(" ", kw+2) + "  " + col(w, W))
			}
		}
	}
}

func owlHelpRule() { fmt.Println(col(strings.Repeat("─", 66), CY)) }

func tuiHelp() {
	clear()
	banner()
	owlHelpRule()
	fmt.Println("  " + col("⬡  Help & Usage — "+APPNAME, B+CY))
	owlHelpRule()
	owlHelpTitle("WHAT IT DOES")
	owlHelpPara(owlHelpAbout)
	owlHelpTitle("HOW TO USE THE MENU")
	owlHelpPara(owlHelpFlow)
	owlHelpTitle("MENU OPTIONS")
	owlHelpRows(owlHelpMenu)
	owlHelpTitle("TIPS")
	owlHelpRows(owlHelpTips)
	fmt.Println()
	owlHelpRule()
	fmt.Println("  " + col("Next page: command-line flags & copy-paste examples", DIM))
	pause()
	clear()
	owlHelpCLI()
	fmt.Println()
	fmt.Println("  " + col("Tip: the same reference is printed by  "+APPNAME+" --help", DIM))
	pause()
}

var owlHelpAbout = []string{
	"ODNSSEC checks whether a domain's DNSSEC is correct. It walks the chain of trust from the IANA root keys down to the domain: DS records must match DNSKEYs, and every RRSIG signature is verified with real cryptography (RSA, ECDSA P-256/P-384, Ed25519). Expired or not-yet-valid signatures, broken links, weak algorithms and NSEC/NSEC3 problems are reported with a grade.",
	"It works offline on zone files or `dig +dnssec` output, or online by querying a resolver for the whole chain itself.",
}

var owlHelpFlow = []string{
	"Type the number of an option (1 or 01) and press Enter. Use [02] for a live domain or [01] for a file you already have. Options [03] and [08] then work on that last result. [H] opens this help, [0] or q quits.",
}

var owlHelpMenu = []owlHelpItem{
	{"01", "Validate a zone / dig file: enter the file path, the origin for relative names (blank = . root) and, optionally, an extra trust-anchor file for private or lab zones. The chain is checked offline."},
	{"02", "Fetch & validate a domain: enter a domain (e.g. cloudflare.com) and a resolver IP such as 1.1.1.1 (blank = system resolver). Every zone from the root down is queried and validated. Afterwards you can save the records to a file to re-check offline later with [01]."},
	{"03", "Signature details: every RRSIG of the last run, with key tag, algorithm, validity dates and verification result."},
	{"04", "Run synthetic demo: a signed lab hierarchy with deliberate faults, so you can see each kind of error."},
	{"05", "Algorithm catalogue: DNSSEC algorithm numbers and their RFC 8624 status (MUST, RECOMMENDED, NOT RECOMMENDED, MUST NOT)."},
	{"06", "Trust anchors: the built-in IANA root keys (KSK-2017 and KSK-2024)."},
	{"07", "Explain the checks: what a validator verifies at each step, in plain words."},
	{"08", "Export last report: choose txt, md, json, csv or sarif and an output file (blank = print to screen)."},
	{"09", "Self-test: known-answer and cryptographic checks."},
}

var owlHelpTips = []owlHelpItem{
	{"*", "To make a file for [01]:  dig +dnssec +multi DNSKEY example.com > k.txt"},
	{"*", "For incident forensics, use --now TIME on the command line to check whether signatures were valid at a past moment."},
	{"*", "Some networks block or rewrite DNSSEC. If a fetch fails, try another resolver such as 1.1.1.1 or 9.9.9.9."},
}

func owlHelpCLI() { usage() }
