package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/fatih/structs"
	"github.com/malice-plugins/pkgs/database"
	"github.com/malice-plugins/pkgs/database/elasticsearch"
	"github.com/malice-plugins/pkgs/utils"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

const (
	name     = "rizin"
	category = "exe"

	// rzbinPath is the rizin v0.9.0 `rz-bin` CLI baked into the image. It is the
	// prebuilt STATIC Linux x86-64 binary from the rizin v0.9.0 release (no
	// runtime shared-library dependencies), so it runs on a minimal alpine base.
	rzbinPath = "/usr/local/bin/rz-bin"

	// malwareDir is where the malice core stages the sample: /malware/<sha256>.
	malwareDir = "/malware"

	// Array caps keep the ES document compact for large binaries (a Go binary
	// can carry tens of thousands of symbols and thousands of strings).
	maxSections = 500
	maxImports  = 1000
	maxExports  = 1000
	maxSymbols  = 1000
	maxStrings  = 1000
)

var (
	// Version stores the plugin's version
	Version string
	// BuildTime stores the plugin's build time
	BuildTime string
	// es is the elasticsearch database object
	es elasticsearch.Database
)

// resultsData is the shape the rizin engine writes to plugins.exe.rizin.
//
// rizin is a NEW engine (there is no classic malice/rizin or radare2 plugin to
// preserve), so this shape follows the `exe`-category convention established by
// diec/floss: a top-level found/status pair, a curated subset of the rz-bin
// JSON (info, headers, sections, imports, exports, symbols, strings, libs,
// entries), and a human-readable markdown summary.
type resultsData struct {
	// Found reports whether rz-bin recognized a known binary format.
	Found bool `json:"found" structs:"found"`
	// Status is "ok" when the scan ran, "error" on rz-bin/parse failure, or
	// "skipped" when the sample is not staged.
	Status string `json:"status" structs:"status"`
	// Error carries a short failure description (only on status "error").
	Error string `json:"error,omitempty" structs:"error"`
	// Info is the binary metadata from `rz-bin -I` (class, arch, bits, compiler,
	// and the security properties pie/nx/relrocs/canary/stripped). Nil when the
	// input is not a recognized binary.
	Info *rzInfo `json:"info,omitempty" structs:"info"`
	// Headers are the file-header fields from `rz-bin -H` (ELF/PE/Mach-O header).
	Headers []rzHeader `json:"headers,omitempty" structs:"headers"`
	// Sections are the sections from `rz-bin -S` (capped at maxSections).
	Sections []rzSection `json:"sections,omitempty" structs:"sections"`
	// Imports are the imported symbols from `rz-bin -i` (capped at maxImports).
	Imports []rzImport `json:"imports,omitempty" structs:"imports"`
	// Exports are the exported symbols from `rz-bin -E` (capped at maxExports).
	Exports []rzExport `json:"exports,omitempty" structs:"exports"`
	// Symbols are the object symbols from `rz-bin -s` (capped at maxSymbols).
	Symbols []rzSymbol `json:"symbols,omitempty" structs:"symbols"`
	// Strings are the extracted strings from `rz-bin -z` (capped at maxStrings).
	Strings []rzString `json:"strings,omitempty" structs:"strings"`
	// Libs are the linked libraries from `rz-bin -l`.
	Libs []string `json:"libs,omitempty" structs:"libs"`
	// Entries are the entry points from `rz-bin -e`.
	Entries []rzEntry `json:"entries,omitempty" structs:"entries"`
	// MarkDown is the human-readable summary rendered by the malice UI.
	MarkDown string `json:"markdown,omitempty" structs:"markdown"`
}

// rzInfo is the curated binary metadata (a subset of `rz-bin -I`). The security
// booleans are always emitted (no omitempty) because a FALSE value is itself a
// finding (e.g. pie:false, nx:false).
type rzInfo struct {
	Class    string `json:"class" structs:"class"`
	Bintype  string `json:"bintype" structs:"bintype"`
	Arch     string `json:"arch" structs:"arch"`
	Machine  string `json:"machine" structs:"machine"`
	Bits     int    `json:"bits" structs:"bits"`
	Endian   string `json:"endian" structs:"endian"`
	Os       string `json:"os" structs:"os"`
	Subsys   string `json:"subsys" structs:"subsys"`
	Lang     string `json:"lang" structs:"lang"`
	Compiler string `json:"compiler" structs:"compiler"`
	Intrp    string `json:"intrp" structs:"intrp"`
	Rpath    string `json:"rpath" structs:"rpath"`
	Relro    string `json:"relro" structs:"relro"`
	Stripped bool   `json:"stripped" structs:"stripped"`
	Pie      bool   `json:"pie" structs:"pie"`
	Nx       bool   `json:"nx" structs:"nx"`
	Relrocs  bool   `json:"relrocs" structs:"relrocs"`
	Canary   bool   `json:"canary" structs:"canary"`
	Static   bool   `json:"static" structs:"static"`
	Havecode bool   `json:"havecode" structs:"havecode"`
}

// rzHeader is one file-header field from `rz-bin -H` (fields[]).
type rzHeader struct {
	Name    string `json:"name" structs:"name"`
	Comment string `json:"comment,omitempty" structs:"comment,omitempty"`
	Vaddr   uint64 `json:"vaddr,omitempty" structs:"vaddr,omitempty"`
	Paddr   uint64 `json:"paddr,omitempty" structs:"paddr,omitempty"`
}

// rzSection is one section from `rz-bin -S` (sections[]).
type rzSection struct {
	Name  string `json:"name" structs:"name"`
	Size  int    `json:"size" structs:"size"`
	Vsize int    `json:"vsize" structs:"vsize"`
	Perm  string `json:"perm" structs:"perm"`
	Type  string `json:"type" structs:"type"`
	Vaddr uint64 `json:"vaddr" structs:"vaddr"`
	Paddr uint64 `json:"paddr" structs:"paddr"`
}

// rzImport is one imported symbol from `rz-bin -i` (imports[]).
type rzImport struct {
	Name    string `json:"name" structs:"name"`
	Bind    string `json:"bind,omitempty" structs:"bind,omitempty"`
	Type    string `json:"type,omitempty" structs:"type,omitempty"`
	Ordinal int    `json:"ordinal,omitempty" structs:"ordinal,omitempty"`
}

// rzExport is one exported symbol from `rz-bin -E` (exports[]).
type rzExport struct {
	Name    string `json:"name" structs:"name"`
	Type    string `json:"type,omitempty" structs:"type,omitempty"`
	Bind    string `json:"bind,omitempty" structs:"bind,omitempty"`
	Ordinal int    `json:"ordinal,omitempty" structs:"ordinal,omitempty"`
	Vaddr   uint64 `json:"vaddr,omitempty" structs:"vaddr,omitempty"`
}

// rzSymbol is one object symbol from `rz-bin -s` (symbols[]).
type rzSymbol struct {
	Name    string `json:"name" structs:"name"`
	Type    string `json:"type,omitempty" structs:"type,omitempty"`
	Bind    string `json:"bind,omitempty" structs:"bind,omitempty"`
	Vaddr   uint64 `json:"vaddr,omitempty" structs:"vaddr,omitempty"`
}

// rzString is one extracted string from `rz-bin -z` (strings[]).
type rzString struct {
	String  string `json:"string" structs:"string"`
	Section string `json:"section,omitempty" structs:"section,omitempty"`
	Type    string `json:"type,omitempty" structs:"type,omitempty"`
	Vaddr   uint64 `json:"vaddr,omitempty" structs:"vaddr,omitempty"`
}

// rzEntry is one entry point from `rz-bin -e` (entries[]).
type rzEntry struct {
	Type  string `json:"type" structs:"type"`
	Vaddr uint64 `json:"vaddr" structs:"vaddr"`
	Paddr uint64 `json:"paddr,omitempty" structs:"paddr,omitempty"`
}

// rizin wraps resultsData; the markdown template references .Results.*
type rizin struct {
	Results resultsData `json:"rizin,omitempty" structs:"rizin,omitempty"`
}

// ---- rz-bin v0.9.0 `-j` schema (merged single invocation) ----
//
// A single combined invocation is used (rz-bin merges all requested sections
// into one JSON object, and it is far faster than one process per flag):
//
//	rz-bin -I -S -H -i -E -s -l -e -z -j <file>
//
// producing a single object with keys: info, sections, fields, imports,
// exports, symbols, strings, libs, entries.
//
// Address fields (vaddr/paddr) are uint64: rz-bin emits the sentinel
// 18446744073709551615 (0xFFFFFFFFFFFFFFFF) for the NULL section, which
// overflows a Go int and would otherwise abort the whole json.Unmarshal.

type rzbinDoc struct {
	Info     rzbinInfo      `json:"info" structs:"info"`
	Fields   []rzbinField   `json:"fields" structs:"fields"`
	Sections []rzbinSection `json:"sections" structs:"sections"`
	Imports  []rzbinImport  `json:"imports" structs:"imports"`
	Exports  []rzbinExport  `json:"exports" structs:"exports"`
	Symbols  []rzbinSymbol  `json:"symbols" structs:"symbols"`
	Strings  []rzbinString  `json:"strings" structs:"strings"`
	Libs     []string       `json:"libs" structs:"libs"`
	Entries  []rzbinEntry   `json:"entries" structs:"entries"`
}

type rzbinInfo struct {
	Arch     string `json:"arch" structs:"arch"`
	Bintype  string `json:"bintype" structs:"bintype"`
	Bits     int    `json:"bits" structs:"bits"`
	Class    string `json:"class" structs:"class"`
	Compiler string `json:"compiler" structs:"compiler"`
	Endian   string `json:"endian" structs:"endian"`
	Intrp    string `json:"intrp" structs:"intrp"`
	Lang     string `json:"lang" structs:"lang"`
	Machine  string `json:"machine" structs:"machine"`
	Os       string `json:"os" structs:"os"`
	Relro    string `json:"relro" structs:"relro"`
	Rpath    string `json:"rpath" structs:"rpath"`
	Subsys   string `json:"subsys" structs:"subsys"`
	Stripped bool   `json:"stripped" structs:"stripped"`
	Havecode bool   `json:"havecode" structs:"havecode"`
	Static   bool   `json:"static" structs:"static"`
	Canary   bool   `json:"canary" structs:"canary"`
	Pie      bool   `json:"pie" structs:"pie"`
	Relrocs  bool   `json:"relrocs" structs:"relrocs"`
	Nx       bool   `json:"nx" structs:"nx"`
}

type rzbinField struct {
	Name    string `json:"name" structs:"name"`
	Vaddr   uint64 `json:"vaddr" structs:"vaddr"`
	Paddr   uint64 `json:"paddr" structs:"paddr"`
	Comment string `json:"comment" structs:"comment"`
}

type rzbinSection struct {
	Name  string `json:"name" structs:"name"`
	Size  int    `json:"size" structs:"size"`
	Vsize int    `json:"vsize" structs:"vsize"`
	Perm  string `json:"perm" structs:"perm"`
	Type  string `json:"type" structs:"type"`
	Vaddr uint64 `json:"vaddr" structs:"vaddr"`
	Paddr uint64 `json:"paddr" structs:"paddr"`
}

type rzbinImport struct {
	Name    string `json:"name" structs:"name"`
	Bind    string `json:"bind" structs:"bind"`
	Type    string `json:"type" structs:"type"`
	Ordinal int    `json:"ordinal" structs:"ordinal"`
}

type rzbinExport struct {
	Name    string `json:"name" structs:"name"`
	Type    string `json:"type" structs:"type"`
	Bind    string `json:"bind" structs:"bind"`
	Ordinal int    `json:"ordinal" structs:"ordinal"`
	Vaddr   uint64 `json:"vaddr" structs:"vaddr"`
}

type rzbinSymbol struct {
	Name    string `json:"name" structs:"name"`
	Type    string `json:"type" structs:"type"`
	Bind    string `json:"bind" structs:"bind"`
	Vaddr   uint64 `json:"vaddr" structs:"vaddr"`
}

type rzbinString struct {
	String  string `json:"string" structs:"string"`
	Section string `json:"section" structs:"section"`
	Type    string `json:"type" structs:"type"`
	Vaddr   uint64 `json:"vaddr" structs:"vaddr"`
}

type rzbinEntry struct {
	Type  string `json:"type" structs:"type"`
	Vaddr uint64 `json:"vaddr" structs:"vaddr"`
	Paddr uint64 `json:"paddr" structs:"paddr"`
}

func assert(err error) {
	if err != nil {
		log.WithFields(log.Fields{
			"plugin":   name,
			"category": category,
		}).Fatal(err)
	}
}

// runRzBin executes the rz-bin CLI with the given args and returns its stdout.
//
// rz-bin emits a large volume of deprecation/analysis WARNINGs on stderr while
// the JSON payload goes to stdout, so the streams are captured separately and
// only stdout is parsed. rz-bin exits 0 even for inputs it cannot fully parse
// (it returns empty/partial data), so a non-zero exit is treated as a hard
// failure but callers still inspect stdout.
// addrSentinel is the 0xFFFFFFFFFFFFFFFF value rz-bin emits for an address it
// does not have (e.g. a file-only ELF section with no virtual address, or the
// leading NULL section). It overflows an int64, so it must be normalized
// before being stored in Elasticsearch (whose long type is a signed int64).
const addrSentinel = ^uint64(0)

// normAddr maps rz-bin's "no address" sentinel to 0 (the conventional
// representation of a missing address) so the value fits in an ES long.
func normAddr(a uint64) uint64 {
	if a == addrSentinel {
		return 0
	}
	return a
}

func runRzBin(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, rzbinPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), errors.Wrapf(err, "rz-bin %s: %s", strings.Join(args, " "), strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// scanFile runs rz-bin against path and returns the curated results.
//
// A single combined invocation extracts every requested section at once. On a
// total failure (no parseable JSON) the engine returns a found=false doc with
// an error status so the scan doc is still written.
func scanFile(ctx context.Context, path string) resultsData {
	out, err := runRzBin(ctx, "-I", "-S", "-H", "-i", "-E", "-s", "-l", "-e", "-z", "-j", path)

	results := resultsData{Status: "ok"}

	// Total failure: rz-bin produced no output at all.
	if strings.TrimSpace(out) == "" {
		results.Found = false
		results.Status = "error"
		if err != nil {
			results.Error = err.Error()
		} else {
			results.Error = "rz-bin produced no output"
		}
		return results
	}

	var doc rzbinDoc
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		results.Found = false
		results.Status = "error"
		results.Error = "failed to parse rz-bin JSON: " + err.Error()
		return results
	}

	// A binary format is "recognized" when rz-bin reports a class or bintype
	// (e.g. class "ELF64", bintype "elf"). Non-binary input yields neither, so
	// found stays false but the scan is still a successful (ok) run.
	recognized := doc.Info.Class != "" || doc.Info.Bintype != ""
	results.Found = recognized

	if recognized {
		results.Info = &rzInfo{
			Class:    doc.Info.Class,
			Bintype:  doc.Info.Bintype,
			Arch:     doc.Info.Arch,
			Machine:  doc.Info.Machine,
			Bits:     doc.Info.Bits,
			Endian:   doc.Info.Endian,
			Os:       doc.Info.Os,
			Subsys:   doc.Info.Subsys,
			Lang:     doc.Info.Lang,
			Compiler: doc.Info.Compiler,
			Intrp:    doc.Info.Intrp,
			Rpath:    doc.Info.Rpath,
			Relro:    doc.Info.Relro,
			Stripped: doc.Info.Stripped,
			Pie:      doc.Info.Pie,
			Nx:       doc.Info.Nx,
			Relrocs:  doc.Info.Relrocs,
			Canary:   doc.Info.Canary,
			Static:   doc.Info.Static,
			Havecode: doc.Info.Havecode,
		}
	}

	// headers (rz-bin -H fields)
	for _, f := range doc.Fields {
		if f.Name == "" {
			continue
		}
		results.Headers = append(results.Headers, rzHeader{
			Name: f.Name, Comment: f.Comment, Vaddr: normAddr(f.Vaddr), Paddr: normAddr(f.Paddr),
		})
	}

	// sections (rz-bin -S), skipping the leading NULL placeholder section
	for _, s := range doc.Sections {
		if s.Name == "" || s.Type == "NULL" {
			continue
		}
		results.Sections = append(results.Sections, rzSection{
			Name: s.Name, Size: s.Size, Vsize: s.Vsize, Perm: s.Perm, Type: s.Type, Vaddr: normAddr(s.Vaddr), Paddr: normAddr(s.Paddr),
		})
		if len(results.Sections) >= maxSections {
			break
		}
	}

	// imports (rz-bin -i)
	for _, i := range doc.Imports {
		if i.Name == "" {
			continue
		}
		results.Imports = append(results.Imports, rzImport{
			Name: i.Name, Bind: i.Bind, Type: i.Type, Ordinal: i.Ordinal,
		})
		if len(results.Imports) >= maxImports {
			break
		}
	}

	// exports (rz-bin -E)
	for _, e := range doc.Exports {
		if e.Name == "" {
			continue
		}
		results.Exports = append(results.Exports, rzExport{
			Name: e.Name, Type: e.Type, Bind: e.Bind, Ordinal: e.Ordinal, Vaddr: normAddr(e.Vaddr),
		})
		if len(results.Exports) >= maxExports {
			break
		}
	}

	// symbols (rz-bin -s)
	for _, s := range doc.Symbols {
		if s.Name == "" {
			continue
		}
		results.Symbols = append(results.Symbols, rzSymbol{
			Name: s.Name, Type: s.Type, Bind: s.Bind, Vaddr: normAddr(s.Vaddr),
		})
		if len(results.Symbols) >= maxSymbols {
			break
		}
	}

	// strings (rz-bin -z)
	for _, s := range doc.Strings {
		if s.String == "" {
			continue
		}
		results.Strings = append(results.Strings, rzString{
			String: s.String, Section: s.Section, Type: s.Type, Vaddr: normAddr(s.Vaddr),
		})
		if len(results.Strings) >= maxStrings {
			break
		}
	}

	// linked libraries (rz-bin -l)
	results.Libs = doc.Libs

	// entry points (rz-bin -e)
	for _, e := range doc.Entries {
		results.Entries = append(results.Entries, rzEntry{
			Type: e.Type, Vaddr: normAddr(e.Vaddr), Paddr: normAddr(e.Paddr),
		})
	}

	return results
}

func generateMarkDownTable(d rizin) string {
	var tplOut bytes.Buffer

	t := template.Must(template.New("rizin").Parse(tpl))

	if err := t.Execute(&tplOut, d); err != nil {
		log.Println("executing template:", err)
	}

	return tplOut.String()
}

func main() {

	cli.AppHelpTemplate = utils.AppHelpTemplate
	app := cli.NewApp()

	app.Name = "rizin"
	app.Author = "rufftruffles"
	app.Email = "https://github.com/malice-plugins"
	app.Version = Version + ", BuildTime: " + BuildTime
	app.Compiled, _ = time.Parse("20060102", BuildTime)
	app.Usage = "Malice rizin Plugin (rz-bin binary analysis: headers, sections, imports, exports, symbols, strings)"
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "verbose, V",
			Usage: "verbose output",
		},
		cli.StringFlag{
			Name:        "elasticsearch",
			Value:       "",
			Usage:       "elasticsearch url for Malice to store results",
			EnvVar:      "MALICE_ELASTICSEARCH_URL",
			Destination: &es.URL,
		},
		cli.BoolFlag{
			Name:  "table, t",
			Usage: "output as Markdown table",
		},
		cli.IntFlag{
			Name:   "timeout",
			Value:  120,
			Usage:  "malice plugin timeout (in seconds)",
			EnvVar: "MALICE_TIMEOUT",
		},
	}
	app.ArgsUsage = "SHA256 of the file to scan (staged at /malware/<sha256>)"
	app.Action = func(c *cli.Context) error {

		if c.Bool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		if !c.Args().Present() {
			return errors.New("please supply a sha256 to scan with rizin")
		}

		// The core passes the sample sha256 as the first positional arg; resolve
		// it against the WORKDIR (/malware) where the sample is staged.
		sha := c.Args().First()
		path, err := filepath.Abs(sha)
		if err != nil {
			// Cannot resolve the path; still write a doc so the scan is recorded.
			return storeResults(c, resultsData{Found: false, Status: "error", Error: "failed to get path from args: " + err.Error()}, "")
		}

		exists := true
		if _, err := os.Stat(path); os.IsNotExist(err) {
			exists = false
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.Int("timeout"))*time.Second)
		defer cancel()

		var results resultsData
		if !exists {
			results = resultsData{Found: false, Status: "skipped", Error: fmt.Sprintf("sample not found at %s", path)}
		} else {
			results = scanFile(ctx, path)
		}

		return storeResults(c, results, path)
	}

	err := app.Run(os.Args)
	assert(err)
}

// storeResults renders the markdown, writes the results to Elasticsearch (when
// a URL is configured), and prints the result (markdown with -t, JSON
// otherwise). It always writes the doc — even for found=false / error /
// skipped results — so a scan is never left unwritten.
func storeResults(c *cli.Context, results resultsData, path string) error {
	d := rizin{Results: results}
	d.Results.MarkDown = generateMarkDownTable(d)

	// Compute the doc id LAZILY. MALICE_SCANID is always set by the malice core;
	// the sha256 fallback is only valid when the file exists. utils.GetSHA256
	// log.Fatals on a missing file, so it must never be evaluated eagerly as a
	// function argument (the bug the LMD engine hit) — only call it when the
	// sample is actually present.
	id := os.Getenv("MALICE_SCANID")
	if id == "" {
		if _, serr := os.Stat(path); serr == nil {
			id = utils.GetSHA256(path)
		}
	}

	if len(c.String("elasticsearch")) > 0 {
		if err := es.Init(); err != nil {
			return errors.Wrap(err, "failed to initialize elasticsearch")
		}
		if err := es.StorePluginResults(database.PluginResults{
			ID:       id,
			Name:     name,
			Category: category,
			Data:     structs.Map(d.Results),
		}); err != nil {
			return errors.Wrapf(err, "failed to index malice/%s results", name)
		}
	}

	if c.Bool("table") {
		fmt.Println(d.Results.MarkDown)
	} else {
		d.Results.MarkDown = ""
		out, err := json.Marshal(d)
		if err != nil {
			return errors.Wrap(err, "failed to marshal JSON")
		}
		fmt.Println(string(out))
	}
	return nil
}
