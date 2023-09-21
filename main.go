/*
Petri displays a tree of all tmux windows, panes, processes, and files.
It prints the tree using Unicode box drawing glyphs, so requires terminal and font support for rendering these.

If query strings are given, petri will attempt to search the data it has collected from tmux panes to filter results.
This feature is experimental and is undocumented until either it can be made stable or is removed.

Usage:

	petri [flags] [query...]

Flags:

	-a, -A
		List info for all files opened by child processes, including those that are normally filtered. (Default: off)
		Files that are normally filtered include executables, files under /usr, /lib, /include, and so on, TTYs, and so on.

	-f, -F
		List normal files opened by child processes. (Default: on)

	-p, -P
		List subprocesses running for each window pane. (Default: on)

When flags are given, a lowercase letter turns on the option given by the flag while a lowercase letter turns it off.
*/
package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/blevesearch/bleve/v2"
	"github.com/blevesearch/bleve/v2/analysis"
	"github.com/blevesearch/bleve/v2/analysis/analyzer/custom"
	"github.com/blevesearch/bleve/v2/analysis/lang/en"
	"github.com/blevesearch/bleve/v2/analysis/token/edgengram"
	"github.com/blevesearch/bleve/v2/analysis/token/lowercase"
	"github.com/blevesearch/bleve/v2/analysis/tokenizer/character"
	_ "github.com/blevesearch/bleve/v2/analysis/tokenizer/whitespace"
	"github.com/blevesearch/bleve/v2/mapping"
	"github.com/blevesearch/bleve/v2/registry"
	"github.com/prometheus/procfs"
	"github.com/segmentio/ksuid"
	"github.com/xlab/treeprint"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

type windowMap map[int]*tmuxWindow

type tmuxWindow struct {
	Index int
	Title string

	id    string // document ID
	panes paneMap
	tree  treeprint.Tree
}

type paneMap map[int]*tmuxPane

type tmuxPane struct {
	Window      int
	WindowTitle string

	Pane  int
	PID   int
	Title string

	branch treeprint.Tree
	pstree treeprint.Tree
	wnd    *tmuxWindow
}

func (t *tmuxPane) PaneDef(parent string) PaneDef {
	return PaneDef{
		Parent:    parent,
		WindowDef: t.WindowDef(),
		Pane:      t.Pane,
		PaneTitle: t.Title,
		RootPID:   t.PID,
	}
}

func (t *tmuxPane) WindowDef() WindowDef {
	return WindowDef{
		Window:     t.Window,
		WindowName: t.WindowTitle,
	}
}

type Document interface {
	Level() int
	Mapping() map[string]any
}

type Indices struct {
	Refs map[string]Document

	Data bleve.Index
}

func NewIndices() (ind *Indices, err error) {
	ind = &Indices{
		Refs: map[string]Document{},
	}

	ws := func(name string) *mapping.FieldMapping {
		fm := bleve.NewTextFieldMapping()
		fm.Name = name
		fm.Analyzer = "ws"
		fm.Store = false
		return fm
	}

	num := func(name string) *mapping.FieldMapping {
		fm := bleve.NewNumericFieldMapping()
		fm.Name = name
		fm.Store = false
		return fm
	}

	root := bleve.NewIndexMapping()

	wndDoc := bleve.NewDocumentMapping()
	paneDoc := bleve.NewDocumentMapping()
	procDoc := bleve.NewDocumentMapping()
	fileDoc := bleve.NewDocumentMapping()

	{
		wndDoc.AddFieldMappingsAt("window", num("window"))
		wndDoc.AddFieldMappingsAt("name", ws("name"))
	}

	{
		paneDoc.AddFieldMappingsAt("pane", num("pane"))
		paneDoc.AddFieldMappingsAt("pid", num("pid"))
		paneDoc.AddFieldMappingsAt("title", ws("title"))
		paneDoc.AddSubDocumentMapping("wnd", wndDoc)
	}

	{
		procDoc.AddFieldMappingsAt("pid", num("pid"))
		procDoc.AddFieldMappingsAt("ppid", num("ppid"))
		cmd := ws("cmd")
		cmd.Analyzer = "cmdline"
		procDoc.AddFieldMappingsAt("cmd", cmd)
		prog := ws("prog")
		cmd.Analyzer = "prog"
		procDoc.AddFieldMappingsAt("prog", prog)
		cwd := ws("dir")
		cwd.Analyzer = "filepath"
		fileDoc.AddFieldMappingsAt("cwd", cwd)
		procDoc.AddSubDocumentMapping("pane", paneDoc)
	}

	{
		file := ws("file")
		file.Analyzer = "filepath"
		dir := ws("dir")
		dir.Analyzer = "filepath"
		fileDoc.AddFieldMappingsAt("file", file)
		fileDoc.AddFieldMappingsAt("base", ws("base"))
		fileDoc.AddFieldMappingsAt("dir", dir)
		fileDoc.AddFieldMappingsAt("ext", ws("ext"))
		fileDoc.AddSubDocumentMapping("proc", procDoc)
	}

	err = root.AddCustomTokenFilter("edgeNgram325",
		map[string]interface{}{
			"type": edgengram.Name,
			"min":  1.0,
			"max":  64.0,
		})
	if err != nil {
		return nil, err
	}

	root.AddCustomAnalyzer("ws", map[string]any{
		"type":      custom.Name,
		"tokenizer": "whitespace",
		"token_filters": []string{
			en.PossessiveName,
			lowercase.Name,
			en.StopName,
			"edgeNgram325",
		},
	})
	if err != nil {
		return nil, err
	}

	err = root.AddCustomAnalyzer("filepath", map[string]any{
		"type":      custom.Name,
		"tokenizer": "filepath",
		"token_filters": []string{
			en.PossessiveName,
			lowercase.Name,
			en.StopName,
			"edgeNgram325",
		},
	})
	if err != nil {
		return nil, err
	}

	err = root.AddCustomAnalyzer("prog", map[string]any{
		"type":      custom.Name,
		"tokenizer": "whitespace",
		"token_filters": []string{
			en.PossessiveName,
			lowercase.Name,
			en.StopName,
			"edgeNgram325",
		},
	})
	if err != nil {
		return nil, err
	}

	err = root.AddCustomAnalyzer("cmdline", map[string]any{
		"type":      custom.Name,
		"tokenizer": "cmdline",
		"token_filters": []string{
			en.PossessiveName,
			lowercase.Name,
			en.StopName,
			"edgeNgram325",
		},
	})
	if err != nil {
		return nil, err
	}

	root.AddDocumentMapping("window", wndDoc)
	root.AddDocumentMapping("pane", paneDoc)
	root.AddDocumentMapping("proc", procDoc)
	root.AddDocumentMapping("file", fileDoc)

	ind.Data, err = bleve.NewMemOnly(root)
	if err != nil {
		return nil, err
	}

	return ind, nil
}

func (ind *Indices) Search(query string) (docs map[string]Document, result *bleve.SearchResult, err error) {
	bq := bleve.NewQueryStringQuery(query)
	req := bleve.NewSearchRequest(bq)
	result, err = ind.Data.Search(req)
	if err != nil {
		return nil, result, err
	}

	docs = map[string]Document{}
	for _, hit := range result.Hits {
		if doc, ok := ind.Refs[hit.ID]; ok {
			docs[hit.ID] = doc
		}
	}
	return docs, result, nil
}

func (ind *Indices) Index(document Document) string {
	id := newID()
	switch document.(type) {
	case WindowDef, PaneDef, ProcDef, FileDef:
		must(ind.Data.Index(id, document.Mapping()))
	default:
		panic(fmt.Errorf("invalid document type %T", document))
	}
	ind.Refs[id] = document
	return id
}

type WindowDef struct {
	Window     int
	WindowName string
}

func (wd WindowDef) Mapping() map[string]any {
	return map[string]any{
		"_type":  "window",
		"window": wd.Window,
		"name":   wd.WindowName,
	}
}

func (wd WindowDef) Value() string {
	return fmt.Sprintf("%d: %s", wd.Window, wd.WindowName)
}

func (WindowDef) Level() int { return 0 }

type PaneDef struct {
	Parent string // Parent of this definition.

	WindowDef

	Pane      int
	PaneTitle string
	RootPID   int
}

func (PaneDef) Level() int { return 1 }

func (pd PaneDef) Mapping() map[string]any {
	return map[string]any{
		"_type":    "pane",
		"pane":     pd.Pane,
		"title":    pd.PaneTitle,
		"pane_pid": pd.RootPID,
		"wnd":      pd.WindowDef.Mapping(),
	}
}

func (pd PaneDef) Value() string {
	return fmt.Sprintf("%d: %s", pd.Pane, pd.PaneTitle)
}

func (pd PaneDef) Proc(pid, ppid int) ProcDef {
	return ProcDef{
		PaneDef: pd,
		PID:     pid,
		PPID:    ppid,
	}
}

type ProcDef struct {
	PaneDef

	PID     int
	PPID    int
	CmdLine []string
	WorkDir string
}

func (ProcDef) Level() int { return 3 }

func (pd ProcDef) Mapping() map[string]any {
	return map[string]any{
		"_type": "proc",
		"pid":   pd.PID,
		"ppid":  pd.PPID,
		"cwd":   pd.WorkDir,
		"prog":  filepath.Base(pd.CmdLine[0]),
		"cmd":   strings.Join(pd.CmdLine, "\x00"),
		"pane":  pd.PaneDef.Mapping(),
	}
}

func (pd ProcDef) Value() string {
	return fmt.Sprintf("(%d) %s", pd.PID, strings.Join(pd.QuotedCmd(), " "))
}

func (pd ProcDef) QuotedCmd() []string {
	cmd := slices.Clone(pd.CmdLine)
	for i, arg := range cmd {
		cmd[i] = quote(arg)
	}
	return cmd
}

func (pd ProcDef) File(name string) FileDef {
	return FileDef{
		ProcDef: pd,
		File:    name,
	}
}

type FileDef struct {
	ProcDef

	File string
}

func (FileDef) Level() int { return 2 }

func (fd FileDef) Mapping() map[string]any {
	ext := filepath.Ext(fd.File)
	base := filepath.Base(fd.File)
	return map[string]any{
		"_type":   "file",
		"file":    fd.File,
		"base":    base,
		"extless": strings.TrimSuffix(base, ext),
		"ext":     strings.TrimPrefix(ext, "."),
		"dir":     filepath.Dir(fd.File),
		"proc":    fd.ProcDef.Mapping(),
	}
}

type procRec struct {
	procfs.Proc

	statOnce sync.Once
	stat     procfs.ProcStat
	statErr  error
}

func (pr *procRec) Stat() (procfs.ProcStat, error) {
	pr.statOnce.Do(func() {
		pr.stat, pr.statErr = pr.Proc.Stat()
	})
	return pr.stat, pr.statErr
}

type procMap map[int]*procRec
type procTable []*procRec

type runeMatch rune

func (r runeMatch) Match(other rune) bool {
	return rune(r) == other
}

type negBool bool

func (v *negBool) String() string {
	return ""
}

func (v *negBool) Set(s string) error {
	b, err := strconv.ParseBool(s)
	if err != nil {
		return err
	}
	*v = negBool(!b)
	return nil
}

func (v *negBool) IsBoolFlag() bool { return true }

func main() {
	indices, err := NewIndices()
	if err != nil {
		panic(err)
	}

	var (
		listFiles    bool = true
		listAllFiles bool
		listProcs    bool = true
	)

	flag.BoolVar(&listFiles, "f", listFiles, "List files opened by child processes.")
	flag.BoolVar(&listProcs, "p", listProcs, "List processes.")
	flag.BoolVar(&listAllFiles, "a", listAllFiles, "List all files opened by child processes.")
	flag.Var((*negBool)(&listFiles), "F", "Do not list files opened by child processes.")
	flag.Var((*negBool)(&listProcs), "P", "Do not print a process tree.")
	flag.Var((*negBool)(&listAllFiles), "A", "Do not print all files. (default)")

	flag.Parse()

	tmux := exec.Command("tmux", "list-panes", "-a", "-F", "#{window_index}\r#{pane_index}\r#{pane_pid}\r#{window_name}\r#{pane_title}")
	tmux.Stderr = os.Stderr
	data, err := tmux.Output()
	if err != nil {
		panic(err)
	}

	queries := flag.Args()

	var procs []*tmuxPane
rowParsing:
	for rowN, row := range bytes.FieldsFunc(data, runeMatch('\n').Match) {
		fs := bytes.SplitN(row, []byte{'\r'}, 5)
		if colN := len(fs); colN != 5 {
			log.Printf("Failed to parse row %d (%q) in tmux output: column count was not three", rowN, colN)
			continue rowParsing
		}

		rec := tmuxPane{
			WindowTitle: string(fs[3]),
			Title:       string(fs[4]),
		}
		for colN, idp := range []*int{&rec.Window, &rec.Pane, &rec.PID} {
			id, err := strconv.ParseInt(string(fs[colN]), 10, strconv.IntSize)
			if err != nil {
				log.Printf("Failed to parse row %d column %d in tmux output: %v", rowN, colN, err)
				continue rowParsing
			}
			*idp = int(id)
		}
		procs = append(procs, &rec)
	}

	slices.SortFunc(procs, func(l, r *tmuxPane) int {
		li, ri := l.PID, r.PID
		if l.Window != r.Window {
			li, ri = l.Window, r.Window
		}
		if l.Pane != r.Pane {
			li, ri = l.Pane, r.Pane
		}
		return max(min(li-ri, 1), -1)
	})

	pfs, err := procfs.NewDefaultFS()
	if err != nil {
		panic(err)
	}

	ptableSrc, err := pfs.AllProcs()
	if err != nil {
		panic(err)
	}

	pmap := procMap{}
	ptable := make(procTable, len(ptableSrc))
	for i, proc := range ptableSrc {
		rec := &procRec{Proc: proc}
		ptable[i] = rec
		pmap[proc.PID] = rec
	}

	windows := windowMap{}
	for _, rec := range procs {
		panes := windows[rec.Window]
		if panes == nil {
			panes = &tmuxWindow{
				Index: rec.Window,
				Title: rec.WindowTitle,
				panes: paneMap{},
				tree:  treeprint.New(),
			}
			wd := rec.WindowDef()
			panes.tree.SetValue(wd.Value())
			panes.id = indices.Index(wd)
			windows[rec.Window] = panes
		}
		panes.panes[rec.Pane] = rec
		rec.wnd = panes
		paneDef := rec.PaneDef(panes.id)

		paneID := indices.Index(paneDef)
		rec.branch = panes.tree.AddBranch(paneDef.Value())
		if proc, ok := pmap[rec.PID]; ok {
			parented := paneDef
			parented.Parent = paneID
			pstree(rec.branch, rec.PID, parented, proc, pfs, ptable, pmap, listProcs, listFiles, listAllFiles, indices)
		}
	}

	if len(queries) == 0 {
		keys := maps.Keys(windows)
		slices.Sort(keys)
		for _, k := range keys {
			fmt.Println(windows[k].tree)
		}
		return
	}

	lt := &lazyTree{
		indices: indices,
	}
	type matchEntry struct {
		ID  string
		Doc Document
	}
	matches := []matchEntry{}
	docs, _, err := indices.Search(strings.Join(queries, " "))
	if err != nil {
		panic(fmt.Errorf("query failed: %w", err))
	}
	for id, doc := range docs {
		matches = append(matches, matchEntry{ID: id, Doc: doc})
	}

	slices.SortFunc(matches, func(l, r matchEntry) int {
		if l.Doc.Level() == r.Doc.Level() {
			return strings.Compare(l.ID, r.ID)
		}
		return max(min(l.Doc.Level()-r.Doc.Level(), 1), -1)
	})
	for _, me := range matches {
		_ = lt.Put(me.ID, me.Doc)
	}

	keys := maps.Keys(lt.windows)
	slices.Sort(keys)
	for _, k := range keys {
		fmt.Println(lt.windows[k])
	}
}

type lazyTree struct {
	indices *Indices
	windows map[int]treeprint.Tree
	trees   map[string]treeprint.Tree
	// Special cases: branches for CHILDREN and FILES nodes.
	pbranches map[string]treeprint.Tree
	fbranches map[string]treeprint.Tree
}

func (l *lazyTree) Put(id string, doc Document) (tree treeprint.Tree) {
	if l.trees == nil {
		l.trees = map[string]treeprint.Tree{}
		l.windows = map[int]treeprint.Tree{}
		l.pbranches = map[string]treeprint.Tree{}
		l.fbranches = map[string]treeprint.Tree{}
	}

	if tree = l.trees[id]; tree != nil {
		return tree
	}

	defer func() {
		l.trees[id] = tree
	}()

	switch doc := doc.(type) {
	case WindowDef:
		tree = treeprint.NewWithRoot(doc.Value())
		l.windows[doc.Window] = tree
		return tree
	case PaneDef:
		parent := l.Put(doc.Parent, l.indices.Refs[doc.Parent])
		return parent.AddBranch(doc.Value())
	case ProcDef:
		parent := l.Put(doc.Parent, l.indices.Refs[doc.Parent])
		return parent.AddBranch(doc.Value())
	case FileDef:
		parent := l.files(doc.Parent)
		return parent.AddNode(doc.File)
	}
	panic(fmt.Errorf("Put: invalid document type %T", doc))
}

func (l *lazyTree) children(parent string) treeprint.Tree {
	switch doc := l.indices.Refs[parent].(type) {
	case ProcDef:
		return l.branch(l.pbranches, parent, "CHILDREN")
	case PaneDef:
		return l.Put(parent, doc)
	default:
		panic(fmt.Errorf("invalid parent to object branch: %T", doc))
	}
}

func (l *lazyTree) files(parent string) treeprint.Tree {
	return l.branch(l.fbranches, parent, "FILES")
}

func (l *lazyTree) branch(mapping map[string]treeprint.Tree, parent, value string) treeprint.Tree {
	node := mapping[parent]
	if node == nil {
		docTree := l.Put(parent, l.indices.Refs[parent])
		node = docTree.AddBranch(value)
		mapping[parent] = node
	}
	return node
}

var invalidFileTargets = regexp.MustCompile(`^$|^[^/][^:]*:|^/dev/(?:pts|tty|null$|random$|urandom$)|/(?:usr|lib|include|bin)(?:/|$)|^/run(?:$|/)`)

func pstree(parent treeprint.Tree, pid int, pane PaneDef, proc *procRec, pfs procfs.FS, ptable procTable, pmap procMap, recurse, listFiles, inclInvalid bool, indices *Indices) {
	cmdline, err := proc.CmdLine()
	if err != nil {
		return
	}

	stat, err := proc.Stat()
	if err != nil {
		return
	}

	procDef := pane.Proc(pid, stat.PPID)
	procDef.CmdLine = slices.Clone(cmdline)
	procDef.WorkDir, _ = proc.Cwd()
	docID := indices.Index(procDef)

	procParent := procDef
	procParent.Parent = docID

	for i, cmd := range cmdline {
		cmdline[i] = quote(cmd)
	}

	pt := parent.AddBranch(procDef.Value())

	if procDef.WorkDir != "" {
		pt.AddMetaBranch("CWD", procDef.WorkDir)
	}

	files := Delay(func() treeprint.Tree {
		return pt.AddBranch("FILES")
	})

	// children := Delay(func() treeprint.Tree {
	// 	return pt.AddBranch("CHILDREN")
	// })

	if listFiles {
		targets, _ := proc.FileDescriptorTargets()
		for _, target := range targets {
			if target != "" && (inclInvalid || !invalidFileTargets.MatchString(target)) {
				fd := procParent.File(target)
				indices.Index(fd)
				files().AddNode(fd.Value())
			}
		}
	}

	if recurse {
		for _, oproc := range ptable {
			stat, err := oproc.Stat()
			if err != nil {
				continue
			}

			if stat.PPID != pid {
				continue
			}

			pstree(pt, oproc.PID, procParent.PaneDef, oproc, pfs, ptable, pmap, recurse, listFiles, inclInvalid, indices)
		}
	}
}

var unsafeChars = regexp.MustCompile(`[^-a-zA-Z0-9\./._,@+=]`)

// quote formats the string, s, for use in shells by quoting it in single
// quotes. Any single quotes in the string are then double-quoted to preserve
// them.
func quote(s string) string {
	firstUnsafe := unsafeChars.FindStringIndex(s)
	if firstUnsafe == nil {
		return s
	}
	prefix, suffix := "", s
	if i := strings.IndexByte(s, '='); strings.HasPrefix(s, "-") && i < firstUnsafe[0] {
		prefix, suffix = suffix[:i+1], suffix[i+1:]
	}
	suffix = `'` + strings.ReplaceAll(suffix, `'`, `'"'"'`) + `'`
	return prefix + suffix
}

// ComputeFunc represents a computation that returns a single value.
type ComputeFunc[T any] func() T

// ForceFunc represents a delayed computation that returns a single value. After
// the first call of a forceFunc, any subsequent call should return the same
// value without re-running the computation.
type ForceFunc[T any] func() T

// Delay implements a delayed computation with a single result. Given a compute
// function, Delay will return a function wrapping it that runs it once, stores
// the result of the computation, and always returns the result of that
// computation on subsequent calls.
//
// This is modeled after promises in Scheme, but without the need to use
// a separate force function to get the result.
func Delay[T any](compute ComputeFunc[T]) ForceFunc[T] {
	var t T
	var once sync.Once
	return func() T {
		once.Do(func() {
			t = compute()
		})
		return t
	}
}

func newID() string {
	return ksuid.New().String()
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func init() {
	registry.RegisterTokenizer("cmdline", func(config map[string]any, cache *registry.Cache) (analysis.Tokenizer, error) {
		return character.NewCharacterTokenizer(func(r rune) bool {
			return r != 0
		}), nil
	})

	registry.RegisterTokenizer("filepath", func(config map[string]any, cache *registry.Cache) (analysis.Tokenizer, error) {
		return character.NewCharacterTokenizer(func(r rune) bool {
			return r != filepath.Separator
		}), nil
	})
}
