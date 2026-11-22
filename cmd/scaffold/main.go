// Command scaffold generates a new org-scoped entity in every layer of the app, in the same
// shape as projects: migration (RLS, audit, version, privileges), queries, proto service,
// handler, constraint mappings, access matrix rows and calls, a page with DataTable and
// create/edit dialogs, and an E2E spec with axe. The output is plain code the project owns;
// nothing here runs at runtime. Usage (make scaffold):
//
//	go run ./cmd/scaffold -name invoice -fields "title:text amount:int due:date paid:bool"
//
// Shared files are edited at "scaffold: ... above this line" markers. It refuses, before
// writing anything, when the entity (or any part of it) exists already or a marker is missing.
package main

import (
	"bytes"
	"embed"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"io/fs"
	"os"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"text/template"
)

//go:embed templates
var templateFS embed.FS

func main() {
	name := flag.String("name", "", "entity name, singular snake_case (invoice, purchase_order)")
	fields := flag.String("fields", "", `fields as name:type, type one of text, int, date, bool; the first is a text label ("title:text amount:int")`)
	plural := flag.String("plural", "", "plural snake_case when adding s/es/ies is wrong")
	flag.Parse()
	e, err := parse(*name, *plural, *fields)
	if err == nil {
		err = scaffold(".", e)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "scaffold:", err)
		os.Exit(1)
	}
	fmt.Printf(`Scaffolded %[1]s (table app.%[1]s, privileges %[2]s.read and %[2]s.write).
Next:
  make generate check   # code from proto and SQL, then every test
  make migrate e2e      # dev database and the browser tests
Review the new rows in docs/access-matrix.md with the business owner, then edit the code freely.
`, e.Plural, e.Name)
}

// Field types: few on purpose. Each maps to one column type, one proto type and one input.
var fieldTypes = []string{"text", "int", "date", "bool"}

var identPattern = regexp.MustCompile(`^[a-z]+(_[a-z]+)*$`) // no digits: Go, sqlc and TS name them alike

// Names that would clash with SQL, the generated code or the columns every entity has.
var reserved = map[string]bool{}

func init() {
	for _, w := range strings.Fields(`
		all analyse analyze and any array as asc asymmetric authorization between bigint binary bit boolean both
		case cast char character check coalesce collate collation column concurrently constraint create cross
		current_catalog current_date current_role current_schema current_time current_timestamp current_user
		date dec decimal default deferrable desc distinct do else end except exists extract false fetch float
		for foreign freeze from full grant greatest group grouping having ilike in initially inner inout int
		integer intersect interval into is isnull join lateral leading least left like limit localtime
		localtimestamp national natural nchar none not notnull null nullif numeric offset on only or order out
		outer overlaps overlay placing position precision primary real references returning right row select
		session_user setof similar smallint some substring symmetric system_user table tablesample text then
		time timestamp to trailing treat trim true union unique user using values varchar variadic verbose
		when where window with
		break chan const continue defer fallthrough func go goto if import interface map package range return
		struct switch type var class delete enum export extends function let new super this throw try typeof
		void while yield await constructor prototype to_string to_json value_of has_own_property
		id org org_id org_name organization version created_at page_size page_token next_page_token query
		app access auth authz api db store server test privilege privileges role roles user users session
		sessions audit audit_log project projects who_am_i
		form update create open errors list columns call calls row rows label`) {
		reserved[w] = true
	}
}

type entity struct {
	Module    string // Go module path, from go.mod
	Name      string // singular snake_case
	Plural    string // plural snake_case: table, list field
	Fields    []field
	Migration string // number of the new migration, e.g. 00007
}

type field struct {
	Name string // snake_case: column, proto field, request field in errors
	Type string // text, int, date, bool
}

func parse(name, plural, fields string) (entity, error) {
	var errs []error
	check := func(what, ident string) {
		switch {
		case !identPattern.MatchString(ident):
			errs = append(errs, fmt.Errorf("%s %q: lower-case letters in snake_case only (e.g. purchase_order)", what, ident))
		case len(ident) > 30:
			errs = append(errs, fmt.Errorf("%s %q: at most 30 characters (Postgres names constraints after it)", what, ident))
		case reserved[ident]:
			errs = append(errs, fmt.Errorf("%s %q is reserved (SQL, Go, TypeScript or an existing name)", what, ident))
		}
	}
	check("NAME", name)
	if plural == "" {
		plural = pluralize(name)
	}
	check("PLURAL", plural)
	if plural == name {
		errs = append(errs, fmt.Errorf("PLURAL must differ from NAME %q", name))
	}

	e := entity{Name: name, Plural: plural}
	seen := map[string]bool{}
	for _, spec := range strings.FieldsFunc(fields, func(r rune) bool { return r == ' ' || r == ',' || r == '\n' || r == '\t' }) {
		n, t, ok := strings.Cut(spec, ":")
		if !ok || !slices.Contains(fieldTypes, t) {
			errs = append(errs, fmt.Errorf("field %q: want name:type with type one of %s", spec, strings.Join(fieldTypes, ", ")))
			continue
		}
		check("field", n)
		if n == name || n == plural || seen[n] {
			errs = append(errs, fmt.Errorf("field %q: duplicate or same as the entity", n))
		}
		seen[n] = true
		e.Fields = append(e.Fields, field{n, t})
	}
	switch {
	case len(e.Fields) == 0:
		errs = append(errs, errors.New(`FIELDS: at least one, e.g. FIELDS="title:text"`))
	case e.Fields[0].Type != "text":
		errs = append(errs, errors.New("FIELDS: the first field is the label (shown, filtered, unique per org) and must be text"))
	case len(e.Fields) > 20:
		errs = append(errs, errors.New("FIELDS: at most 20; add more by hand later"))
	}
	return e, errors.Join(errs...)
}

func pluralize(s string) string {
	switch {
	case strings.HasSuffix(s, "y") && !strings.ContainsAny(s[len(s)-2:len(s)-1], "aeiou"):
		return s[:len(s)-1] + "ies"
	case strings.HasSuffix(s, "s"), strings.HasSuffix(s, "x"), strings.HasSuffix(s, "z"),
		strings.HasSuffix(s, "ch"), strings.HasSuffix(s, "sh"):
		return s + "es"
	}
	return s + "s"
}

// Names derived for each language.

func pascal(s string) string {
	var b strings.Builder
	for part := range strings.SplitSeq(s, "_") {
		b.WriteString(strings.ToUpper(part[:1]) + part[1:])
	}
	return b.String()
}

func camel(s string) string { p := pascal(s); return strings.ToLower(p[:1]) + p[1:] }

func (e entity) Pascal() string       { return pascal(e.Name) }   // Invoice
func (e entity) PluralPascal() string { return pascal(e.Plural) } // Invoices
func (e entity) Camel() string        { return camel(e.Name) }    // invoice
func (e entity) PluralCamel() string  { return camel(e.Plural) }  // invoices
func (e entity) Kebab() string        { return strings.ReplaceAll(e.Plural, "_", "-") }
func (e entity) Human() string        { return strings.ReplaceAll(e.Name, "_", " ") }   // purchase order
func (e entity) HumanPlural() string  { return strings.ReplaceAll(e.Plural, "_", " ") } // purchase orders
func (e entity) Title() string        { h := e.HumanPlural(); return strings.ToUpper(h[:1]) + h[1:] }
func (e entity) Label() field         { return e.Fields[0] }

// A is the article for the singular: "an invoice", "a project".
func (e entity) A() string {
	if strings.ContainsAny(e.Name[:1], "aeiou") {
		return "an"
	}
	return "a"
}

func (e entity) CapA() string { return strings.ToUpper(e.A()[:1]) + e.A()[1:] }

func (e entity) HasType(t string) bool {
	return slices.ContainsFunc(e.Fields, func(f field) bool { return f.Type == t })
}

func (f field) ProtoGo() string { return pascal(f.Name) } // protoc-gen-go: due_on -> DueOn
func (f field) Camel() string   { return camel(f.Name) }  // protobuf-es: due_on -> dueOn
func (f field) Human() string   { h := strings.ReplaceAll(f.Name, "_", " "); return strings.ToUpper(h[:1]) + h[1:] }

// SQLC is sqlc's Go name: like protoc-gen-go, but an "id" part is "ID" (external_id -> ExternalID).
func (f field) SQLC() string {
	var b strings.Builder
	for part := range strings.SplitSeq(f.Name, "_") {
		if part == "id" {
			b.WriteString("ID")
		} else {
			b.WriteString(pascal(part))
		}
	}
	return b.String()
}

// Shared files and the marker line each snippet goes above. Every marker must exist exactly once.
type insertion struct{ path, marker, snippet string }

var insertions = []insertion{
	{"internal/api/api.go", "// scaffold: services above this line", "mount"},
	{"internal/api/constraints.go", "// scaffold: constraint fields above this line", "constraint_fields"},
	{"internal/api/constraints.go", "// scaffold: constraints not user-facing above this line", "constraints_internal"},
	{"internal/api/matrix_test.go", "-- scaffold: seed rows above this line", "matrix_seed"},
	{"internal/api/matrix_test.go", "// scaffold: calls above this line", "matrix_calls"},
	{"frontend/src/lib/api.ts", "// scaffold: service imports above this line", "api_import"},
	{"frontend/src/lib/api.ts", "// scaffold: clients above this line", "api_client"},
	{"frontend/src/App.tsx", "// scaffold: page imports above this line", "app_import"},
	{"frontend/src/App.tsx", "// scaffold: pages above this line", "app_page"},
}

// scaffold writes the entity into the repository at root. Nothing is written unless every
// check passes and every output renders (and, for Go, formats).
func scaffold(dir string, e entity) error {
	root, err := os.OpenRoot(dir) // every path below stays inside the repository
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	read := func(rel string) (string, error) {
		b, err := root.ReadFile(rel)
		return string(b), err
	}
	gomod, err := read("go.mod")
	if err != nil {
		return err
	}
	modLine, _, _ := strings.Cut(gomod, "\n")
	e.Module = strings.TrimSpace(strings.TrimPrefix(modLine, "module"))

	// The entity exists when a whole word of these appears where the scaffold would put it.
	taken := regexp.MustCompile(`\b(app\.` + e.Plural + `|` + e.Name + `\.read|` + e.Pascal() + `Service|` +
		e.PluralPascal() + `Page|` + e.Plural + `_pkey|List` + e.PluralPascal() + `)\b`)
	var existing []string
	mentions := func(path, text string) {
		if m := taken.FindString(text); m != "" {
			existing = append(existing, path+" mentions "+m)
		}
	}

	migrations, err := fs.Glob(root.FS(), "internal/store/migrations/*.sql")
	if err != nil {
		return err
	}
	last := 0
	for _, m := range migrations {
		n, _ := strconv.Atoi(strings.SplitN(path.Base(m), "_", 2)[0])
		last = max(last, n)
		body, err := read(m)
		if err != nil {
			return err
		}
		mentions(m, body)
	}
	e.Migration = fmt.Sprintf("%05d", last+1)

	tmpl, err := template.New("").Funcs(template.FuncMap{"add": func(a, b int) int { return a + b }}).
		ParseFS(templateFS, "templates/*")
	if err != nil {
		return err
	}
	render := func(name string) (string, error) {
		var b bytes.Buffer
		if err := tmpl.ExecuteTemplate(&b, name, e); err != nil {
			return "", err
		}
		return b.String(), nil
	}

	out := map[string]string{} // path -> new content
	newFiles := map[string]string{
		"internal/store/migrations/" + e.Migration + "_" + e.Plural + ".sql": "migration.sql.tmpl",
		"proto/app/v1/" + e.Name + ".proto":                                  "service.proto.tmpl",
		"internal/api/" + e.Plural + ".go":                                   "handler.go.tmpl",
		"internal/api/" + e.Plural + "_test.go":                              "handler_test.go.tmpl",
		"frontend/src/components/" + e.Kebab() + "-page.tsx":                "page.tsx.tmpl",
		"frontend/e2e/" + e.Kebab() + ".spec.ts":                             "e2e.spec.ts.tmpl",
	}
	for p, name := range newFiles {
		if _, err := root.Stat(p); err == nil {
			existing = append(existing, p+" exists")
		}
		if out[p], err = render(name); err != nil {
			return err
		}
	}

	// Appended to the end of a file, or after the last row of the access matrix.
	appends := []struct{ path, snippet string }{
		{"internal/store/queries.sql", "queries"},
		{"dev/e2e-clean.sql", "e2e_clean"},
		{"docs/access-matrix.md", "matrix_rows"},
	}
	for _, a := range appends {
		text, err := read(a.path)
		if err != nil {
			return err
		}
		mentions(a.path, text)
		snippet, err := render(a.snippet)
		if err != nil {
			return err
		}
		if a.path == "docs/access-matrix.md" {
			text, err = afterMatrixRows(text, snippet)
			if err != nil {
				return err
			}
		} else {
			text = strings.TrimRight(text, "\n") + "\n" + snippet
		}
		out[a.path] = text
	}

	var problems []string
	for _, in := range insertions {
		text, ok := out[in.path]
		if !ok {
			if text, err = read(in.path); err != nil {
				return err
			}
		}
		if !ok {
			mentions(in.path, text)
		}
		if n := strings.Count(text, in.marker); n != 1 {
			problems = append(problems, fmt.Sprintf("%s: marker %q found %d times, want 1 (restore it, or add the %s part by hand)", in.path, in.marker, n, e.Name))
			continue
		}
		snippet, err := render(in.snippet)
		if err != nil {
			return err
		}
		i := strings.Index(text, in.marker)
		lineStart := strings.LastIndex(text[:i], "\n") + 1
		out[in.path] = text[:lineStart] + snippet + text[lineStart:]
	}
	if len(existing) > 0 {
		slices.Sort(existing)
		existing = slices.Compact(existing)
		return fmt.Errorf("%s exists already, nothing written:\n  %s\nEdit the existing code instead, or remove it first", e.Name, strings.Join(existing, "\n  "))
	}
	if len(problems) > 0 {
		return fmt.Errorf("nothing written:\n  %s", strings.Join(problems, "\n  "))
	}

	paths := make([]string, 0, len(out))
	for p, text := range out {
		if strings.HasSuffix(p, ".go") {
			b, err := format.Source([]byte(text))
			if err != nil {
				return fmt.Errorf("%s: generated Go does not parse (template bug): %w", p, err)
			}
			out[p] = string(b)
		}
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		if err := root.MkdirAll(path.Dir(p), 0o750); err != nil {
			return err
		}
		if err := root.WriteFile(p, []byte(out[p]), 0o600); err != nil {
			return err
		}
		fmt.Println("wrote", p)
	}
	return nil
}

// afterMatrixRows inserts rows after the last row of the table whose header starts with
// "| Action" (the table matrix_test.go reads), and checks the personas are the ones the rows know.
func afterMatrixRows(text, rows string) (string, error) {
	const header = "| Action | anonymous | nobody | viewerAcme | editorAcme | adminAcme | editorGlobex |"
	i := strings.Index(text, header)
	if i < 0 {
		return "", fmt.Errorf("docs/access-matrix.md: no table with header %q; add the rows by hand:\n%s", header, rows)
	}
	end := i
	for {
		next := strings.IndexByte(text[end:], '\n')
		if next < 0 {
			end = len(text)
			break
		}
		lineEnd := end + next + 1
		if !strings.HasPrefix(text[lineEnd:], "|") {
			end = lineEnd
			break
		}
		end = lineEnd
	}
	return text[:end] + rows + text[end:], nil
}
