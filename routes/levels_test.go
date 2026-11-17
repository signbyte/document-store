package routes

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/gmb-lib/go-authbyte/permissions"
	"github.com/go-quicktest/qt"
)

// The document the service declares to a membership register is exactly its key,
// its display name, the four levels of the documents group and no permission.
func TestDeclaredDocumentIsTheServiceKeyAndItsFourLevels(t *testing.T) {
	sets := Declared()
	qt.Assert(t, qt.HasLen(sets, 1))

	raw, err := permissions.Declaration(sets...)
	qt.Assert(t, qt.IsNil(err))

	var doc struct {
		Services []struct {
			Key         string `json:"key"`
			DisplayName string `json:"displayName"`
			Roles       []struct {
				Group       string `json:"group"`
				Level       string `json:"level"`
				Description string `json:"description"`
			} `json:"roles"`
			Permissions []json.RawMessage `json:"permissions"`
		} `json:"services"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(raw, &doc)))
	qt.Assert(t, qt.HasLen(doc.Services, 1))

	svc := doc.Services[0]
	qt.Check(t, qt.Equals(svc.Key, "document-store"))
	qt.Check(t, qt.Equals(svc.DisplayName, "Document storage"))
	qt.Check(t, qt.HasLen(svc.Permissions, 0))
	qt.Check(t, qt.IsNotNil(svc.Permissions), qt.Commentf("an empty list is declared, not an absent one"))

	var got []string
	for _, r := range svc.Roles {
		qt.Check(t, qt.Not(qt.Equals(r.Description, "")), qt.Commentf("level %s has no description", r.Level))
		got = append(got, r.Group+":"+r.Level)
	}
	sort.Strings(got)
	qt.Check(t, qt.DeepEquals(got, []string{
		"documents:durable", "documents:grant", "documents:read", "documents:write",
	}))
}

// The scope group and level names a route checks are the same constants the
// declaration is made of: every level a route names is declared, and every level
// declared is named by some route. The test reads the package's source, so a route
// that names a level with a literal, or a level declared that no route checks,
// fails it.
func TestRoutesCheckExactlyTheDeclaredLevels(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	qt.Assert(t, qt.IsNil(err))

	var files []*ast.File
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, 0)
		qt.Assert(t, qt.IsNil(err))
		files = append(files, f)
	}

	// The value of each string constant of the package.
	values := map[string]string{}
	for _, f := range files {
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, s := range gd.Specs {
				vs := s.(*ast.ValueSpec)
				for i, n := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						v, err := strconv.Unquote(lit.Value)
						qt.Assert(t, qt.IsNil(err))
						values[n.Name] = v
					}
				}
			}
		}
	}

	checked := map[string]bool{}
	calls := 0
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "requireScope" || len(call.Args) != 2 {
				return true
			}
			calls++
			id, ok := call.Args[1].(*ast.Ident)
			if !ok {
				t.Errorf("%s: requireScope names its level with something other than a constant", fset.Position(call.Pos()))

				return true
			}
			v, ok := values[id.Name]
			if !ok {
				t.Errorf("%s: %s is not a string constant of the package", fset.Position(call.Pos()), id.Name)

				return true
			}
			checked[ScopeGroup+":"+v] = true

			return true
		})
	}
	qt.Assert(t, qt.IsTrue(calls > 0), qt.Commentf("no requireScope call found: the test reads nothing"))

	declaredLevels := map[string]bool{}
	for _, r := range Declared()[0].Levels() {
		declaredLevels[r.Group+":"+r.Level] = true
	}

	for l := range checked {
		qt.Check(t, qt.IsTrue(declaredLevels[l]), qt.Commentf("%s is checked by a route but not declared", l))
	}
	for l := range declaredLevels {
		qt.Check(t, qt.IsTrue(checked[l]), qt.Commentf("%s is declared but no route checks it", l))
	}
}

// The routes start as before when a membership register is configured but
// cannot be reached: the declaration is made in the background.
func TestRoutesStartWithAnUnreachableMembershipRegister(t *testing.T) {
	t.Setenv("MEMBERSHIP_URL", "http://127.0.0.1:1")
	t.Setenv("MEMBERSHIP_AUDIENCE", "register-audience")
	t.Setenv("SERVICE_CLIENT_SECRET", "a-secret")
	t.Setenv("AUDIT_ISSUER_URL", "http://127.0.0.1:1")

	app := testApp(t)
	app.Start(t)
	app.Stop()
}

// What the register takes: a level description of at most 256 characters, at most
// 50 levels for a key, and a document of at most 256 KB.
func TestDeclaredDocumentStaysWithinTheRegistersLimits(t *testing.T) {
	const (
		maxDescription = 256
		maxLevels      = 50
		maxDocument    = 262144
	)

	for _, set := range Declared() {
		levels := set.Levels()
		qt.Check(t, qt.IsTrue(len(levels) <= maxLevels), qt.Commentf("%d levels", len(levels)))
		for _, r := range levels {
			qt.Check(t, qt.IsTrue(len(r.Description) <= maxDescription),
				qt.Commentf("the description of %s:%s is %d characters", r.Group, r.Level, len(r.Description)))
		}
	}

	raw, err := permissions.Declaration(Declared()...)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(len(raw) <= maxDocument), qt.Commentf("the document is %d bytes", len(raw)))
}
