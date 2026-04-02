package constresolver

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
)

// GoParser parses Go source files using go/parser for precise constant extraction.
type GoParser struct{}

// Extensions returns Go file extensions.
func (p *GoParser) Extensions() []string {
	return []string{".go"}
}

// ParseFile extracts integer constants from a Go source file.
// Key format: "packagename.CONST_NAME"
func (p *GoParser) ParseFile(path string, content []byte) (ConstMap, error) {
	result := make(ConstMap)

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, content, 0)
	if err != nil {
		// Return partial results (map may be empty) with the error.
		return result, err
	}

	pkgName := f.Name.Name

	for _, decl := range f.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.CONST {
			continue
		}

		for _, spec := range genDecl.Specs {
			valSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}

			for i, name := range valSpec.Names {
				if i >= len(valSpec.Values) {
					break
				}
				lit, ok := valSpec.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.INT {
					// Skip iota, expressions, and non-integer literals.
					continue
				}
				val64, err := strconv.ParseInt(lit.Value, 0, 64)
				if err != nil {
					continue
				}
				val := int(val64)
				key := pkgName + "." + name.Name
				result[key] = val
			}
		}
	}

	return result, nil
}
