// Command validate-comments ensures every Go function declaration has documentation.
package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

// main validates the requested Go source trees and reports every missing comment.
func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: validate-comments <path>...")
		os.Exit(2)
	}
	failed := false
	for _, root := range os.Args[1:] {
		if err := validateTree(root); err != nil {
			fmt.Fprintln(os.Stderr, err)
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
}

// validateTree walks one source tree and validates each non-generated Go file.
func validateTree(root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != root && strings.HasPrefix(entry.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		return validateFile(path)
	})
}

// validateFile reports undocumented function declarations in one Go source file.
func validateFile(path string) error {
	source, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if bytes.Contains(source, []byte("Code generated")) {
		return nil
	}

	files := token.NewFileSet()
	file, err := parser.ParseFile(files, path, source, parser.ParseComments)
	if err != nil {
		return err
	}
	missing := make([]string, 0)
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Doc == nil {
			position := files.Position(function.Pos())
			missing = append(missing, fmt.Sprintf("%s:%d: function %s has no documentation", path, position.Line, function.Name.Name))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%s", strings.Join(missing, "\n"))
	}
	return nil
}
