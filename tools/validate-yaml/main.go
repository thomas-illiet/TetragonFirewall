package main

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// main validates one or more multi-document Kubernetes YAML files.
func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: validate-yaml FILE...")
		os.Exit(2)
	}
	for _, path := range os.Args[1:] {
		data, err := os.ReadFile(path)
		if err != nil {
			fail(path, err)
		}
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		documents := 0
		for {
			var value map[string]any
			err := decoder.Decode(&value)
			if err == io.EOF {
				break
			}
			if err != nil {
				fail(path, err)
			}
			if len(value) == 0 {
				continue
			}
			documents++
			if value["apiVersion"] == nil || value["kind"] == nil {
				fail(path, fmt.Errorf("document %d is missing apiVersion or kind", documents))
			}
		}
		if documents == 0 {
			fail(path, fmt.Errorf("contains no Kubernetes resources"))
		}
		fmt.Printf("%s: %d Kubernetes resource(s)\n", path, documents)
	}
}

// fail prints a path-scoped validation error and terminates the command.
func fail(path string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
	os.Exit(1)
}
