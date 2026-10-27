package main

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
)

// main validates SVG syntax and requires accessible title and description elements.
func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: validate-svg FILE...")
		os.Exit(2)
	}
	for _, path := range os.Args[1:] {
		if err := validate(path); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
			os.Exit(1)
		}
		fmt.Printf("%s: valid accessible SVG\n", path)
	}
}

// validate parses one SVG and checks its root, title, description, and ARIA linkage.
func validate(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := xml.NewDecoder(file)
	rootSeen, titleSeen, descSeen, labelled := false, false, false, false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		if !rootSeen {
			if start.Name.Local != "svg" {
				return fmt.Errorf("root element is %q, expected svg", start.Name.Local)
			}
			rootSeen = true
			for _, attr := range start.Attr {
				if attr.Name.Local == "aria-labelledby" && attr.Value != "" {
					labelled = true
				}
			}
		}
		switch start.Name.Local {
		case "title":
			titleSeen = true
		case "desc":
			descSeen = true
		}
	}
	if !rootSeen || !titleSeen || !descSeen || !labelled {
		return fmt.Errorf("SVG must include title, desc, and aria-labelledby")
	}
	return nil
}
