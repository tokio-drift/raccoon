//go:build ignore

// package_module_proxy.go builds a local file-based Go module proxy
// for github.com/tokio-drift/raccoon at a specified version tag.
package main

import (
	"archive/zip"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	tagFlag := flag.String("tag", "v0.1.0", "Module version tag (e.g. v0.1.0)")
	outFlag := flag.String("out", "", "Output directory for the proxy")
	rootFlag := flag.String("root", ".", "Root directory of the raccoon repository")
	flag.Parse()

	if *outFlag == "" {
		fmt.Fprintln(os.Stderr, "error: -out is required")
		os.Exit(1)
	}

	modulePath := "github.com/tokio-drift/raccoon"
	vDir := filepath.Join(*outFlag, filepath.FromSlash(modulePath), "@v")
	if err := os.MkdirAll(vDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "error creating proxy dir: %v\n", err)
		os.Exit(1)
	}

	// 1. Write @v/list
	if err := os.WriteFile(filepath.Join(vDir, "list"), []byte(*tagFlag+"\n"), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error writing list: %v\n", err)
		os.Exit(1)
	}

	// 2. Write @v/<tag>.info
	now := time.Now().UTC().Format(time.RFC3339)
	infoContent := fmt.Sprintf(`{"Version":"%s","Time":"%s"}`+"\n", *tagFlag, now)
	if err := os.WriteFile(filepath.Join(vDir, *tagFlag+".info"), []byte(infoContent), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error writing info: %v\n", err)
		os.Exit(1)
	}

	// 3. Write @v/<tag>.mod
	goModBytes, err := os.ReadFile(filepath.Join(*rootFlag, "go.mod"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading go.mod: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(filepath.Join(vDir, *tagFlag+".mod"), goModBytes, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error writing mod: %v\n", err)
		os.Exit(1)
	}

	// 4. Create @v/<tag>.zip
	zipPath := filepath.Join(vDir, *tagFlag+".zip")
	zipFile, err := os.Create(zipPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating zip file: %v\n", err)
		os.Exit(1)
	}
	defer zipFile.Close()

	zw := zip.NewWriter(zipFile)
	prefix := fmt.Sprintf("%s@%s/", modulePath, *tagFlag)

	err = filepath.Walk(*rootFlag, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(*rootFlag, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}

		// Skip VCS, build artifacts, test cases
		if rel == ".git" || strings.HasPrefix(rel, ".git/") ||
			rel == "bin" || strings.HasPrefix(rel, "bin/") ||
			rel == "node_modules" || strings.HasPrefix(rel, "node_modules/") ||
			rel == ".raccoon" || strings.HasPrefix(rel, ".raccoon/") ||
			strings.HasSuffix(rel, ".test") {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if info.IsDir() {
			return nil
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = prefix + rel
		header.Method = zip.Deflate

		w, err := zw.CreateHeader(header)
		if err != nil {
			return err
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		_, err = io.Copy(w, f)
		return err
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error packaging module zip: %v\n", err)
		os.Exit(1)
	}

	if err := zw.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "error closing zip writer: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Module %s@%s successfully packaged to %s\n", modulePath, *tagFlag, vDir)
}
