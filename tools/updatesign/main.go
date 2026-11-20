// Command updatesign makes the signed archive and manifest that mygo.Updater
// installs.
//
// `mygo build` signs an archive of what it built, which is not what is
// shipped here: the macOS bundle gets its compatibility layer afterwards, as
// a dylib and a launcher, and an update that replaced the bundle with the
// unsigned one would leave macOS 11 unable to start the app. This tool builds
// the archive from the bundle as it is released instead, and signs it with
// the key installed apps check.
//
// The signing key comes from MYGO_UPDATER_PRIVATE_KEY or -key, as mygo keygen
// writes it. Publish the archive and the manifest as assets of the release
// the manifest's URLs name.
package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// manifest is the JSON that mygo reads as internal/update.Manifest. It is
// repeated here because that package is internal to MyGo.
type manifest struct {
	Version   string `json:"version"`
	Notes     string `json:"notes,omitempty"`
	Date      string `json:"date,omitempty"`
	URL       string `json:"url"`
	Size      int64  `json:"size"`
	Signature string `json:"signature"`
}

type options struct {
	version string
	target  string
	app     string
	exe     string
	name    string
	repo    string
	tag     string
	notes   string
	key     string
	out     string
}

func main() {
	var o options
	flag.StringVar(&o.version, "version", "", "version of the release, without a leading v")
	flag.StringVar(&o.target, "target", "", "build target, such as darwin-universal or windows-amd64")
	flag.StringVar(&o.app, "app", "", "the .app bundle to ship (macOS)")
	flag.StringVar(&o.exe, "exe", "", "the executable to ship (Windows)")
	flag.StringVar(&o.name, "name", "", "name of the executable inside the archive (default: its own)")
	flag.StringVar(&o.repo, "repo", "howmp/sshkeygate", "GitHub repository, as owner/name")
	flag.StringVar(&o.tag, "tag", "", "release tag (default v<version>)")
	flag.StringVar(&o.notes, "notes", "", "Markdown file with the release notes")
	flag.StringVar(&o.key, "key", "", "file holding the private key (default: $MYGO_UPDATER_PRIVATE_KEY)")
	flag.StringVar(&o.out, "out", filepath.Join("dist", "updates"), "directory to write the files to")
	flag.Parse()

	if err := run(o); err != nil {
		fmt.Fprintln(os.Stderr, "updatesign:", err)
		os.Exit(1)
	}
}

func run(o options) error {
	switch {
	case o.version == "":
		return errors.New("-version is required")
	case o.target == "":
		return errors.New("-target is required")
	case (o.app == "") == (o.exe == ""):
		return errors.New("give exactly one of -app and -exe")
	}
	if o.tag == "" {
		o.tag = "v" + o.version
	}
	key, err := signingKey(o.key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(o.out, 0o755); err != nil {
		return err
	}

	archiveName := fmt.Sprintf("sshkeygate-%s-%s.tar.gz", o.version, o.target)
	archivePath := filepath.Join(o.out, archiveName)
	size, digest, err := writeArchive(archivePath, o)
	if err != nil {
		return err
	}

	m := manifest{
		Version: o.version,
		Notes:   notes(o.notes),
		Date:    time.Now().UTC().Format(time.RFC3339),
		URL: "https://github.com/" + o.repo + "/releases/download/" +
			o.tag + "/" + archiveName,
		Size:      size,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, digest)),
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	name := "update-" + o.target + ".json"
	if err := os.WriteFile(filepath.Join(o.out, name), append(data, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("signed %s (%d bytes) and %s\n", archiveName, size, name)
	return nil
}

// signingKey reads the private key the way mygo keygen writes it: base64 of
// the 64-byte Ed25519 key.
func signingKey(path string) (ed25519.PrivateKey, error) {
	text := os.Getenv("MYGO_UPDATER_PRIVATE_KEY")
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		text = string(b)
	}
	if strings.TrimSpace(text) == "" {
		return nil, errors.New("no signing key: set MYGO_UPDATER_PRIVATE_KEY or pass -key")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
	if err != nil {
		return nil, fmt.Errorf("the signing key is not base64: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("the signing key is %d bytes, not %d", len(raw), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(raw), nil
}

// writeArchive writes the archive of what is shipped and returns its size and
// SHA-256 digest, which the signature covers.
//
// On macOS the archive holds the bundle as one entry, which the updater
// expects to find exactly one of; on Windows it holds the executable alone,
// named as the running one so that it replaces it.
func writeArchive(dst string, o options) (int64, []byte, error) {
	f, err := os.Create(dst)
	if err != nil {
		return 0, nil, err
	}
	sum := sha256.New()
	count := &countingWriter{}
	gz, err := gzip.NewWriterLevel(io.MultiWriter(f, sum, count), gzip.BestCompression)
	if err != nil {
		f.Close()
		return 0, nil, err
	}
	tw := tar.NewWriter(gz)

	if o.app != "" {
		// Walk the bundle itself and name it: the updater wants the archive
		// to hold the bundle as its one entry, at the top level.
		err = addTree(tw, o.app, filepath.Base(o.app))
	} else {
		err = addFile(tw, o.exe, executableName(o))
	}
	if err == nil {
		err = tw.Close()
	} else {
		tw.Close()
	}
	if cerr := gz.Close(); err == nil {
		err = cerr
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(dst)
		return 0, nil, err
	}
	return count.n, sum.Sum(nil), nil
}

// executableName is the name the executable takes inside the archive: the
// one it runs under, so that the update replaces it.
func executableName(o options) string {
	if o.name != "" {
		return o.name
	}
	name := filepath.Base(o.exe)
	if name == "" || name == "." {
		return "sshkeygate.exe"
	}
	return name
}

// addTree adds dir as entry name, with everything it holds.
func addTree(tw *tar.Writer, dir, name string) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		link := ""
		if info.Mode()&fs.ModeSymlink != 0 {
			if link, err = os.Readlink(p); err != nil {
				return err
			}
		}
		hdr, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return err
		}
		hdr.Name = path.Join(name, filepath.ToSlash(rel))
		if d.IsDir() {
			hdr.Name += "/"
		}
		hdr.Uid, hdr.Gid, hdr.Uname, hdr.Gname = 0, 0, "", ""
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		return copyFile(tw, p)
	})
}

// addFile adds the single file src as entry name.
func addFile(tw *tar.Writer, src, name string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	hdr, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	hdr.Name = name
	hdr.Uid, hdr.Gid, hdr.Uname, hdr.Gname = 0, 0, "", ""
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	return copyFile(tw, src)
}

func copyFile(w io.Writer, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(w, f)
	return err
}

// notes returns the release notes, or an empty string when there is no file.
func notes(path string) string {
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// countingWriter counts the bytes written through it, which the closing of
// the gzip and tar writers completes.
type countingWriter struct{ n int64 }

func (c *countingWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}
