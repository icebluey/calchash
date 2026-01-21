package calchash_test

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf16"

	whirlpoolhash "github.com/jzelinskie/whirlpool"
	"lukechampine.com/blake3"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
)

var testBin string

const (
	exitMismatch = 1
	exitTrouble  = 2
)

var digestNames = []string{
	"blake2b512",
	"blake2s256",
	"blake3",
	"md4",
	"md5",
	"md5-sha1",
	"ripemd",
	"ripemd160",
	"rmd160",
	"sha1",
	"sha224",
	"sha256",
	"sha384",
	"sha512",
	"sha512-224",
	"sha512-256",
	"sha3-224",
	"sha3-256",
	"sha3-384",
	"sha3-512",
	"whirlpool",
}

func TestMain(m *testing.M) {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "getwd failed: %v\n", err)
		os.Exit(1)
	}
	root := filepath.Dir(wd)
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		root = wd
	}
	tmpDir, err := os.MkdirTemp("", "calchash-testbin-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "tempdir failed: %v\n", err)
		os.Exit(1)
	}
	bin := filepath.Join(tmpDir, "calchash")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags", "-s -w", "-o", bin, ".")
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n%s", err, stderr.String())
		_ = os.RemoveAll(tmpDir)
		os.Exit(1)
	}
	testBin = bin
	if _, err := os.Stat(testBin); err != nil {
		fmt.Fprintf(os.Stderr, "binary not found: %v\n", err)
		_ = os.RemoveAll(tmpDir)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(tmpDir)
	os.Exit(code)
}

type cmdResult struct {
	stdout   string
	stderr   string
	exitCode int
}

func runCmd(t *testing.T, dir, input string, args ...string) cmdResult {
	t.Helper()
	cmd := exec.Command(testBin, args...)
	cmd.Dir = dir
	cmd.Env = os.Environ()
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	exitCode := 0
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			t.Fatalf("run failed: %v", err)
		}
	}
	return cmdResult{
		stdout:   outBuf.String(),
		stderr:   errBuf.String(),
		exitCode: exitCode,
	}
}

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func encodeUTF16LE(s string, withBOM bool) []byte {
	u16 := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(u16)*2+2)
	if withBOM {
		out = append(out, 0xFF, 0xFE)
	}
	for _, v := range u16 {
		out = append(out, byte(v), byte(v>>8))
	}
	return out
}

func sumHash(h hash.Hash, data []byte) []byte {
	_, _ = h.Write(data)
	return h.Sum(nil)
}

func digestBytes(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	switch name {
	case "blake2b512":
		h, err := blake2b.New512(nil)
		if err != nil {
			t.Fatalf("blake2b512: %v", err)
		}
		return sumHash(h, data)
	case "blake2s256":
		h, err := blake2s.New256(nil)
		if err != nil {
			t.Fatalf("blake2s256: %v", err)
		}
		return sumHash(h, data)
	case "blake3":
		h := blake3.New(32, nil)
		return sumHash(h, data)
	case "md4":
		return sumHash(md4.New(), data)
	case "md5":
		sum := md5.Sum(data)
		return sum[:]
	case "md5-sha1":
		md5Sum := md5.Sum(data)
		sha1Sum := sha1.Sum(data)
		out := make([]byte, 0, len(md5Sum)+len(sha1Sum))
		out = append(out, md5Sum[:]...)
		out = append(out, sha1Sum[:]...)
		return out
	case "ripemd", "ripemd160", "rmd160":
		return sumHash(ripemd160.New(), data)
	case "sha1":
		sum := sha1.Sum(data)
		return sum[:]
	case "sha224":
		return sumHash(sha256.New224(), data)
	case "sha256":
		sum := sha256.Sum256(data)
		return sum[:]
	case "sha384":
		return sumHash(sha512.New384(), data)
	case "sha512":
		sum := sha512.Sum512(data)
		return sum[:]
	case "sha512-224":
		return sumHash(sha512.New512_224(), data)
	case "sha512-256":
		return sumHash(sha512.New512_256(), data)
	case "sha3-224":
		return sumHash(sha3.New224(), data)
	case "sha3-256":
		return sumHash(sha3.New256(), data)
	case "sha3-384":
		return sumHash(sha3.New384(), data)
	case "sha3-512":
		return sumHash(sha3.New512(), data)
	case "whirlpool":
		return sumHash(whirlpoolhash.New(), data)
	default:
		t.Fatalf("missing digest mapping for %s", name)
		return nil
	}
}

func TestListDigestsIncludesAll(t *testing.T) {
	dir := t.TempDir()
	res := runCmd(t, dir, "", "-l")
	if res.exitCode != 0 {
		t.Fatalf("exit %d: %s", res.exitCode, res.stderr)
	}
	out := res.stdout
	for _, name := range digestNames {
		flag := "-" + name
		if !strings.Contains(out, flag) {
			t.Fatalf("list missing %q", flag)
		}
	}
}

func TestCLIAllDigests(t *testing.T) {
	dir := t.TempDir()
	data := []byte("all digests\n")
	writeFile(t, dir, "sample.txt", data)
	for _, name := range digestNames {
		name := name
		t.Run(name, func(t *testing.T) {
			expected := digestBytes(t, name, data)
			expectedHex := hex.EncodeToString(expected)
			res := runCmd(t, dir, "", "-"+name, "sample.txt")
			if res.exitCode != 0 {
				t.Fatalf("exit %d: %s", res.exitCode, res.stderr)
			}
			if res.stderr != "" {
				t.Fatalf("unexpected stderr: %q", res.stderr)
			}
			want := fmt.Sprintf("%s  sample.txt\n", expectedHex)
			if res.stdout != want {
				t.Fatalf("stdout mismatch: %q != %q", res.stdout, want)
			}
		})
	}
}

func TestCLIEscapedFilenameOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("filename escaping with backslashes is not portable on Windows")
	}
	dir := t.TempDir()
	name := "a\nb\\c"
	data := []byte("hello\n")
	writeFile(t, dir, name, data)
	sumHex := sha256Hex(data)
	res := runCmd(t, dir, "", "-sha256", name)
	if res.exitCode != 0 {
		t.Fatalf("exit %d: %s", res.exitCode, res.stderr)
	}
	wantPrefix := fmt.Sprintf("%s  ", sumHex)
	if !strings.HasPrefix(res.stdout, wantPrefix) {
		t.Fatalf("unexpected output prefix: %q", res.stdout)
	}
	if !strings.Contains(res.stdout, "\\n") || !strings.Contains(res.stdout, "\\\\") {
		t.Fatalf("expected escaped sequences, got %q", res.stdout)
	}
}

func TestCLICheckBSD(t *testing.T) {
	dir := t.TempDir()
	data := []byte("hello\n")
	writeFile(t, dir, "sample.txt", data)
	sumHex := sha256Hex(data)
	list := fmt.Sprintf("SHA256 (sample.txt) = %s\n", sumHex)
	writeFile(t, dir, "checksums.txt", []byte(list))
	res := runCmd(t, dir, "", "-sha256", "-c", "checksums.txt")
	if res.exitCode != 0 {
		t.Fatalf("exit %d: %s", res.exitCode, res.stderr)
	}
	if res.stdout != "sample.txt: OK\n" {
		t.Fatalf("unexpected stdout: %q", res.stdout)
	}
}

func TestCLICheckUTF8BOM(t *testing.T) {
	dir := t.TempDir()
	data := []byte("hello\n")
	writeFile(t, dir, "sample.txt", data)
	sumHex := sha256Hex(data)
	list := fmt.Sprintf("%s  sample.txt\n", sumHex)
	dataWithBOM := append([]byte{0xEF, 0xBB, 0xBF}, []byte(list)...)
	writeFile(t, dir, "checksums-bom.txt", dataWithBOM)
	res := runCmd(t, dir, "", "-sha256", "-c", "checksums-bom.txt")
	if res.exitCode != 0 {
		t.Fatalf("exit %d: %s", res.exitCode, res.stderr)
	}
	if res.stdout != "sample.txt: OK\n" {
		t.Fatalf("unexpected stdout: %q", res.stdout)
	}
}

func TestCLIComputeSHA256(t *testing.T) {
	dir := t.TempDir()
	data := []byte("hello\n")
	writeFile(t, dir, "sample.txt", data)
	sumHex := sha256Hex(data)
	res := runCmd(t, dir, "", "-sha256", "sample.txt")
	if res.exitCode != 0 {
		t.Fatalf("exit %d: %s", res.exitCode, res.stderr)
	}
	want := fmt.Sprintf("%s  sample.txt\n", sumHex)
	if res.stdout != want {
		t.Fatalf("stdout mismatch: %q != %q", res.stdout, want)
	}
}

func TestCLITagOutput(t *testing.T) {
	dir := t.TempDir()
	data := []byte("hello\n")
	writeFile(t, dir, "sample.txt", data)
	sumHex := sha256Hex(data)
	res := runCmd(t, dir, "", "-sha256", "--tag", "sample.txt")
	want := fmt.Sprintf("SHA256 (sample.txt) = %s\n", sumHex)
	if res.stdout != want {
		t.Fatalf("stdout mismatch: %q != %q", res.stdout, want)
	}
}

func TestCLIBinaryMarker(t *testing.T) {
	dir := t.TempDir()
	data := []byte("hello\n")
	writeFile(t, dir, "sample.txt", data)
	sumHex := sha256Hex(data)
	res := runCmd(t, dir, "", "-sha256", "-b", "sample.txt")
	want := fmt.Sprintf("%s *sample.txt\n", sumHex)
	if res.stdout != want {
		t.Fatalf("stdout mismatch: %q != %q", res.stdout, want)
	}
}

func TestCLIZeroOutput(t *testing.T) {
	dir := t.TempDir()
	data := []byte("hello\n")
	writeFile(t, dir, "sample.txt", data)
	sumHex := sha256Hex(data)
	res := runCmd(t, dir, "", "-sha256", "-z", "sample.txt")
	want := fmt.Sprintf("%s  sample.txt\x00", sumHex)
	if res.stdout != want {
		t.Fatalf("stdout mismatch: %q != %q", res.stdout, want)
	}
}

func TestCLICheckOK(t *testing.T) {
	dir := t.TempDir()
	data := []byte("hello\n")
	writeFile(t, dir, "sample.txt", data)
	sumHex := sha256Hex(data)
	list := fmt.Sprintf("%s  sample.txt\n", sumHex)
	writeFile(t, dir, "checksums.txt", []byte(list))
	res := runCmd(t, dir, "", "-sha256", "-c", "checksums.txt")
	if res.exitCode != 0 {
		t.Fatalf("exit %d: %s", res.exitCode, res.stderr)
	}
	if res.stdout != "sample.txt: OK\n" {
		t.Fatalf("unexpected stdout: %q", res.stdout)
	}
}

func TestCLICheckUTF16LE(t *testing.T) {
	dir := t.TempDir()
	data := []byte("hello\n")
	writeFile(t, dir, "sample.txt", data)
	sumHex := sha256Hex(data)
	line := fmt.Sprintf("%s  sample.txt\n", sumHex)
	for _, tc := range []struct {
		name    string
		withBOM bool
	}{
		{"bom", true},
		{"no_bom", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded := encodeUTF16LE(line, tc.withBOM)
			writeFile(t, dir, "checksums-utf16le.txt", encoded)
			res := runCmd(t, dir, "", "-sha256", "-c", "checksums-utf16le.txt")
			if res.exitCode != 0 {
				t.Fatalf("exit %d: %s", res.exitCode, res.stderr)
			}
			if res.stdout != "sample.txt: OK\n" {
				t.Fatalf("unexpected stdout: %q", res.stdout)
			}
		})
	}
}

func TestCLICheckFail(t *testing.T) {
	dir := t.TempDir()
	data := []byte("hello\n")
	writeFile(t, dir, "sample.txt", data)
	sumHex := sha256Hex(data)
	bad := sumHex[:len(sumHex)-1]
	if sumHex[len(sumHex)-1] != '0' {
		bad += "0"
	} else {
		bad += "1"
	}
	list := fmt.Sprintf("%s  sample.txt\n", bad)
	writeFile(t, dir, "checksums.txt", []byte(list))
	res := runCmd(t, dir, "", "-sha256", "-c", "checksums.txt")
	if res.exitCode != 1 {
		t.Fatalf("expected exit 1, got %d", res.exitCode)
	}
	if !strings.Contains(res.stdout, "sample.txt: FAILED") {
		t.Fatalf("unexpected stdout: %q", res.stdout)
	}
}

func TestCLICheckIgnoreMissing(t *testing.T) {
	dir := t.TempDir()
	list := fmt.Sprintf("%s  missing.txt\n", strings.Repeat("0", 64))
	writeFile(t, dir, "checksums.txt", []byte(list))
	res := runCmd(t, dir, "", "-sha256", "--ignore-missing", "-c", "checksums.txt")
	if res.exitCode != 0 {
		t.Fatalf("exit %d: %s", res.exitCode, res.stderr)
	}
	if res.stdout != "" {
		t.Fatalf("expected no output, got %q", res.stdout)
	}
}

func TestCLIAppendOutput(t *testing.T) {
	dir := t.TempDir()
	data := []byte("hello\n")
	writeFile(t, dir, "sample.txt", data)
	sumHex := sha256Hex(data)
	outPath := writeFile(t, dir, "out.txt", []byte("header\n"))
	res := runCmd(t, dir, "", "-sha256", "-o", outPath, "-a", "sample.txt")
	if res.exitCode != 0 {
		t.Fatalf("exit %d: %s", res.exitCode, res.stderr)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	want := fmt.Sprintf("header\n%s  sample.txt\n", sumHex)
	if string(got) != want {
		t.Fatalf("output mismatch: %q != %q", string(got), want)
	}
}

func TestCLIAppendWithoutOutputError(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "sample.txt", []byte("hello\n"))
	res := runCmd(t, dir, "", "-sha256", "-a", "sample.txt")
	if res.exitCode != exitTrouble {
		t.Fatalf("expected exit %d, got %d", exitTrouble, res.exitCode)
	}
	if !strings.Contains(res.stderr, "append requires -o/--output") {
		t.Fatalf("unexpected stderr: %q", res.stderr)
	}
}

func TestCLIMultipleDigestError(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "sample.txt", []byte("hello\n"))
	res := runCmd(t, dir, "", "-sha1", "-sha256", "sample.txt")
	if res.exitCode != exitTrouble {
		t.Fatalf("expected exit %d, got %d", exitTrouble, res.exitCode)
	}
	if !strings.Contains(res.stderr, "multiple digest options provided") {
		t.Fatalf("unexpected stderr: %q", res.stderr)
	}
}

func TestCLIList(t *testing.T) {
	dir := t.TempDir()
	res := runCmd(t, dir, "", "-l")
	if res.exitCode != 0 {
		t.Fatalf("exit %d: %s", res.exitCode, res.stderr)
	}
	if !strings.Contains(res.stdout, "Supported digests:") {
		t.Fatalf("missing header: %q", res.stdout)
	}
	if !strings.Contains(res.stdout, "-sha256") {
		t.Fatalf("missing sha256: %q", res.stdout)
	}
}

func TestCLIHelpAndVersion(t *testing.T) {
	dir := t.TempDir()
	help := runCmd(t, dir, "", "-h")
	if help.exitCode != 0 {
		t.Fatalf("help exit %d: %s", help.exitCode, help.stderr)
	}
	if !strings.Contains(help.stdout, "Usage: calchash") {
		t.Fatalf("missing usage: %q", help.stdout)
	}
	ver := runCmd(t, dir, "", "-v")
	if ver.exitCode != 0 {
		t.Fatalf("version exit %d: %s", ver.exitCode, ver.stderr)
	}
	if strings.TrimSpace(ver.stdout) != "calchash 1.0.0" {
		t.Fatalf("unexpected version: %q", ver.stdout)
	}
}

func TestCLIForceUTF8(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		t.Skip("invalid UTF-8 filenames are not portable on this OS")
	}
	dir := t.TempDir()
	name := string([]byte{0xff, 'a'})
	data := []byte("hello\n")
	writeFile(t, dir, name, data)
	sumHex := sha256Hex(data)
	res := runCmd(t, dir, "", "-sha256", "-u", name)
	if res.exitCode != 0 {
		t.Fatalf("exit %d: %s", res.exitCode, res.stderr)
	}
	if !strings.HasPrefix(res.stdout, sumHex+"  ") {
		t.Fatalf("unexpected output prefix: %q", res.stdout)
	}
	if !strings.Contains(res.stdout, "\uFFFDa") {
		t.Fatalf("expected replacement rune, got %q", res.stdout)
	}
}

func TestDigestStreamWindowsTextNormalization(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows-only text normalization")
	}
	cases := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{"crlf", []byte("a\r\nb\r\n"), []byte("a\nb\n")},
		{"trailing_cr", []byte("a\r"), []byte("a\n")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			filename := tc.name + ".txt"
			writeFile(t, dir, filename, tc.input)
			want := sha256.Sum256(tc.expected)
			wantHex := hex.EncodeToString(want[:])
			res := runCmd(t, dir, "", "-sha256", filename)
			if res.exitCode != 0 {
				t.Fatalf("exit %d: %s", res.exitCode, res.stderr)
			}
			expect := fmt.Sprintf("%s  %s\n", wantHex, filename)
			if res.stdout != expect {
				t.Fatalf("stdout mismatch: %q != %q", res.stdout, expect)
			}
		})
	}
}

func TestDigestStreamWindowsBinaryPreservesCRLF(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows-only binary mode")
	}
	input := []byte("a\r\nb\r\n")
	dir := t.TempDir()
	filename := "crlf.txt"
	writeFile(t, dir, filename, input)
	want := sha256.Sum256(input)
	wantHex := hex.EncodeToString(want[:])
	res := runCmd(t, dir, "", "-sha256", "-b", filename)
	if res.exitCode != 0 {
		t.Fatalf("exit %d: %s", res.exitCode, res.stderr)
	}
	expect := fmt.Sprintf("%s *%s\n", wantHex, filename)
	if res.stdout != expect {
		t.Fatalf("stdout mismatch: %q != %q", res.stdout, expect)
	}
}

func TestCLIComputeFromStdinDefault(t *testing.T) {
	dir := t.TempDir()
	data := []byte("stdin\n")
	sumHex := sha256Hex(data)
	res := runCmd(t, dir, string(data), "-sha256")
	if res.exitCode != 0 {
		t.Fatalf("exit %d: %s", res.exitCode, res.stderr)
	}
	want := fmt.Sprintf("%s  -\n", sumHex)
	if res.stdout != want {
		t.Fatalf("stdout mismatch: %q != %q", res.stdout, want)
	}
}

func TestCLIComputeFromStdinDash(t *testing.T) {
	dir := t.TempDir()
	data := []byte("stdin\n")
	sumHex := sha256Hex(data)
	res := runCmd(t, dir, string(data), "-sha256", "-")
	if res.exitCode != 0 {
		t.Fatalf("exit %d: %s", res.exitCode, res.stderr)
	}
	want := fmt.Sprintf("%s  -\n", sumHex)
	if res.stdout != want {
		t.Fatalf("stdout mismatch: %q != %q", res.stdout, want)
	}
}

func TestCLICheckFromStdinList(t *testing.T) {
	dir := t.TempDir()
	data := []byte("hello\n")
	writeFile(t, dir, "sample.txt", data)
	sumHex := sha256Hex(data)
	list := fmt.Sprintf("%s  sample.txt\n", sumHex)
	res := runCmd(t, dir, list, "-sha256", "-c", "-")
	if res.exitCode != 0 {
		t.Fatalf("exit %d: %s", res.exitCode, res.stderr)
	}
	if res.stdout != "sample.txt: OK\n" {
		t.Fatalf("unexpected stdout: %q", res.stdout)
	}
}

func TestCLICheckStatusMismatch(t *testing.T) {
	dir := t.TempDir()
	data := []byte("hello\n")
	writeFile(t, dir, "sample.txt", data)
	sumHex := sha256Hex(data)
	bad := sumHex[:len(sumHex)-1]
	if sumHex[len(sumHex)-1] != '0' {
		bad += "0"
	} else {
		bad += "1"
	}
	list := fmt.Sprintf("%s  sample.txt\n", bad)
	writeFile(t, dir, "checksums.txt", []byte(list))
	res := runCmd(t, dir, "", "-sha256", "-c", "--status", "checksums.txt")
	if res.exitCode != exitMismatch {
		t.Fatalf("expected exit %d, got %d", exitMismatch, res.exitCode)
	}
	if res.stdout != "" || res.stderr != "" {
		t.Fatalf("expected no output, got stdout=%q stderr=%q", res.stdout, res.stderr)
	}
}

func TestCLICheckQuiet(t *testing.T) {
	dir := t.TempDir()
	data := []byte("hello\n")
	writeFile(t, dir, "sample.txt", data)
	sumHex := sha256Hex(data)
	list := fmt.Sprintf("%s  sample.txt\n", sumHex)
	writeFile(t, dir, "checksums.txt", []byte(list))
	res := runCmd(t, dir, "", "-sha256", "--quiet", "-c", "checksums.txt")
	if res.exitCode != 0 {
		t.Fatalf("exit %d: %s", res.exitCode, res.stderr)
	}
	if res.stdout != "" {
		t.Fatalf("expected no output, got %q", res.stdout)
	}
}

func TestCLICheckStrictWarn(t *testing.T) {
	dir := t.TempDir()
	data := []byte("hello\n")
	writeFile(t, dir, "sample.txt", data)
	sumHex := sha256Hex(data)
	list := fmt.Sprintf("badline\n%s  sample.txt\n", sumHex)
	writeFile(t, dir, "checksums.txt", []byte(list))
	res := runCmd(t, dir, "", "-sha256", "--warn", "--strict", "-c", "checksums.txt")
	if res.exitCode != exitTrouble {
		t.Fatalf("expected exit %d, got %d", exitTrouble, res.exitCode)
	}
	if !strings.Contains(res.stderr, "WARNING") {
		t.Fatalf("expected warning, got %q", res.stderr)
	}
}

func TestCLIOutputOverwrite(t *testing.T) {
	dir := t.TempDir()
	data := []byte("hello\n")
	writeFile(t, dir, "sample.txt", data)
	sumHex := sha256Hex(data)
	outPath := writeFile(t, dir, "out.txt", []byte("old\n"))
	res := runCmd(t, dir, "", "-sha256", "-o", outPath, "sample.txt")
	if res.exitCode != 0 {
		t.Fatalf("exit %d: %s", res.exitCode, res.stderr)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	want := fmt.Sprintf("%s  sample.txt\n", sumHex)
	if string(got) != want {
		t.Fatalf("output mismatch: %q != %q", string(got), want)
	}
}

func TestCLIDirectoryInputError(t *testing.T) {
	dir := t.TempDir()
	res := runCmd(t, dir, "", "-sha256", dir)
	if res.exitCode != exitTrouble {
		t.Fatalf("expected exit %d, got %d", exitTrouble, res.exitCode)
	}
	if !strings.Contains(res.stderr, "Is a directory") {
		t.Fatalf("unexpected stderr: %q", res.stderr)
	}
}
