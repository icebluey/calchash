// calchash.go
//
// A coreutils-inspired checksum tool.
//
// Features.
// - Cross-platform: Linux, macOS, Windows.
// - Read FILEs, or standard input when FILE is "-" or no FILE is given.
// - Output formats compatible with coreutils-style "<hex>  <file>" and "<hex> *<file>".
// - Optional BSD-style "--tag" output.
// - Check mode "-c" to verify checksum lists.
//
// Important.
// - A digest option is REQUIRED. There is no default digest.
// - Whirlpool uses github.com/jzelinskie/whirlpool (x/crypto does not include it).
// - BLAKE3 uses lukechampine.com/blake3.

package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	whirlpoolhash "github.com/jzelinskie/whirlpool"
	"lukechampine.com/blake3"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
)

const (
	progName    = "calchash"
	progVersion = "1.0.0"

	bufLen = 1 << 16
)

type exitCode int

const (
	exitOK       exitCode = 0
	exitMismatch exitCode = 1
	exitTrouble  exitCode = 2
)

type options struct {
	binary bool
	text   bool

	check bool
	tag   bool
	zero  bool

	ignoreMissing bool
	quiet         bool
	status        bool
	strict        bool
	warn          bool

	append bool

	outputPath string
	forceUTF8  bool

	list    bool
	help    bool
	version bool

	algoName string
}

type digester interface {
	Write(p []byte) (int, error)
	Final() ([]byte, error)
}

type hashDigester struct {
	h hash.Hash
}

func (d *hashDigester) Write(p []byte) (int, error) {
	return d.h.Write(p)
}

func (d *hashDigester) Final() ([]byte, error) {
	return d.h.Sum(nil), nil
}

type md5sha1Digester struct {
	m hash.Hash
	s hash.Hash
}

func (d *md5sha1Digester) Write(p []byte) (int, error) {
	_, _ = d.m.Write(p)
	_, _ = d.s.Write(p)
	return len(p), nil
}

func (d *md5sha1Digester) Final() ([]byte, error) {
	out := make([]byte, 0, md5.Size+sha1.Size)
	out = append(out, d.m.Sum(nil)...)
	out = append(out, d.s.Sum(nil)...)
	return out, nil
}

type digestSpec struct {
	flagName  string
	tagName   string
	digestLen int
	newFn     func() (digester, error)
}

func supportedDigests() []digestSpec {
	return []digestSpec{
		{
			flagName:  "blake2b512",
			tagName:   "BLAKE2B-512",
			digestLen: 64,
			newFn: func() (digester, error) {
				h, err := blake2b.New512(nil)
				if err != nil {
					return nil, err
				}
				return &hashDigester{h: h}, nil
			},
		},
		{
			flagName:  "blake2s256",
			tagName:   "BLAKE2S-256",
			digestLen: 32,
			newFn: func() (digester, error) {
				h, err := blake2s.New256(nil)
				if err != nil {
					return nil, err
				}
				return &hashDigester{h: h}, nil
			},
		},
		{
			flagName:  "blake3",
			tagName:   "BLAKE3",
			digestLen: 32,
			newFn: func() (digester, error) {
				return &hashDigester{h: blake3.New(32, nil)}, nil
			},
		},
		{
			flagName:  "md4",
			tagName:   "MD4",
			digestLen: 16,
			newFn: func() (digester, error) {
				return &hashDigester{h: md4.New()}, nil
			},
		},
		{
			flagName:  "md5",
			tagName:   "MD5",
			digestLen: 16,
			newFn: func() (digester, error) {
				return &hashDigester{h: md5.New()}, nil
			},
		},
		{
			flagName:  "md5-sha1",
			tagName:   "MD5-SHA1",
			digestLen: md5.Size + sha1.Size,
			newFn: func() (digester, error) {
				return &md5sha1Digester{m: md5.New(), s: sha1.New()}, nil
			},
		},
		{
			flagName:  "ripemd",
			tagName:   "RIPEMD160",
			digestLen: 20,
			newFn: func() (digester, error) {
				return &hashDigester{h: ripemd160.New()}, nil
			},
		},
		{
			flagName:  "ripemd160",
			tagName:   "RIPEMD160",
			digestLen: 20,
			newFn: func() (digester, error) {
				return &hashDigester{h: ripemd160.New()}, nil
			},
		},
		{
			flagName:  "rmd160",
			tagName:   "RIPEMD160",
			digestLen: 20,
			newFn: func() (digester, error) {
				return &hashDigester{h: ripemd160.New()}, nil
			},
		},
		{
			flagName:  "sha1",
			tagName:   "SHA1",
			digestLen: 20,
			newFn: func() (digester, error) {
				return &hashDigester{h: sha1.New()}, nil
			},
		},
		{
			flagName:  "sha224",
			tagName:   "SHA224",
			digestLen: 28,
			newFn: func() (digester, error) {
				return &hashDigester{h: sha256.New224()}, nil
			},
		},
		{
			flagName:  "sha256",
			tagName:   "SHA256",
			digestLen: 32,
			newFn: func() (digester, error) {
				return &hashDigester{h: sha256.New()}, nil
			},
		},
		{
			flagName:  "sha384",
			tagName:   "SHA384",
			digestLen: 48,
			newFn: func() (digester, error) {
				return &hashDigester{h: sha512.New384()}, nil
			},
		},
		{
			flagName:  "sha512",
			tagName:   "SHA512",
			digestLen: 64,
			newFn: func() (digester, error) {
				return &hashDigester{h: sha512.New()}, nil
			},
		},
		{
			flagName:  "sha512-224",
			tagName:   "SHA512-224",
			digestLen: 28,
			newFn: func() (digester, error) {
				return &hashDigester{h: sha512.New512_224()}, nil
			},
		},
		{
			flagName:  "sha512-256",
			tagName:   "SHA512-256",
			digestLen: 32,
			newFn: func() (digester, error) {
				return &hashDigester{h: sha512.New512_256()}, nil
			},
		},
		{
			flagName:  "sha3-224",
			tagName:   "SHA3-224",
			digestLen: 28,
			newFn: func() (digester, error) {
				return &hashDigester{h: sha3.New224()}, nil
			},
		},
		{
			flagName:  "sha3-256",
			tagName:   "SHA3-256",
			digestLen: 32,
			newFn: func() (digester, error) {
				return &hashDigester{h: sha3.New256()}, nil
			},
		},
		{
			flagName:  "sha3-384",
			tagName:   "SHA3-384",
			digestLen: 48,
			newFn: func() (digester, error) {
				return &hashDigester{h: sha3.New384()}, nil
			},
		},
		{
			flagName:  "sha3-512",
			tagName:   "SHA3-512",
			digestLen: 64,
			newFn: func() (digester, error) {
				return &hashDigester{h: sha3.New512()}, nil
			},
		},
		{
			flagName:  "whirlpool",
			tagName:   "WHIRLPOOL",
			digestLen: 64,
			newFn: func() (digester, error) {
				return &hashDigester{h: whirlpoolhash.New()}, nil
			},
		},
	}
}

func findDigest(name string) (digestSpec, bool) {
	for _, d := range supportedDigests() {
		if d.flagName == name {
			return d, true
		}
	}
	return digestSpec{}, false
}

func usage(w io.Writer) {
	fmt.Fprintf(w, "Usage: %s [OPTION]... [FILE]...\n", progName)
	fmt.Fprintf(w, "\nWith no FILE, or when FILE is -, read standard input.\n\n")
	fmt.Fprintf(w, "  -b, --binary         read in binary mode\n")
	fmt.Fprintf(w, "  -c, --check          read SHA256 sums from the FILEs and check them\n")
	fmt.Fprintf(w, "      --tag            create a BSD-style checksum\n")
	fmt.Fprintf(w, "  -t, --text           read in text mode (default)\n")
	fmt.Fprintf(w, "  -z, --zero           end each output line with NUL, not newline,\n")
	fmt.Fprintf(w, "                       and disable file name escaping\n\n")
	fmt.Fprintf(w, "The following five options are useful only when verifying checksums:\n")
	fmt.Fprintf(w, "      --ignore-missing  don't fail or report status for missing files\n")
	fmt.Fprintf(w, "      --quiet          don't print OK for each successfully verified file\n")
	fmt.Fprintf(w, "      --status         don't output anything, status code shows success\n")
	fmt.Fprintf(w, "      --strict         exit non-zero for improperly formatted checksum lines\n")
	fmt.Fprintf(w, "  -w, --warn           warn about improperly formatted checksum lines\n\n")
	fmt.Fprintf(w, "  -a, --append         append to file when using with -o or --output\n")
	fmt.Fprintf(w, "  -o, --output         write output to file\n")
	fmt.Fprintf(w, "  -u, --utf8           force output characters are UTF-8 encoding\n")
	fmt.Fprintf(w, "  -l, --list           list supported digests\n")
	fmt.Fprintf(w, "  -h, --help           display this help and exit\n")
	fmt.Fprintf(w, "  -v, --version        output version information and exit\n\n")
	fmt.Fprintf(w, "The digest algorithm must be specified (e.g., -sha256, -sha1).\n")
	fmt.Fprintf(w, "Use -l or --list to see all supported algorithms.\n")
}

func printVersion(w io.Writer) {
	fmt.Fprintf(w, "%s %s\n", progName, progVersion)
}

func listDigests(w io.Writer) {
	fmt.Fprintf(w, "Supported digests:\n")
	fmt.Fprintf(w, "-blake2b512                -blake2s256                -blake3\n")
	fmt.Fprintf(w, "-md4                       -md5                       -md5-sha1\n")
	fmt.Fprintf(w, "-ripemd                    -ripemd160                 -rmd160\n")
	fmt.Fprintf(w, "-sha1                      -sha224                    -sha256\n")
	fmt.Fprintf(w, "-sha3-224                  -sha3-256                  -sha3-384\n")
	fmt.Fprintf(w, "-sha3-512                  -sha384                    -sha512\n")
	fmt.Fprintf(w, "-sha512-224                -sha512-256                -whirlpool\n")
}

func dief(code exitCode, format string, a ...any) {
	fmt.Fprintf(os.Stderr, "%s: %s\n", progName, fmt.Sprintf(format, a...))
	os.Exit(int(code))
}

func writeErr(opt *options, format string, a ...any) {
	if opt != nil && opt.status {
		return
	}
	fmt.Fprintf(os.Stderr, "%s: %s\n", progName, fmt.Sprintf(format, a...))
}

func sanitizeUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		if r == utf8.RuneError && size == 1 {
			b.WriteRune('\uFFFD')
			s = s[1:]
			continue
		}
		b.WriteRune(r)
		s = s[size:]
	}
	return b.String()
}

func escapeFilename(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case 0:
			b.WriteString(`\0`)
		default:
			if c < 0x20 || c == 0x7f {
				b.WriteString(`\`)
				b.WriteString(fmt.Sprintf("%03o", c))
			} else {
				b.WriteByte(c)
			}
		}
	}
	return b.String()
}

func unescapeFilename(s string) (string, error) {
	var out bytes.Buffer
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' {
			out.WriteByte(c)
			continue
		}
		if i+1 >= len(s) {
			return "", errors.New("dangling escape")
		}
		i++
		switch s[i] {
		case '\\':
			out.WriteByte('\\')
		case 'n':
			out.WriteByte('\n')
		case 'r':
			out.WriteByte('\r')
		case 't':
			out.WriteByte('\t')
		case '0':
			out.WriteByte(0)
		default:
			if s[i] < '0' || s[i] > '7' {
				return "", fmt.Errorf("bad escape: \\%c", s[i])
			}
			if i+2 >= len(s) {
				return "", errors.New("short octal escape")
			}
			oct := s[i : i+3]
			v, err := strconv.ParseUint(oct, 8, 8)
			if err != nil {
				return "", err
			}
			out.WriteByte(byte(v))
			i += 2
		}
	}
	return out.String(), nil
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') ||
			(c >= 'a' && c <= 'f') ||
			(c >= 'A' && c <= 'F') {
			continue
		}
		return false
	}
	return true
}

func normalizeTextWindows(prevCR *bool, in []byte, out []byte) ([]byte, bool) {
	j := 0
	p := *prevCR
	for i := 0; i < len(in); i++ {
		c := in[i]
		if p {
			if c == '\n' {
				out[j] = '\n'
				j++
				p = false
				continue
			}
			out[j] = '\n'
			j++
			p = false
		}
		if c == '\r' {
			p = true
			continue
		}
		out[j] = c
		j++
	}
	*prevCR = p
	return out[:j], p
}

func digestStream(r io.Reader, spec digestSpec, opt *options) ([]byte, error) {
	d, err := spec.newFn()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, bufLen)
	norm := make([]byte, bufLen+1)

	prevCR := false
	winText := (runtime.GOOS == "windows") && opt.text && !opt.binary

	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			if winText {
				p, _ := normalizeTextWindows(&prevCR, buf[:n], norm)
				_, err = d.Write(p)
			} else {
				_, err = d.Write(buf[:n])
			}
			if err != nil {
				return nil, err
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return nil, rerr
		}
	}

	if winText && prevCR {
		_, err = d.Write([]byte{'\n'})
		if err != nil {
			return nil, err
		}
	}

	return d.Final()
}

func openOutput(opt *options) (io.Writer, func(), error) {
	if opt.outputPath == "" || opt.outputPath == "-" {
		return os.Stdout, func() {}, nil
	}
	var (
		f   *os.File
		err error
	)
	if opt.append {
		f, err = os.OpenFile(opt.outputPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	} else {
		f, err = os.Create(opt.outputPath)
	}
	if err != nil {
		return nil, nil, err
	}
	return f, func() { _ = f.Close() }, nil
}

func lineSep(opt *options) string {
	if opt.zero {
		return "\x00"
	}
	return "\n"
}

func formatDigestLine(spec digestSpec, sum []byte, name string, opt *options) string {
	hexsum := hex.EncodeToString(sum)

	if opt.forceUTF8 {
		name = sanitizeUTF8(name)
	}

	if opt.tag {
		return fmt.Sprintf("%s (%s) = %s", spec.tagName, name, hexsum)
	}

	if !opt.zero {
		name = escapeFilename(name)
	}

	if opt.binary {
		return fmt.Sprintf("%s *%s", hexsum, name)
	}
	return fmt.Sprintf("%s  %s", hexsum, name)
}

func globNeeded(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

func expandGlobs(args []string) []string {
	var out []string
	for _, a := range args {
		if a == "-" || !globNeeded(a) {
			out = append(out, a)
			continue
		}
		m, err := filepath.Glob(a)
		if err != nil || len(m) == 0 {
			out = append(out, a)
			continue
		}
		sort.Strings(m)
		out = append(out, m...)
	}
	return out
}

type parsedLine struct {
	ok        bool
	hexDigest string
	filename  string
	binary    bool
	bsdAlgo   string
}

func parseChecksumLine(line string) parsedLine {
	line = strings.TrimRight(line, "\r\n\x00")
	if line == "" || strings.HasPrefix(line, "#") {
		return parsedLine{}
	}

	/* BSD style: ALGO (filename) = digest */
	if i := strings.Index(line, " ("); i >= 0 {
		if j := strings.Index(line, ") = "); j > i {
			algo := strings.TrimSpace(line[:i])
			fn := line[i+2 : j]
			dh := strings.TrimSpace(line[j+4:])
			if algo != "" && fn != "" && dh != "" {
				return parsedLine{
					ok:        true,
					hexDigest: dh,
					filename:  fn,
					bsdAlgo:   algo,
				}
			}
		}
	}

	/* GNU style: digest [ ][*| ]filename */
	sp := -1
	for i := 0; i < len(line); i++ {
		if line[i] == ' ' || line[i] == '\t' {
			sp = i
			break
		}
	}
	if sp < 0 {
		return parsedLine{}
	}

	dh := line[:sp]
	rest := line[sp:]
	if len(rest) < 2 {
		return parsedLine{}
	}
	if rest[0] != ' ' && rest[0] != '\t' {
		return parsedLine{}
	}

	rest = rest[1:]

	bin := false
	if len(rest) > 0 && rest[0] == '*' {
		bin = true
		rest = rest[1:]
	} else if len(rest) > 0 && (rest[0] == ' ' || rest[0] == '\t') {
		rest = rest[1:]
	}

	if rest == "" {
		return parsedLine{}
	}

	return parsedLine{
		ok:        true,
		hexDigest: dh,
		filename:  rest,
		binary:    bin,
	}
}

func computeFiles(files []string, spec digestSpec, opt *options, out io.Writer) exitCode {
	sep := lineSep(opt)
	trouble := false

	for _, name := range files {
		var r io.Reader
		var clos func()

		if name == "-" {
			r = os.Stdin
			clos = func() {}
		} else {
			f, err := os.Open(name)
			if err != nil {
				trouble = true
				writeErr(opt, "%s: %v", name, err)
				continue
			}
			if fi, serr := f.Stat(); serr == nil && fi.IsDir() {
				_ = f.Close()
				trouble = true
				writeErr(opt, "%s: Is a directory", name)
				continue
			}
			r = f
			clos = func() { _ = f.Close() }
		}

		sum, err := digestStream(r, spec, opt)
		clos()
		if err != nil {
			trouble = true
			writeErr(opt, "%s: %v", name, err)
			continue
		}

		line := formatDigestLine(spec, sum, name, opt)
		_, _ = io.WriteString(out, line)
		_, _ = io.WriteString(out, sep)
	}

	if trouble {
		return exitTrouble
	}
	return exitOK
}

func readRecord(br *bufio.Reader, delim byte) ([]byte, error) {
	b, err := br.ReadBytes(delim)
	if err == nil {
		return b[:len(b)-1], nil
	}
	if err == io.EOF && len(b) > 0 {
		return b, nil
	}
	return nil, err
}

func looksLikeUTF16LE(b []byte) bool {
	if len(b) < 8 {
		return false
	}
	// Heuristic: for ASCII-ish UTF-16LE text, odd bytes are very often 0x00.
	n := len(b)
	if n%2 == 1 {
		n--
	}
	if n < 8 {
		return false
	}
	zerosOdd := 0
	totalOdd := 0
	zerosEven := 0
	totalEven := 0
	for i := 0; i < n; i++ {
		if i%2 == 0 {
			totalEven++
			if b[i] == 0 {
				zerosEven++
			}
			continue
		}
		totalOdd++
		if b[i] == 0 {
			zerosOdd++
		}
	}
	// >= 80% of odd bytes are 0x00, and not too many even bytes are 0x00.
	return zerosOdd*5 >= totalOdd*4 && zerosEven*3 <= totalEven*2
}

func decodeUTF16LE(b []byte) (string, error) {
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
		b = b[2:]
	}
	if len(b)%2 != 0 {
		return "", errors.New("invalid UTF-16LE data")
	}
	u16 := make([]uint16, 0, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		u16 = append(u16, uint16(b[i])|uint16(b[i+1])<<8)
	}
	return string(utf16.Decode(u16)), nil
}

func prepareChecksumListReader(r io.Reader, opt *options) (io.Reader, error) {
	br := bufio.NewReader(r)
	peek, perr := br.Peek(64)
	if perr != nil && perr != io.EOF {
		return nil, perr
	}

	// Always support UTF-8 BOM.
	if len(peek) >= 3 && peek[0] == 0xEF && peek[1] == 0xBB && peek[2] == 0xBF {
		_, _ = br.Discard(3)
		return br, nil
	}

	// When -z/--zero is used, ignore UTF-16LE support.
	if opt.zero {
		return br, nil
	}

	// UTF-16LE BOM.
	if len(peek) >= 2 && peek[0] == 0xFF && peek[1] == 0xFE {
		all, err := io.ReadAll(br)
		if err != nil {
			return nil, err
		}
		s, derr := decodeUTF16LE(all)
		if derr != nil {
			return nil, derr
		}
		return strings.NewReader(s), nil
	}

	// Heuristic UTF-16LE (no BOM).
	if looksLikeUTF16LE(peek) {
		all, err := io.ReadAll(br)
		if err != nil {
			return nil, err
		}
		s, derr := decodeUTF16LE(all)
		if derr != nil {
			return nil, derr
		}
		return strings.NewReader(s), nil
	}

	return br, nil
}

func checkFiles(listFiles []string, spec digestSpec, opt *options, out io.Writer) exitCode {
	sep := lineSep(opt)

	delim := byte('\n')
	if opt.zero {
		delim = 0
	}

	wantLen := spec.digestLen * 2

	var badLine bool
	var mismatchCount int
	var trouble bool
	var goodLine bool

	report := func(s string) {
		if opt.status {
			return
		}
		_, _ = io.WriteString(out, s)
		_, _ = io.WriteString(out, sep)
	}

	warnf := func(format string, a ...any) {
		if opt.status || !opt.warn {
			return
		}
		fmt.Fprintf(os.Stderr, "%s: WARNING: %s\n", progName, fmt.Sprintf(format, a...))
	}

	openList := func(path string) (io.Reader, func(), error) {
		if path == "-" {
			return os.Stdin, func() {}, nil
		}
		f, err := os.Open(path)
		if err != nil {
			return nil, nil, err
		}
		return f, func() { _ = f.Close() }, nil
	}

	for _, lf := range listFiles {
		r, clos, err := openList(lf)
		if err != nil {
			trouble = true
			writeErr(opt, "%s: %v", lf, err)
			continue
		}

		rr, rerr := prepareChecksumListReader(r, opt)
		if rerr != nil {
			trouble = true
			writeErr(opt, "%s: %v", lf, rerr)
			clos()
			continue
		}

		br := bufio.NewReader(rr)
		fileReadErr := false
		goodLineThisFile := false
		badLineThisFile := 0
		lineno := 0

		for {
			rec, rerr := readRecord(br, delim)
			if rerr == io.EOF {
				break
			}
			if rerr != nil {
				trouble = true
				fileReadErr = true
				writeErr(opt, "%s: %v", lf, rerr)
				break
			}

			lineno++
			pl := parseChecksumLine(string(rec))
			if !pl.ok {
				trim := strings.TrimSpace(string(rec))
				if trim != "" && !strings.HasPrefix(trim, "#") {
					badLine = true
					badLineThisFile++
					warnf("%s:%d: improperly formatted checksum line", lf, lineno)
				}
				continue
			}

			if pl.bsdAlgo != "" && !strings.EqualFold(pl.bsdAlgo, spec.tagName) {
				badLine = true
				badLineThisFile++
				warnf("%s:%d: algorithm mismatch (got %q, expected %q)",
					lf, lineno, pl.bsdAlgo, spec.tagName)
				continue
			}

			dh := strings.TrimSpace(pl.hexDigest)
			fn := pl.filename

			if !isHex(dh) || len(dh) != wantLen {
				badLine = true
				badLineThisFile++
				warnf("%s:%d: invalid %s digest", lf, lineno, spec.tagName)
				continue
			}

			goodLine = true
			goodLineThisFile = true

			if !opt.zero {
				u, uerr := unescapeFilename(fn)
				if uerr == nil {
					fn = u
				}
			}

			/* stdin conflict: list is stdin, target "-" would also be stdin */
			if lf == "-" && fn == "-" {
				badLine = true
				badLineThisFile++
				warnf("%s:%d: target file '-' is invalid when reading checksum list from stdin",
					lf, lineno)
				continue
			}

			var fr io.Reader
			var fclos func()

			if fn == "-" {
				fr = os.Stdin
				fclos = func() {}
			} else {
				f, ferr := os.Open(fn)
				if ferr != nil {
					if os.IsNotExist(ferr) && opt.ignoreMissing {
						continue
					}
					trouble = true
					writeErr(opt, "%s: %v", fn, ferr)
					continue
				}
				if fi, serr := f.Stat(); serr == nil && fi.IsDir() {
					_ = f.Close()
					trouble = true
					writeErr(opt, "%s: Is a directory", fn)
					continue
				}
				fr = f
				fclos = func() { _ = f.Close() }
			}

			/* In check mode, honor the line's binary marker on Windows. */
			eff := *opt
			if pl.binary {
				eff.binary = true
				eff.text = false
			} else {
				eff.binary = false
				eff.text = true
			}

			sum, derr := digestStream(fr, spec, &eff)
			fclos()
			if derr != nil {
				trouble = true
				writeErr(opt, "%s: %v", fn, derr)
				continue
			}

			got := hex.EncodeToString(sum)
			if strings.EqualFold(got, dh) {
				if !opt.quiet {
					report(fmt.Sprintf("%s: OK", fn))
				}
			} else {
				mismatchCount++
				report(fmt.Sprintf("%s: FAILED", fn))
			}
		}

		if badLineThisFile > 0 && goodLineThisFile && !fileReadErr && !opt.status {
			if badLineThisFile == 1 {
				fmt.Fprintf(os.Stderr, "%s: WARNING: 1 line is improperly formatted\n", progName)
			} else {
				fmt.Fprintf(os.Stderr, "%s: WARNING: %d lines are improperly formatted\n", progName, badLineThisFile)
			}
		}

		if !goodLineThisFile && !fileReadErr {
			trouble = true
			writeErr(opt, "%s: no properly formatted %s checksum lines found", lf, spec.tagName)
		}

		clos()
	}

	if opt.strict && badLine {
		return exitTrouble
	}

	if opt.strict && !goodLine {
		return exitTrouble
	}

	if trouble {
		return exitTrouble
	}

	if mismatchCount > 0 {
		if !opt.status {
			fmt.Fprintf(os.Stderr, "%s: WARNING: %d computed checksums did NOT match%s", progName, mismatchCount, sep)
		}
		return exitMismatch
	}

	return exitOK
}

func parseArgs(argv []string) (options, []string) {
	var opt options
	var files []string

	opt.text = true

	isDigest := func(a string) (string, bool) {
		if strings.HasPrefix(a, "--") {
			a = a[2:]
		} else if strings.HasPrefix(a, "-") && a != "-" {
			a = a[1:]
		} else {
			return "", false
		}
		_, ok := findDigest(a)
		return a, ok
	}

	for i := 0; i < len(argv); i++ {
		a := argv[i]

		if a == "--" {
			files = append(files, argv[i+1:]...)
			break
		}

		if d, ok := isDigest(a); ok {
			opt.algoName = d
			continue
		}

		if !strings.HasPrefix(a, "-") || a == "-" {
			files = append(files, a)
			continue
		}

		switch {
		case a == "-b" || a == "--binary":
			opt.binary = true
			opt.text = false

		case a == "-t" || a == "--text":
			opt.text = true
			opt.binary = false

		case a == "-c" || a == "--check":
			opt.check = true

		case a == "--tag":
			opt.tag = true

		case a == "-z" || a == "--zero":
			opt.zero = true

		case a == "--ignore-missing":
			opt.ignoreMissing = true

		case a == "--quiet":
			opt.quiet = true

		case a == "--status":
			opt.status = true
			opt.quiet = true

		case a == "--strict":
			opt.strict = true

		case a == "-w" || a == "--warn":
			opt.warn = true

		case a == "-a" || a == "--append":
			opt.append = true

		case a == "-o" || a == "--output":
			if i+1 >= len(argv) {
				dief(exitTrouble, "missing argument for %s", a)
			}
			i++
			opt.outputPath = argv[i]

		case strings.HasPrefix(a, "--output="):
			opt.outputPath = strings.TrimPrefix(a, "--output=")

		case a == "-u" || a == "--utf8":
			opt.forceUTF8 = true

		case a == "-l" || a == "--list":
			opt.list = true

		case a == "-h" || a == "--help":
			opt.help = true

		case a == "-v" || a == "--version":
			opt.version = true

		default:
			/* Support grouped short options (no-arg ones only). */
			if strings.HasPrefix(a, "-") && len(a) > 2 && !strings.HasPrefix(a, "--") {
				group := a[1:]
				ok := true
				for j := 0; j < len(group); j++ {
					switch group[j] {
					case 'b':
						opt.binary = true
						opt.text = false
					case 't':
						opt.text = true
						opt.binary = false
					case 'c':
						opt.check = true
					case 'z':
						opt.zero = true
					case 'w':
						opt.warn = true
					case 'a':
						opt.append = true
					case 'u':
						opt.forceUTF8 = true
					case 'l':
						opt.list = true
					case 'h':
						opt.help = true
					case 'v':
						opt.version = true
					default:
						ok = false
					}
					if !ok {
						break
					}
				}
				if ok {
					continue
				}
			}

			dief(exitTrouble, "unknown option: %s", a)
		}
	}

	return opt, files
}

func requireDigest(opt *options) {
	if opt.algoName != "" {
		return
	}
	dief(exitTrouble, "missing digest option, use -l to list supported digests")
}

func main() {
	opt, args := parseArgs(os.Args[1:])

	if opt.help {
		usage(os.Stdout)
		os.Exit(int(exitOK))
	}

	if opt.version {
		printVersion(os.Stdout)
		os.Exit(int(exitOK))
	}

	if opt.list {
		listDigests(os.Stdout)
		os.Exit(int(exitOK))
	}

	requireDigest(&opt)

	spec, ok := findDigest(opt.algoName)
	if !ok {
		dief(exitTrouble, "unsupported digest: %s", opt.algoName)
	}

	out, clos, err := openOutput(&opt)
	if err != nil {
		dief(exitTrouble, "cannot open output: %v", err)
	}
	defer clos()

	/* Expand globs (Windows compatibility, no-op on Unix shells). */
	args = expandGlobs(args)

	if opt.check {
		if len(args) == 0 {
			args = []string{"-"}
		}
		os.Exit(int(checkFiles(args, spec, &opt, out)))
	}

	if len(args) == 0 {
		args = []string{"-"}
	}

	os.Exit(int(computeFiles(args, spec, &opt, out)))
}
