# calchash

Coreutils-style checksum tool that supports multiple digests, BSD tag output,
and verification of GNU/BSD checksum lists.

## Features
- Cross-platform: Linux, macOS, Windows.
- Reads FILEs or stdin (FILE "-" or no FILEs).
- GNU output: "<hex>  <file>" or "<hex> *<file>".
- BSD output: "ALGO (file) = <hex>" via `--tag`.
- Check mode `-c` for GNU and BSD lists (BSD lines carry their own algorithm).
- UTF-8 BOM and UTF-16LE list decoding (BOM or heuristic).
- Windows text mode normalization (CRLF -> LF) when not in binary mode.

## Build
```
# linux
CGO_ENABLED=0 GOARCH=amd64 GOAMD64=v3 go build -trimpath -ldflags "-s -w" -mod=mod -o calchash calchash.go
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -mod=mod -o calchash calchash.go

# windows
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 GOAMD64=v3 go build -trimpath -ldflags "-s -w" -mod=mod -o calchash.exe calchash.go
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -mod=mod -o calchash.exe calchash.go
```

## Usage
```
# compute
calchash -sha256 file.txt

# compute from stdin
echo "data" | calchash -sha256

# verify GNU-style list (requires digest)
calchash -sha256 -c checksums.txt

# verify BSD-style list (algorithm per line)
calchash -c hash.txt

# list supported digests
calchash -l
```

## Options (summary)
- `-b, --binary` read in binary mode.
- `-t, --text` read in text mode (default). On Windows, normalizes CRLF to LF.
- `-c, --check` read checksum lists and verify.
- `--tag` output BSD-style "ALGO (file) = digest".
- `-z, --zero` terminate lines with NUL and disable filename escaping; in `-c`,
  use NUL as the line separator and disable UTF-16LE list decoding.
- `--ignore-missing` skip missing files in check mode.
- `--quiet` do not print "OK" lines in check mode.
- `--status` no output; exit code indicates status (implies `--quiet`).
- `--strict` exit non-zero for any improperly formatted line.
- `-w, --warn` warn about improperly formatted lines.
- `-o, --output PATH` write output to PATH (`-` for stdout).
- `-a, --append` append to output file (requires `-o`).
- `-u, --utf8` sanitize output filenames as UTF-8 (invalid bytes -> replacement).
- `-l, --list` list supported digests.
- `-h, --help`, `-v, --version`.
- Digest flag is required unless `-c` is used with BSD-style lines.

Short options without arguments can be grouped (for example `-bwz`).

## Supported digests
Flags are accepted with a leading `-` (for example `-sha256`).
BSD tag names are shown in parentheses.

- `blake2b512` (BLAKE2B-512)
- `blake2s256` (BLAKE2S-256)
- `blake3` (BLAKE3)
- `md4` (MD4)
- `md5` (MD5)
- `md5-sha1` (MD5-SHA1)
- `ripemd`, `ripemd160`, `rmd160` (RIPEMD160)
- `sha1` (SHA1)
- `sha224` (SHA224)
- `sha256` (SHA256)
- `sha384` (SHA384)
- `sha512` (SHA512)
- `sha512-224` (SHA512-224)
- `sha512-256` (SHA512-256)
- `sha3-224` (SHA3-224)
- `sha3-256` (SHA3-256)
- `sha3-384` (SHA3-384)
- `sha3-512` (SHA3-512)
- `whirlpool` (WHIRLPOOL)

## Output formats
GNU style (default):
```
<hex>  <file>
<hex> *<file>     # when -b or when the list line uses '*'
```

BSD style (`--tag`):
```
ALGO (file) = <hex>
```

When `-z` is used, output lines end with NUL and filenames are not escaped.

## Check mode details
- `-c` reads checksum list files; with no files it reads stdin.
- Accepts both BSD and GNU formats:
  - BSD: `ALGO (file) = digest` (per-line algorithm).
  - GNU: `digest  file` or `digest *file` (binary marker `*`).
- If a digest flag is provided, GNU lines are checked with that digest.
  BSD lines always use the algorithm on the line.
- If no digest flag is provided, only BSD lines are accepted. GNU lines are
  reported as non-BSD and the run exits with a missing-digest error.
- Lines starting with `#` and blank lines are ignored.
- In check mode on Windows, a GNU `*` marker forces binary mode for that line;
  otherwise text mode is used. On non-Windows, text/binary are equivalent.
- UTF-8 BOM is supported. UTF-16LE BOM or heuristic decoding is supported
  unless `-z` is used.

## Filename escaping and encoding
- Filenames are escaped in GNU output unless `-z` is used.
- Escapes: `\\`, `\n`, `\r`, `\t`, `\0`, and octal `\ooo` for other control bytes.
- In check mode, GNU filenames are unescaped before opening.
- `-u, --utf8` replaces invalid UTF-8 bytes with U+FFFD in output only.

## Exit codes
- `0` success.
- `1` checksum mismatch in check mode.
- `2` trouble (I/O errors, invalid lines, missing digest option, etc).

## Examples
```
# verify a BSD-style list
calchash -c hash.txt

# verify a GNU list with an explicit digest
calchash -sha256 -c checksums.txt

# write SHA512 sums to a file
calchash -sha512 -o sums.txt file1.bin file2.bin

# append to an existing output file
calchash -sha512 -o sums.txt -a file3.bin
```
