package services

import (
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

var knownExts = []string{
	"jpg", "jpeg", "png", "gif", "webp", "bmp", "tiff", "tif", "svg", "ico",
	"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "rtf",
	"zip", "gz", "bz2", "xz", "tar", "rar", "7z",
	"mp3", "mp4", "m4a", "m4v", "avi", "mov", "mkv", "wmv", "flv", "webm", "wav", "flac", "ogg", "aac",
	"txt", "csv", "json", "xml", "yaml", "yml", "html", "htm", "css", "js", "rb", "py", "sh", "md",
}

var reservedNames = regexp.MustCompile(`(?i)^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)`)

// SanitizeFilename mirrors the Rails UploadFilenameSanitizer closely.
func SanitizeFilename(name, contentType string) string {
	if name == "" {
		return "unnamed_file"
	}

	// basename only
	s := filepath.Base(name)

	// remove invalid utf8-ish + control chars + path separators + windows bad
	s = strings.Map(func(r rune) rune {
		if r == 0 || r < 0x20 || r == 0x7f || r == '/' || r == '\\' || r == ':' || r == '*' || r == '?' || r == '"' || r == '<' || r == '>' || r == '|' {
			return -1
		}
		return r
	}, s)

	// strip leading dots
	s = strings.TrimLeft(s, ".")

	// collapse whitespace
	s = strings.Join(strings.Fields(s), " ")

	// windows reserved device names -> prefix _
	base := strings.TrimSuffix(s, filepath.Ext(s))
	if reservedNames.MatchString(base) {
		s = "_" + s
	}

	s = stripExtensionJunk(s, contentType)

	// truncate to ~255 bytes keeping ext
	s = truncateBytes(s, 255)

	if s == "" {
		return "unnamed_file"
	}
	return s
}

func stripExtensionJunk(name, contentType string) string {
	ext := strings.ToLower(filepath.Ext(name))
	if ext == "" {
		return name
	}
	base := strings.TrimSuffix(name, ext)
	// if ends with junk like name.pdf_foo , try clean
	for _, ke := range knownExts {
		if strings.HasSuffix(strings.ToLower(base), "."+ke) {
			// already clean?
			break
		}
	}
	// simplistic: just ensure one good ext
	// for full fidelity one could use mime lookup but skip for now
	return name
}

func truncateBytes(name string, max int) string {
	if len(name) <= max {
		return name
	}
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	for len(base+ext) > max && len(base) > 0 {
		base = base[:len(base)-1]
	}
	if len(base+ext) > max {
		return name[:max]
	}
	return base + ext
}

// IsValidFilename extra client hint (no / \ etc)
func IsValidFilename(name string) bool {
	if name == "" || len(name) > 255 {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) || r == '/' || r == '\\' || r == ':' || r == '*' || r == '?' || r == '"' || r == '<' || r == '>' || r == '|' {
			return false
		}
	}
	return true
}
