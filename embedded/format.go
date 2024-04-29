package embedded

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/color"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/danielgtaylor/shorthand/v2"
	"github.com/spf13/viper"
	"golang.org/x/exp/maps"
	"golang.org/x/term"

	"github.com/eliukblau/pixterm/pkg/ansimage"
	"github.com/loicalleyne/restish/cli"
)

// FilteredRawJSONFormatter can apply JMESPath queries and can output prettyfied JSON
// and YAML output. If Stdout is a TTY, then colorized output is provided. The
// default formatter uses the `rsh-filter` and `rsh-output-format` configuration
// values to perform JMESPath queries and set JSON (default) or YAML output.
type FilteredRawJSONFormatter struct {
	tty   bool
	color bool
}

// NewDefaultFormatter creates a new formatted with autodetected TTY
// capabilities.
func NewFilteredRawJSONFormatter(tty, color bool) *FilteredRawJSONFormatter {
	return &FilteredRawJSONFormatter{
		tty:   tty,
		color: color,
	}
}

// filterData filters the current response using shorthand query and returns the
// result.
func (f *FilteredRawJSONFormatter) filterData(filter string, data map[string]any) (any, error) {
	keys := maps.Keys(data)
	sort.Strings(keys)
	found := strings.HasPrefix(filter, "*") || strings.HasPrefix(filter, "..") || strings.HasPrefix(filter, "{")
	if !found {
		for _, k := range keys {
			if strings.HasPrefix(filter, k) {
				if len(filter) > len(k) && filter[len(k)] == '{' {
					// Catch a common typo 'body{id}` vs `body.{id}`
					return nil, fmt.Errorf("expected '.' or '[' after '%s' but found %s", k, filter)
				}
				if len(filter) == len(k) || len(filter) > len(k) && (filter[len(k)] == '.' || filter[len(k)] == '[') {
					// Matches e.g. `body`, `body.`, `body[...]`, etc.
					found = true
					break
				}
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("filter must begin with one of '%v' and use '.' delimiters", strings.Join(keys, "', '"))
	}

	opts := shorthand.GetOptions{}
	// if enableVerbose {
	// 	opts.DebugLogger = LogDebug
	// }

	result, _, err := shorthand.GetPath(filter, data, opts)
	return result, err
}

func (f *FilteredRawJSONFormatter) formatRaw(data any) ([]byte, string, bool) {
	kind := reflect.ValueOf(data).Kind()
	lexer := ""

	if kind == reflect.String {
		dStr := data.(string)
		if len(dStr) != 0 && (dStr[0] == '{' || dStr[0] == '[') {
			// Looks like JSON to me!
			lexer = "json"
		}
		return []byte(dStr), lexer, true
	}

	if kind == reflect.Slice {
		scalars := true

		if d, ok := data.([]byte); ok {
			// Special case: binary data which should be represented by base64.
			encoded := make([]byte, base64.StdEncoding.EncodedLen(len(d)))
			base64.StdEncoding.Encode(encoded, d)
			return encoded, lexer, true
		}

		for _, item := range data.([]interface{}) {
			switch item.(type) {
			case nil, bool, int, int64, float64, string:
				// The above are scalars used by decoders
			default:
				scalars = false
			}
			if !scalars {
				break
			}
		}

		if scalars {
			var encoded []byte
			for _, item := range data.([]interface{}) {
				if item == nil {
					encoded = append(encoded, []byte("null\n")...)
				} else if f, ok := item.(float64); ok && f == float64(int64(f)) {
					// This is likely an integer from JSON that was loaded as a float64!
					// Prevent the use of scientific notation!
					encoded = append(strconv.AppendFloat(encoded, f, 'f', -1, 64), '\n')
				} else {
					encoded = append(encoded, []byte(fmt.Sprintf("%v\n", item))...)
				}
			}
			return encoded, lexer, true
		}
	}

	return nil, "", false
}

// nl prepends a new line to a slice of bytes.
func (f *FilteredRawJSONFormatter) nl(v []byte) []byte {
	result := append([]byte{'\n'}, v...)
	if result[len(result)-1] != '\n' {
		result = append(result, '\n')
	}
	return result
}

// formatAuto formats the response as a human-readable terminal display
// friendly format.
func (f *FilteredRawJSONFormatter) formatAuto(format string, resp cli.Response) ([]byte, error) {
	text := fmt.Sprintf("%s %d %s\n", resp.Proto, resp.Status, http.StatusText(resp.Status))

	headerNames := []string{}
	for k := range resp.Headers {
		headerNames = append(headerNames, k)
	}
	sort.Strings(headerNames)

	for _, name := range headerNames {
		text += name + ": " + resp.Headers[name] + "\n"
	}

	var err error
	var encoded []byte

	if f.color {
		encoded, err = cli.Highlight("http", []byte(text))
		if err != nil {
			return nil, err
		}
	} else {
		encoded = []byte(text)
	}

	ct := resp.Headers["Content-Type"]
	if resp.Body != nil && (ct == "image/png" || ct == "image/jpeg" || ct == "image/webp" || ct == "image/gif") {
		if b, ok := resp.Body.([]byte); ok {
			// This is likely an image. Let's display it if we can! Get the window
			// size, read and scale the image, and display it using unicode.
			w, h, err := term.GetSize(0)
			if err != nil {
				// Default to standard terminal size
				w, h = 80, 24
			}

			image, err := ansimage.NewScaledFromReader(bytes.NewReader(b), h*2, w*1, color.Transparent, ansimage.ScaleModeFit, ansimage.NoDithering)
			if err == nil {
				return append(encoded, f.nl([]byte(image.Render()))...), nil
			} else {
				cli.LogWarning("Unable to display image: %v", err)
			}
		}
	}

	// if b, ok := printable(resp.Body); ok {
	// 	return append(encoded, f.nl(b)...), nil
	// }

	if reflect.ValueOf(resp.Body).Kind() != reflect.Invalid {
		b, err := cli.MarshalShort(format, true, resp.Body)
		if err != nil {
			return nil, err
		}

		if f.color {
			// Uncomment to debug lexer...
			// iter, err := ReadableLexer.Tokenise(&chroma.TokeniseOptions{State: "root"}, string(readable))
			// if err != nil {
			// 	panic(err)
			// }
			// for _, token := range iter.Tokens() {
			// 	fmt.Println(token.Type, token.Value)
			// }

			if b, err = cli.Highlight(format, b); err != nil {
				return nil, err
			}
		}

		return append(encoded, f.nl(b)...), nil
	}

	// No body to display.
	return encoded, nil
}

// Format will filter, prettify, colorize and output the data.
func (f *FilteredRawJSONFormatter) Format(resp cli.Response) error {
	var err error
	outFormat := "json"
	filter := viper.GetString("rsh-filter")

	// Special case: raw response output mode. The response wasn't decoded so we
	// have a bunch of bytes and the user asked for raw output, so just write it.
	// This enables completely bypassing decoding and file downloads.
	if filter == "" && (viper.GetBool("rsh-raw") || !f.tty) {
		if b, ok := resp.Body.([]byte); ok {
			cli.Stdout.Write(b)
			return nil
		}
	}

	// // Output defaults. Bypass by passing output options.
	// if outFormat == "auto" {
	// 	if f.tty {
	// 		// Live terminal: readable output
	// 		outFormat = "readable"
	// 	} else {
	// 		// Redirected (e.g. file or pipe) output: JSON for easier scripting.
	// 		outFormat = "json"
	// 	}
	// }
	outFormat = "json"
	if !f.tty && filter == "" {
		filter = "body"
	}

	var data any = resp.Map()

	// Filter the data if requested via shorthand query.
	if filter != "" && filter != "@" {
		// Optimization: select just the body
		if filter == "body" {
			data = resp.Body
		} else {
			data, err = f.filterData(filter, data.(map[string]any))
			if err != nil || data == nil {
				return err
			}
		}
	}

	// Encode to the requested output format using nice formatting.
	var encoded []byte
	// var lexer string
	// handled := false

	// Special case: raw output with scalars or an array of scalars. This enables
	// shell-friendly output without quotes or with each item on its own line
	// which is easy to use in e.g. bash `for` loops.
	// if viper.GetBool("rsh-raw") {
	// 	var ok bool
	// 	if encoded, lexer, ok = f.formatRaw(data); ok {
	// 		handled = true
	// 	}
	// }

	// if !handled {
	// 	if (f.tty && filter == "") || (outFormat == "readable" && (filter == "" || filter == "@")) {
	// 		encoded, err = f.formatAuto(outFormat, resp)
	// 	} else {
	// 		encoded, err = cli.MarshalShort(outFormat, true, data)
	// 		lexer = outFormat
	// 	}
	// }
	encoded, err = cli.MarshalShort(outFormat, false, data)
	if err != nil {
		return err
	}

	// Only colorize if we have a lexer and color is enabled.
	// if f.color && lexer != "" {
	// 	encoded, err = cli.Highlight(lexer, encoded)
	// 	if err != nil {
	// 		return err
	// 	}
	// }

	// Make sure we end with a newline, otherwise things won't look right
	// in the terminal.
	// if len(encoded) > 0 && encoded[len(encoded)-1] != '\n' {
	// 	encoded = append(encoded, '\n')
	// }

	cli.Stdout.Write(encoded)

	return nil
}
