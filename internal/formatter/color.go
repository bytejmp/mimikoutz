package formatter

import "os"

var (
	ColorReset   = "\033[0m"
	ColorRed     = "\033[91m"
	ColorGreen   = "\033[92m"
	ColorYellow  = "\033[93m"
	ColorMagenta = "\033[95m"
	ColorCyan    = "\033[96m"
	ColorGray    = "\033[90m"
	ColorBold    = "\033[1m"
	ColorBgRed   = "\033[41m"
	ColorWhite   = "\033[97m"
)

var UseColor = true

func init() {
	if os.Getenv("NO_COLOR") != "" {
		DisableColor()
	}
}

func DisableColor() {
	UseColor = false
	ColorReset = ""
	ColorRed = ""
	ColorGreen = ""
	ColorYellow = ""
	ColorMagenta = ""
	ColorCyan = ""
	ColorGray = ""
	ColorBold = ""
	ColorBgRed = ""
	ColorWhite = ""
}
