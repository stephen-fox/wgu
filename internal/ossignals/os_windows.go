package ossignals

import (
	"os"
)

func QuitSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}
