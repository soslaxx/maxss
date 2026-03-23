package main

import (
	"fmt"
	"os"

	"maxss/internal/app"
)

func main() {
	if err := app.Run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "maxss error: %v\n", err)
		os.Exit(1)
	}
}
