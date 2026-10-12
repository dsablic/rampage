// A tiny stripped-Go fixture: gopclntab must still yield main.main and main.greet.
package main

import (
	"fmt"
	"os"
)

//go:noinline
func greet(name string) string {
	return fmt.Sprintf("rampage fixture greeting for %s", name)
}

//go:noinline
func shout(message string) string {
	return message + "!"
}

func main() {
	who := "go"
	if len(os.Args) > 1 {
		who = os.Args[1]
	}
	fmt.Println(shout(greet(who)))
}
