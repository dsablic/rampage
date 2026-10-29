// A tiny module with one replaced dependency, so its embedded build info carries path, mod, dep, => and build
// lines.
package main

import "example.com/greet"

func main() {
	println(greet.Hello())
}
