// Fixture for Go runtime type metadata: named structs with embedded and unexported fields, an interface with a
// method set, a named map with methods, and composite field types. Kept small: no fmt.
package main

type Base struct {
	ID   uint32
	Tags []string
}

type Inner struct {
	Count uint64
	Ratio float64
}

type Record struct {
	Base
	Name    string
	flags   uint16
	Inner   Inner
	Next    *Record
	Values  map[string]int32
	Buckets [4]uint8
	Notify  chan<- int
	Hook    func(int, string) (bool, error)
	Any     interface{}
	Shape   Shape
}

type Shape interface {
	Area() float64
	Name() string
}

type Square struct{ Side float64 }

func (s Square) Area() float64 { return s.Side * s.Side }
func (s Square) Name() string   { return "square" }

type Index map[string]*Record

func (i Index) Len() int { return len(i) }

type Error struct{ Code int }

func (e *Error) Error() string { return "error" }

var sink []interface{}

//go:noinline
func keep(value interface{}) { sink = append(sink, value) }

func main() {
	record := &Record{Name: "a", Shape: Square{Side: 2}}
	record.flags = 1
	keep(record)
	keep(Index{"a": record})
	var err error = &Error{Code: 1}
	keep(err)
	var shape Shape = Square{Side: 1}
	keep(shape)
	println(len(sink), shape.Area(), Index{}.Len())
}
