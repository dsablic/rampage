module example.com/buildinfo

go 1.22

require example.com/greet v0.1.0

replace example.com/greet v0.1.0 => ./greet
