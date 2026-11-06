module example.com/shop

go 1.23

require (
	example.com/localfork v0.1.0
	example.com/patched v1.0.0
	example.com/tidyup v1.4.0
)

require (
	example.com/colorize v0.3.1 // indirect
	example.org/textwrap v0.9.0 // indirect
)

replace example.com/localfork => ../localfork

replace example.com/patched v1.0.0 => example.com/patched v1.0.2
