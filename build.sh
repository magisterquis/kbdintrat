function build {
        if [ -z "$1" ]; then
                echo "Usage: build name" >&2
                return 1
        fi
        go build -v -i -ldflags "-X main.ImplantID=$1" -o kbdintrat.$1
}
