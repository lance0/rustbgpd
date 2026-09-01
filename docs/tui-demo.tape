# rustbgpd — README route-explorer demo
#
# Rendered with VHS (https://github.com/charmbracelet/vhs):
#   docker compose -f examples/docker-compose/docker-compose.yml up -d --build
#   PATH="$HOME/go/bin:$HOME/.local/bin:$PATH" vhs docs/tui-demo.tape
#
# The checked-in Compose example provides the real daemon, FRR peer, public
# test-only credential, and deterministic IPv4/IPv6 sample routes.

Output "docs/images/tui-demo.gif"

Set Width 1395
Set Height 728
Set FontSize 15
Set Padding 16
Set Theme "Catppuccin Mocha"
Set CursorBlink false
Set Framerate 15

Require docker

Hide
Type "clear"
Enter
Sleep 500ms
Show

Type@30ms "cd examples/docker-compose && docker compose exec rustbgpd rbgp -s http://127.0.0.1:50051 top"
Enter
Sleep 3500ms

Enter
Sleep 1s
Type "r"
Sleep 3s

Type "v"
Sleep 3s
Type "/"
Type@40ms "192.168.1.0/24"
Enter
Sleep 5s

Type "f"
Sleep 4s
Type "f"
Sleep 1s

Type "v"
Sleep 3s
Type "v"
Sleep 3s
Type "v"
Sleep 3s

Down
Sleep 500ms
Enter
Sleep 4s
Escape
Sleep 4s

Hide
Type "q"
Sleep 500ms
