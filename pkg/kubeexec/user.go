package kubeexec

import "strings"

// RootUser is the user commands run as when none is named.
const RootUser = "root"

// AsUser wraps a command to run as user in a container running as root
// (userns machines), with su: the command is unchanged for root or an empty
// user. Options come before the user name, as busybox's su requires (and
// util-linux's accepts); stdin goes through to the command.
func AsUser(user string, cmd []string) []string {
	if user == "" || user == RootUser {
		return cmd
	}
	quoted := make([]string, len(cmd))
	for i, arg := range cmd {
		quoted[i] = shellQuote(arg)
	}
	return []string{"su", "-s", "/bin/sh", user, "-c", strings.Join(quoted, " ")}
}

// shellQuote quotes a word for a POSIX shell.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
