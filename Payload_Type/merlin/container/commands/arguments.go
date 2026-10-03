/*
Merlin is a post-exploitation command and control framework.

This file is part of Merlin.
Copyright (C) 2023  Russel Van Tuyl

Merlin is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as
published by the Free Software Foundation, either version 3 of the License, or any later version.

Merlin is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with Merlin.  If not, see <http://www.gnu.org/licenses/>.
*/

package commands

import (
	"fmt"
	"strings"
)

// splitCommandLineArguments splits a Mythic argument string into argv values.
// Double quotes group whitespace into one argument and are removed before the
// values are sent to the agent. Backslashes are only special immediately before
// a double quote, matching the argv behavior used by Windows process creation.
func splitCommandLineArguments(input string) ([]string, error) {
	var args []string

	for len(input) > 0 {
		input = strings.TrimLeft(input, " \t")
		if input == "" {
			break
		}

		arg, rest, err := readCommandLineArgument(input)
		if err != nil {
			return nil, err
		}

		args = append(args, arg)
		input = rest
	}

	return args, nil
}

func readCommandLineArgument(input string) (string, string, error) {
	var arg strings.Builder
	inQuote := false
	slashes := 0

	appendSlashes := func(count int) {
		for i := 0; i < count; i++ {
			arg.WriteByte('\\')
		}
	}

	for i := 0; i < len(input); i++ {
		c := input[i]

		switch c {
		case ' ', '\t':
			if !inQuote {
				appendSlashes(slashes)
				return arg.String(), input[i+1:], nil
			}
		case '"':
			appendSlashes(slashes / 2)
			if slashes%2 == 0 {
				if inQuote && i+1 < len(input) && input[i+1] == '"' {
					arg.WriteByte('"')
					i++
				} else {
					inQuote = !inQuote
				}
			} else {
				arg.WriteByte('"')
			}
			slashes = 0
			continue
		case '\\':
			slashes++
			continue
		}

		appendSlashes(slashes)
		slashes = 0
		arg.WriteByte(c)
	}

	appendSlashes(slashes)
	if inQuote {
		return "", "", fmt.Errorf("unterminated double quote in arguments")
	}

	return arg.String(), "", nil
}
