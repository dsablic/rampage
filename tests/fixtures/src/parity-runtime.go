// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type config struct {
	limit  int64
	factor int64
}

type state struct {
	total         int64
	checkpoint    int64
	hasCheckpoint bool
	applied       uint32
	rejected      uint32
}

type command struct {
	name  string
	units int64
}

func parseUnits(text string) (int64, error) {
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse units %q: %w", text, err)
	}
	if value < 0 || value > 10000 {
		return 0, errors.New("units outside 0..10000")
	}
	return value, nil
}

func parseConfig(text string) (config, error) {
	var cfg config
	if len(text) > 96 {
		return cfg, errors.New("config too long")
	}
	seen := make(map[string]bool)
	for _, field := range strings.Split(text, ";") {
		name, raw, ok := strings.Cut(field, "=")
		if !ok || seen[name] {
			return config{}, errors.New("missing separator or duplicate config field")
		}
		value, err := parseUnits(raw)
		if err != nil {
			return config{}, fmt.Errorf("config field %q: %w", name, err)
		}
		if value == 0 {
			return config{}, errors.New("config values must be positive")
		}
		switch name {
		case "limit":
			cfg.limit = value
		case "factor":
			cfg.factor = value
		default:
			return config{}, fmt.Errorf("unknown config field %q", name)
		}
		seen[name] = true
	}
	if !seen["limit"] || !seen["factor"] {
		return config{}, errors.New("limit and factor required")
	}
	return cfg, nil
}

func parseCommand(text string) (command, error) {
	if len(text) > 96 {
		return command{}, errors.New("command too long")
	}
	if text == "checkpoint" || text == "restore" {
		return command{name: text}, nil
	}
	name, raw, ok := strings.Cut(text, ":")
	if !ok || (name != "add" && name != "remove") {
		return command{}, errors.New("unknown command")
	}
	units, err := parseUnits(raw)
	if err != nil {
		return command{}, fmt.Errorf("command %q: %w", name, err)
	}
	return command{name: name, units: units}, nil
}

func applyCommand(current *state, cfg config, cmd command) error {
	next := current.total
	switch cmd.name {
	case "add":
		next += cmd.units * cfg.factor
	case "remove":
		next -= cmd.units * cfg.factor
	case "checkpoint":
		current.checkpoint = next
		current.hasCheckpoint = true
	case "restore":
		if !current.hasCheckpoint {
			return errors.New("no checkpoint")
		}
		next = current.checkpoint
	default:
		return errors.New("invalid decoded command")
	}
	if next < 0 || next > cfg.limit {
		return errors.New("total outside configured limit")
	}
	current.total = next
	current.applied++
	return nil
}

func runPipeline(text string, commands []string) (state, error) {
	var current state
	if len(commands) > 16 {
		return current, errors.New("more than 16 commands")
	}
	cfg, err := parseConfig(text)
	if err != nil {
		return current, fmt.Errorf("pipeline config: %w", err)
	}
	for _, text := range commands {
		cmd, err := parseCommand(text)
		if err != nil {
			current.rejected++
			continue
		}
		if err := applyCommand(&current, cfg, cmd); err != nil {
			current.rejected++
		}
	}
	return current, nil
}

var parityGoState state
var parityGoFailed bool

func main() {
	text := "limit=40;factor=3"
	commands := []string{"add:5", "checkpoint", "remove:2", "add:20", "restore", "remove:1", "unknown:2"}
	if len(os.Args) > 1 {
		text = os.Args[1]
		commands = os.Args[2:]
	}
	result, err := runPipeline(text, commands)
	parityGoState = result
	parityGoFailed = err != nil
}
