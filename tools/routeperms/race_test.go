//go:build race

package main

func init() { skipUnderRace = true }
