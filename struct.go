package main

import (
	"github.com/fatih/color"
)

type record struct {
	Exchange exchangeFunc
	Handler handlerFunc
	Alias *string
	Desc string
}

type rttCategory struct {
	Rating string
	Desc string
	Color *color.Color
}

type sshfpAlgorithm struct {
	Name string
}

type sshfpType struct {
	Name string
}

type priorityLabel struct {
	Name string
}

