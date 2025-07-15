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
