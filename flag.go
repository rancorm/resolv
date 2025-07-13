package main

import (
	"flag"
)

func init() {
	const previousLine = "\x1B[1F"

	flag.BoolVar(&recursionLookup, "recursion", true, "Recursion lookup")
	flag.BoolVar(&listRecords, "records", false, "List record types")
	flag.BoolVar(&recursiveCNAMELookup, "recursive", false, "Recursive CNAME lookup")
	flag.StringVar(&targetServer, "server", "", "Target server")
	flag.StringVar(&targetServer, "s", "", previousLine)
	flag.BoolVar(&arpaLookup, "arpa", false, "Reverse lookup")
	flag.BoolVar(&listRatings, "ratings", false, "List ratings")
	flag.BoolVar(&showHelp, "help", false, "This help menu")
	flag.BoolVar(&showHelp, "h", false, "")
}
