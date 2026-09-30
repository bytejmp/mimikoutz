package main

import "fmt"

const banner = `
    /\_/\
   ( ^.^ )    mimikoutz v1.0
    > ^ <     "Tame the chaos, own the hash"
   /|   |\
  (_|   |_)   /*** Clean. Dedup. Dominate. ***/

`

func printBanner() {
	fmt.Fprint(stderr, banner)
}
