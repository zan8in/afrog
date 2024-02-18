package catalog

// Catalog is a poc catalog helper implementation
type Catalog struct {
	pocsDirectory string
}

// New creates a new Catalog structure using provided input items
func New(directory string) *Catalog {
	catalog := &Catalog{pocsDirectory: directory}
	return catalog
}
