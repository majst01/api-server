package store

type Identifyable interface {
	GetUuid() string
	GetProject() string
}

type Store[I Identifyable] interface {
	Get(string) (I, error)
	Set(I) error
	List(project *string) ([]I, error)
	Delete(string) (I, error)
}
