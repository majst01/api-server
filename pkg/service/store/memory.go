package store

import (
	"fmt"
	"sync"
)

type memoryStore[I Identifyable] struct {
	sync.Mutex
	store map[string]I
}

func NewMemoryStore[I Identifyable](initial map[string]I) *memoryStore[I] {
	if initial == nil {
		initial = make(map[string]I)
	}
	return &memoryStore[I]{
		store: initial,
	}
}

func (m *memoryStore[I]) Get(uuid string) (I, error) {
	m.Lock()
	defer m.Unlock()
	i, ok := m.store[uuid]
	if ok {
		return i, nil
	}
	return i, fmt.Errorf("no entity with uuid:%q found", uuid)
}
func (m *memoryStore[I]) Set(i I) error {
	m.Lock()
	defer m.Unlock()
	m.store[i.GetUuid()] = i
	return nil
}
func (m *memoryStore[I]) List(project *string) ([]I, error) {
	m.Lock()
	defer m.Unlock()
	result := []I{}
	for _, i := range m.store {
		if project != nil {
			if i.GetProject() == *project {
				result = append(result, i)
			}
			continue
		}
		result = append(result, i)
	}
	return result, nil
}
func (m *memoryStore[I]) Delete(uuid string) (I, error) {
	m.Lock()
	defer m.Unlock()
	i, ok := m.store[uuid]
	if !ok {
		return i, fmt.Errorf("no entity with uuid:%q found", uuid)
	}
	delete(m.store, uuid)
	return i, nil
}
