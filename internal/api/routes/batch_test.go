package routes

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestChunkSlice(t *testing.T) {
	// 100 items, batch size 50 → 2 chunks
	items := make([]int, 100)
	for i := range items {
		items[i] = i
	}
	chunks := chunkSlice(items, 50)
	require.Len(t, chunks, 2)
	require.Len(t, chunks[0], 50)
	require.Len(t, chunks[1], 50)
	require.Equal(t, 0, chunks[0][0])
	require.Equal(t, 99, chunks[1][49])

	// 0 items → 0 chunks
	require.Empty(t, chunkSlice([]int{}, 50))

	// 3 items, batch size 50 → 1 chunk
	require.Len(t, chunkSlice([]int{1, 2, 3}, 50), 1)

	// 101 items, batch size 50 → 3 chunks (50, 50, 1)
	items101 := make([]int, 101)
	chunks101 := chunkSlice(items101, 50)
	require.Len(t, chunks101, 3)
	require.Len(t, chunks101[0], 50)
	require.Len(t, chunks101[1], 50)
	require.Len(t, chunks101[2], 1)
}
