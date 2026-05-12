package randomutils

import (
	"fmt"
	"math/big"
	"math/rand"
	"sync"
	"unsafe"
)

// WeightedRandomChoice describes a weighted, randomly selectable object for use with a WeightedRandomChooser.
type WeightedRandomChoice[T any] struct {
	// Data describes the wrapped data that a WeightedRandomChooser should return when making a random WeightedRandomChoice selection.
	Data T

	// weight describes a value indicating the likelihood of this WeightedRandomChoice to appear in a random selection.
	// Its probability is calculated as current weight / all weights in a WeightedRandomChooser.
	weight *big.Int

	// hitCount describes the number of times this WeightedRandomChoice has been selected.
	hitCount uint64
	uniqueId uint32
}

// NewWeightedRandomChoice creates a WeightedRandomChoice with the given underlying data and weight to use when added to a WeightedRandomChooser.
func NewWeightedRandomChoice[T any](data T, weight *big.Int) *WeightedRandomChoice[T] {
	return &WeightedRandomChoice[T]{
		Data:     data,
		weight:   new(big.Int).Set(weight),
		uniqueId: 0, // Default uniqueId for compatibility
	}
}

// NewWeightedRandomChoiceWithId creates a WeightedRandomChoice with the given underlying data, weight, and uniqueId.
func NewWeightedRandomChoiceWithId[T any](data T, weight *big.Int, uniqueId uint32) *WeightedRandomChoice[T] {
	return &WeightedRandomChoice[T]{
		Data:     data,
		weight:   new(big.Int).Set(weight),
		uniqueId: uniqueId,
	}
}

// WeightedRandomChooser takes a series of WeightedRandomChoice objects which wrap underlying data, and returns one
// of the weighted options randomly.
type WeightedRandomChooser[T any] struct {
	// choices describes the weighted choices from which the chooser will randomly select.
	choices []*WeightedRandomChoice[T]

	// totalWeight describes the sum of all weights in choices. This is stored here so it does not need to be
	// recomputed.
	totalWeight *big.Int

	averageExecutionTime float64

	// randomProvider offers a source of random data.
	randomProvider *rand.Rand
	// randomProviderLock is a lock to offer thread safety to the random number generator.
	randomProviderLock *sync.Mutex
}

// NewWeightedRandomChooser creates a WeightedRandomChooser with a new random provider and mutex lock.
func NewWeightedRandomChooser[T any]() *WeightedRandomChooser[T] {
	// return NewWeightedRandomChooserWithRand[T](rand.New(rand.NewSource(time.Now().Unix())), &sync.Mutex{})
	return NewWeightedRandomChooserWithRand[T](rand.New(rand.NewSource(1)), &sync.Mutex{})
}

// NewWeightedRandomChooserWithRand creates a WeightedRandomChooser with the provided random provider and mutex lock to be acquired when using it.
func NewWeightedRandomChooserWithRand[T any](randomProvider *rand.Rand, randomProviderLock *sync.Mutex) *WeightedRandomChooser[T] {
	return &WeightedRandomChooser[T]{
		choices:            make([]*WeightedRandomChoice[T], 0),
		randomProvider:     randomProvider,
		randomProviderLock: randomProviderLock,
		totalWeight:        big.NewInt(0),
	}
}

// ChoiceCount returns the count of choices added to this provider.
func (c *WeightedRandomChooser[T]) ChoiceCount() int {
	return len(c.choices)
}

// add a function to print the choices
func (c *WeightedRandomChooser[T]) PrintChoices() {
	fmt.Println("Printing WeightedRandomChooser choices:")
	for _, choice := range c.choices {
		fmt.Printf("choice data: %v\n", choice.Data)
		fmt.Printf("choice weight: %v\n", choice.weight)
		fmt.Printf("choice uniqueId: %v\n", choice.uniqueId)
		fmt.Println()
	}
}

// RemoveChoiceByUniqueId removes a choice with the specified uniqueId from the chooser
func (c *WeightedRandomChooser[T]) RemoveChoiceByUniqueId(uniqueId uint32) bool {
	// Acquire our lock during the duration of this method.
	c.randomProviderLock.Lock()
	defer c.randomProviderLock.Unlock()

	// Find and remove the choice with matching uniqueId
	for i, choice := range c.choices {
		if choice.uniqueId == uniqueId {
			// Subtract the weight from total
			c.totalWeight = new(big.Int).Sub(c.totalWeight, choice.weight)
			// Remove the choice from slice
			c.choices = append(c.choices[:i], c.choices[i+1:]...)
			return true
		}
	}
	return false
}

// AddChoices adds weighted choices to the WeightedRandomChooser, allowing for future random selection.
func (c *WeightedRandomChooser[T]) AddChoices(choices ...*WeightedRandomChoice[T]) {
	// Acquire our lock during the duration of this method.
	// c.randomProviderLock.Lock()
	// defer c.randomProviderLock.Unlock()

	// Loop for each choice to add to sum all weights
	// for _, choice := range choices {
	// 	c.totalWeight = new(big.Int).Add(c.totalWeight, choice.weight)
	// }

	// // Add to choices to our array
	// c.choices = append(c.choices, choices...)
	for _, choice := range choices {
		// fmt.Println("Adding choice: ", choice.Data)
		c.AddChoice(choice)
	}
}

func (c *WeightedRandomChooser[T]) AddChoice(choice *WeightedRandomChoice[T]) {
	// Acquire our lock during the duration of this method.
	c.randomProviderLock.Lock()
	defer c.randomProviderLock.Unlock()

	// Loop for each choice to add to sum all weights
	c.totalWeight = new(big.Int).Add(c.totalWeight, choice.weight)

	// weight := INITIAL_WEIGHT // new choice never fuzzed
	// // Ityfuzz  weight ~ 3

	// choice.hitCount = 0

	// Add to choices to our array
	c.choices = append(c.choices, choice)
}

// Choose selects a random weighted item from the WeightedRandomChooser, or returns an error if one occurs.
func (c *WeightedRandomChooser[T]) Choose() (*T, error) {
	// If we have no choices or 0 total weight, return nil.
	if len(c.choices) == 0 || c.totalWeight.Cmp(big.NewInt(0)) == 0 {
		return nil, fmt.Errorf("could not return a weighted random choice because no choices exist with non-zero weights")
	}

	// Acquire our lock during the duration of this method.
	c.randomProviderLock.Lock()
	defer c.randomProviderLock.Unlock()

	// We'll want to randomly select a position in our total weight that will determine which item to return.
	// If our total weight fits in an int64 and int is an int64 on this architecture, this is a quick calculation.
	// If it's a larger number, we calculate the position with a bit more work.
	var selectedWeightPosition *big.Int
	if c.totalWeight.IsInt64() && unsafe.Sizeof(0) == 64 {
		selectedWeightPosition = big.NewInt(int64(c.randomProvider.Intn(int(c.totalWeight.Int64()))))
	} else {
		// Next we'll determine how many bits/bytes are needed to represent our random value
		bitLength := c.totalWeight.BitLen()
		byteLength := bitLength / 8
		unusedBits := bitLength % 8
		if unusedBits != 0 {
			byteLength += 1
		}

		// Generate the number of bytes needed.
		randomData := make([]byte, byteLength)
		_, err := c.randomProvider.Read(randomData)
		if err != nil {
			return nil, err
		}

		// If we have unused bits, we'll want to mask/clear them out (big.Int uses big endian for byte parsing)
		randomData[0] = randomData[0] & (byte(0xFF) >> unusedBits)

		// We use these bytes to get an index in [0, total weight] to use to return an item.
		// TODO: this may be the correct bit size but have too many bits set to actually be in range, so we perform
		//  modulus division to wrap around. This isn't fully uniform in distribution, we should consider revisiting this.
		selectedWeightPosition = new(big.Int).SetBytes(randomData)
		selectedWeightPosition = new(big.Int).Mod(selectedWeightPosition, c.totalWeight)
	}

	// Loop for each item
	for _, choice := range c.choices {
		// If our selected weight position is in range for this item, return it
		if selectedWeightPosition.Cmp(choice.weight) < 0 {
			return &choice.Data, nil
		}

		// Subtract the choice weight from the current position, and go to the next item to see if it's in range.
		selectedWeightPosition = new(big.Int).Sub(selectedWeightPosition, choice.weight)
	}

	return nil, fmt.Errorf("could not obtain a weighted random choice, selected position does not exist")
}
