package agent

import "math/rand"

// See: https://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-go

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func GenerateICEUfrag() string {
	return randStringRunes(16)[0:13] + "wnb" // It will be better to generate fully random, but we want to see "our sign" in the traffic :)
}

func GenerateICEPwd() string {
	return randStringRunes(32)
}
