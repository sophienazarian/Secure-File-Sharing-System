package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	"errors"
	"strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	// var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	// dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})

	Describe("InitUser", func() {

		Specify("Make two of same username", func() {
			userlib.DebugMsg("Initializing user Alice twice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Try to get that user")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Make user with empty username", func() {
			userlib.DebugMsg("Initializing user Alice twice")
			alice, err = client.InitUser(emptyString, defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Make user with empty password", func() {
			userlib.DebugMsg("Initializing user Alice twice")
			alice, err = client.InitUser("alice", emptyString)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Try to get that user")
			alice, err = client.GetUser("alice", emptyString)
			Expect(err).To(BeNil())
		})

		Specify("Make user with empty password", func() {
			userlib.DebugMsg("Initializing user Alice twice")
			alice, err = client.InitUser("alice", "!@#$%^&*()")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Try to get that user")
			alice, err = client.GetUser("alice", "!@#$%^&*()")
			Expect(err).To(BeNil())
		})

		Specify("Make two users with same password", func() {
			userlib.DebugMsg("Initializing users Alice and Bob with different passwords")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			alice, err = client.InitUser("Bob", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Try to make a user with the same username as a deleted user", func() {
			userlib.DebugMsg("Initializing user Alice")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DatastoreClear()

			userlib.DebugMsg("Initializing user Alice again")
			alice, err = client.GetUser("Bob", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Try to make a user with the same username as a tampered user", func() {
			userlib.DebugMsg("Initializing user Alice")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			m := userlib.DatastoreGetMap()
			for key := range m {
				m[key] = []byte("Haha got you")
			}

			userlib.DebugMsg("Initializing user Alice again")
			alice, err = client.GetUser("Bob", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

	})

	Describe("GetUser", func() {

		Specify("Unused username", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting non initialized user.")
			_, err = client.GetUser("bob", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Bad credentials", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice with wrong password.")
			_, err = client.GetUser("alice", "wrong password")
			Expect(err).ToNot(BeNil())
		})

		Specify("Get compromised user", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("tampering with user struct")
			datastoreMap := userlib.DatastoreGetMap()
			for key := range datastoreMap {
				userlib.DatastoreSet(key, []byte("tampered"))
			}
			_, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Multiple device stay updated", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing first instance of Alice.")
			alice, err := client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing second instance of Alice.")
			alicePhone, err := client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing third instance of Alice.")
			aliceLaptop, err := client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Stroring file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice2 can still load the file.")
			data, err := alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())

			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Storing file %s with content: %s", aliceFile, contentTwo)
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))

			userlib.DebugMsg("Alice3 appending file")
			err = aliceLaptop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo + contentThree)))
		})
	})

	Describe("StoreFile", func() {

		Specify("Diff + same users store same filename", func() {
			userlib.DebugMsg("Initializing users Alice and Bob with same passwords")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			alice, err = client.InitUser("Bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Get users Alice and Bob with same passwords")
			alice, err = client.GetUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.GetUser("Bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Both store same file")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			err = bob.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Both repeat store same file")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			err = bob.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
		})

		Specify("Store, tamper with file, store on top", func() {
			userlib.DebugMsg("Initializing users Alice and Bob with same passwords")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Get user Alice")
			alice, err = client.GetUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Screenshotting Datastore")
			v1 := userlib.DatastoreGetMap()
			v1Screenshot := make(map[userlib.UUID][]byte)
			for k, v := range v1 {
				v1Screenshot[k] = v
			}

			userlib.DebugMsg("Store file")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			targets := make([]userlib.UUID, 0)
			v2 := userlib.DatastoreGetMap()
			for key := range v2 {
				_, ok := v1Screenshot[key]
				if !ok {
					targets = append(targets, key)
				}
			}

			for _, target := range targets {
				userlib.DatastoreSet(target, []byte("trolololol"))
			}

			userlib.DebugMsg("Repeat store same file")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).ToNot(BeNil())
		})

		Specify("Store, tamper with user, store on top", func() {
			userlib.DebugMsg("Initializing users Alice with same password")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Get user Alice")
			alice, err = client.GetUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Screenshotting Datastore")
			v1 := userlib.DatastoreGetMap()
			v1Screenshot := make(map[userlib.UUID][]byte)
			for k, v := range v1 {
				v1Screenshot[k] = v
			}

			userlib.DebugMsg("Store file")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			targets := make([]userlib.UUID, 0)
			v2 := userlib.DatastoreGetMap()
			for key := range v2 {
				_, ok := v1Screenshot[key]
				if ok {
					targets = append(targets, key)
				}
			}

			for _, target := range targets {
				userlib.DatastoreSet(target, []byte("trolololol"))
			}

			userlib.DebugMsg("Repeat store same file")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).ToNot(BeNil())
		})

		Specify("Store, tamper with user, store different file", func() {
			userlib.DebugMsg("Initializing users Alice with same password")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Get user Alice")
			alice, err = client.GetUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Screenshotting Datastore")
			v1 := userlib.DatastoreGetMap()
			v1Screenshot := make(map[userlib.UUID][]byte)
			for k, v := range v1 {
				v1Screenshot[k] = v
			}

			userlib.DebugMsg("Store file")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			targets := make([]userlib.UUID, 0)
			v2 := userlib.DatastoreGetMap()
			for key := range v2 {
				_, ok := v1Screenshot[key]
				if ok {
					targets = append(targets, key)
				}
			}

			for _, target := range targets {
				userlib.DatastoreSet(target, []byte("trolololol"))
			}

			userlib.DebugMsg("Store diff file")
			err = alice.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())
		})
	})

	Describe("LoadFile", func() {

		Specify("File does not exist", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Loading file that doesnt exist")
			_, err = alice.LoadFile("doesntexist")
			Expect(err).ToNot(BeNil())
		})

		Specify("Stores file, tampers with blob, and loads file", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Screenshotting Datastore")
			v1 := userlib.DatastoreGetMap()
			v1Screenshot := make(map[userlib.UUID][]byte)
			for k, v := range v1 {
				v1Screenshot[k] = v
			}

			userlib.DebugMsg("Store file")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			targets := make([]userlib.UUID, 0)
			v2 := userlib.DatastoreGetMap()
			for key := range v2 {
				_, ok := v1Screenshot[key]
				if !ok {
					targets = append(targets, key)
				}
			}

			for _, target := range targets {
				userlib.DatastoreSet(target, []byte("trolololol"))
			}

			userlib.DebugMsg("Load file")
			_, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

		})

		Specify("File deleted after creation", func() {
			userlib.DebugMsg("Initializing users Alice")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Get user Alice")
			alice, err = client.GetUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob")
			bob, err = client.InitUser("Bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Get user Bob")
			bob, err = client.GetUser("Bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Get alice's laptop")
			aliceLaptop, err = client.GetUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob stores file")
			err = bob.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob invites Alice to laptop")
			invite, err := bob.CreateInvitation(bobFile, "Alice")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice accepts invitation")
			err = aliceLaptop.AcceptInvitation("Bob", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice loads file")
			data, err := alice.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice2 appends file")
			err = aliceLaptop.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob loads file")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			userlib.DebugMsg("Bob stores file")
			err = bob.StoreFile(bobFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice loads file")
			data, err = alice.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree)))
		})

		Specify("Swapping blobs", func() {
			userlib.DebugMsg("Initializing users Alice")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Get user Alice")
			alice, err = client.GetUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Screenshotting Datastore")
			v1 := userlib.DatastoreGetMap()
			v1Screenshot := make(map[userlib.UUID][]byte)
			for k, v := range v1 {
				v1Screenshot[k] = v
			}

			userlib.DebugMsg("Alice appends file")
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			targets := make([]userlib.UUID, 0)
			v2 := userlib.DatastoreGetMap()
			for key := range v2 {
				_, ok := v1Screenshot[key]
				if !ok {
					targets = append(targets, key)
				}
			}
			v2Screenshot := make(map[userlib.UUID][]byte)
			for k, v := range v2 {
				v2Screenshot[k] = v
			}

			userlib.DebugMsg("Alice appends file again")
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			v3 := userlib.DatastoreGetMap()
			for key := range v3 {
				_, ok := v2Screenshot[key]
				if !ok {
					targets = append(targets, key)
				}
			}

			first, _ := userlib.DatastoreGet(targets[0])
			Expect(err).To(BeNil())
			second, _ := userlib.DatastoreGet(targets[1])
			Expect(err).To(BeNil())
			userlib.DatastoreSet(targets[0], second)
			userlib.DatastoreSet(targets[1], first)

			userlib.DebugMsg("Alice loads file")
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Append", func() {

		Specify("Filename DNE", func() {
			userlib.DebugMsg("Initializing users Alice with same password")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Get user Alice")
			alice, err = client.GetUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.AppendToFile("dud.txt", []byte("bruh wyd"))
			Expect(err).ToNot(BeNil())
		})

		Specify("File deleted after creation", func() {
			userlib.DebugMsg("Initializing users Alice with same password")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Get user Alice")
			alice, err = client.GetUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Screenshotting Datastore")
			v1 := userlib.DatastoreGetMap()
			v1Screenshot := make(map[userlib.UUID][]byte)
			for k, v := range v1 {
				v1Screenshot[k] = v
			}

			userlib.DebugMsg("Store file")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			targets := make([]userlib.UUID, 0)
			v2 := userlib.DatastoreGetMap()
			for key := range v2 {
				_, ok := v1Screenshot[key]
				if !ok {
					targets = append(targets, key)
				}
			}

			for _, target := range targets {
				userlib.DatastoreDelete(target)
			}

			err = alice.AppendToFile(aliceFile, []byte("bruh wyd"))
			Expect(err).ToNot(BeNil())
		})

		Specify("Last append erased", func() {
			userlib.DebugMsg("Initializing users Alice with same password")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Get user Alice")
			alice, err = client.GetUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Store file")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Screenshotting Datastore")
			v1 := userlib.DatastoreGetMap()
			v1Screenshot := make(map[userlib.UUID][]byte)
			for k, v := range v1 {
				v1Screenshot[k] = v
			}

			err = alice.AppendToFile(aliceFile, []byte("bruh wyd"))
			Expect(err).To(BeNil())

			targets := make([]userlib.UUID, 0)
			v2 := userlib.DatastoreGetMap()
			for key := range v2 {
				_, ok := v1Screenshot[key]
				if !ok {
					targets = append(targets, key)
				}
			}

			for _, target := range targets {
				userlib.DatastoreDelete(target)
			}
			_, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("File deleted after creation, but check is from second device", func() {
			userlib.DebugMsg("Initializing users Alice with same password")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Get user Alice")
			aliceLaptop, err = client.GetUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Get user Alice again")
			alicePhone, err = client.GetUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Screenshotting Datastore")
			v1 := userlib.DatastoreGetMap()
			v1Screenshot := make(map[userlib.UUID][]byte)
			for k, v := range v1 {
				v1Screenshot[k] = v
			}

			userlib.DebugMsg("Store file")
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			targets := make([]userlib.UUID, 0)
			v2 := userlib.DatastoreGetMap()
			for key := range v2 {
				_, ok := v1Screenshot[key]
				if !ok {
					targets = append(targets, key)
				}
			}

			for _, target := range targets {
				userlib.DatastoreDelete(target)
			}

			err = alicePhone.AppendToFile(aliceFile, []byte("bruh wyd"))
			Expect(err).ToNot(BeNil())
		})

		Specify("Last append erased, but check is from second device", func() {
			userlib.DebugMsg("Initializing users Alice with same password")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Get user Alice")
			aliceLaptop, err = client.GetUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Get user Alice again")
			alicePhone, err = client.GetUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Store file")
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Screenshotting Datastore")
			v1 := userlib.DatastoreGetMap()
			v1Screenshot := make(map[userlib.UUID][]byte)
			for k, v := range v1 {
				v1Screenshot[k] = v
			}

			err = alicePhone.AppendToFile(aliceFile, []byte("bruh wyd"))
			Expect(err).To(BeNil())

			targets := make([]userlib.UUID, 0)
			v2 := userlib.DatastoreGetMap()
			for key := range v2 {
				_, ok := v1Screenshot[key]
				if !ok {
					targets = append(targets, key)
				}
			}

			for _, target := range targets {
				userlib.DatastoreDelete(target)
			}

			_, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Bandwidth", func() {
			// Helper function to measure bandwidth of a particular operation
			measureBandwidth := func(probe func()) (bandwidth int) {
				before := userlib.DatastoreGetBandwidth()
				probe()
				after := userlib.DatastoreGetBandwidth()
				return after - before
			}

			userlib.DebugMsg("Initializing users Alice with same password")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Get user Alice")
			alice, err = client.GetUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Store file")
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			bw1 := measureBandwidth(func() {
				alice.AppendToFile(aliceFile, []byte(contentOne))
			})

			for i := 1; i < 10; i++ {
				user := strconv.Itoa(i)
				u, err := client.InitUser(user, defaultPassword)
				Expect(err).To(BeNil())
				u.StoreFile("dud.txt", []byte("dud"))
			}

			for i := 1; i < 10; i++ {
				alice.AppendToFile(aliceFile, []byte(contentOne))
			}

			bw2 := measureBandwidth(func() {
				alice.AppendToFile(aliceFile, []byte(contentOne))
			})

			if bw2-bw1 != 0 {
				err = errors.New("bandwidth scales")
			} else {
				err = nil
			}
			Expect(err).To(BeNil())

		})

	})

	Describe("CreateInv", func() {

		Specify("File does not exist", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user bob")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Creating invite for Bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Sending Bob nonexistent file")
			_, err = alice.CreateInvitation(bobFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("File tampered with", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user bob")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Screenshotting Datastore")
			v1 := userlib.DatastoreGetMap()
			v1Screenshot := make(map[userlib.UUID][]byte)
			for k, v := range v1 {
				v1Screenshot[k] = v
			}

			userlib.DebugMsg("Store file")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			targets := make([]userlib.UUID, 0)
			v2 := userlib.DatastoreGetMap()
			for key := range v2 {
				_, ok := v1Screenshot[key]
				if !ok {
					targets = append(targets, key)
				}
			}

			for _, target := range targets {
				userlib.DatastoreSet(target, []byte("trolololol"))
			}

			userlib.DebugMsg("Creating invite for Bob")
			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Sending file to non-existent user", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Creating invite for Bob")
			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

		})

		Specify("User nor file exists", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Creating invite for Bob")
			_, err := alice.CreateInvitation(bobFile, "bob")
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("AcceptInv", func() {

		Specify("File name already exists", func() {

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user bob")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file %s with content: %s", bobFile, contentTwo)
			err = bob.StoreFile(bobFile, []byte(contentTwo))

			userlib.DebugMsg("Creating invite for Bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

		})

		Specify("Revoked before accepting invite", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user bob")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("creating invite for Bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob revoking access")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite")
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Filename swapping", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user bob")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("creating invite for Bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file %s with content: %s", aliceFile, contentTwo)
			err = bob.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite")
			invite, err = bob.CreateInvitation(aliceFile, "alice")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice accepting invite")
			err = alice.AcceptInvitation("bob", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice Loading alicefile")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice Loading bobfile")
			data1, err := alice.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data1).To(Equal([]byte(contentTwo)))

			userlib.DebugMsg("Bob Loading alicefile")
			data2, err := bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data2).To(Equal([]byte(contentTwo)))

			userlib.DebugMsg("Bob Loading bobfile")
			data3, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data3).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice appending alicefile")
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice Loading alicefile")
			data4, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data4).To(Equal([]byte(contentOne + contentThree)))

			userlib.DebugMsg("Bob Loading bobfile")
			data5, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data5).To(Equal([]byte(contentOne + contentThree)))
		})

		Specify("Accept an invite thats not yours", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user bob")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charles.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user charles")
			charles, err = client.GetUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("creating invite for Bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles accepting Bob's invite")
			err = charles.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Accept an invite thats not yours", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user bob")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("creating invite for Bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking access")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite")
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob creating file with same name")
			err = bob.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
		})

		Specify("Accept invite after another user revoked", func() {

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user bob")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charlie.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice")
			charles, err = client.GetUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("creating invite for Bob")
			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice invites charles")
			invite2, err := alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("revoking bob")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite")
			err = bob.AcceptInvitation("alice", invite2, aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("charles accepting invite")
			err = charles.AcceptInvitation("alice", invite2, aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("charles loads file")
			data, err := charles.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})

		Specify("Invite tampered with", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user bob")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Store file")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Screenshotting Datastore")
			v1 := userlib.DatastoreGetMap()
			v1Screenshot := make(map[userlib.UUID][]byte)
			for k, v := range v1 {
				v1Screenshot[k] = v
			}

			userlib.DebugMsg("Creating invite for Bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			targets := make([]userlib.UUID, 0)
			v2 := userlib.DatastoreGetMap()
			for key := range v2 {
				_, ok := v1Screenshot[key]
				if !ok {
					targets = append(targets, key)
				}
			}

			for _, target := range targets {
				userlib.DatastoreSet(target, []byte("trolololol"))
			}

			userlib.DebugMsg("Bob accepts invite")
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Accept invite, tamper file, revoke", func() {

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user bob")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Screenshotting Datastore")
			v1 := userlib.DatastoreGetMap()
			v1Screenshot := make(map[userlib.UUID][]byte)
			for k, v := range v1 {
				v1Screenshot[k] = v
			}

			userlib.DebugMsg("Storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			targets := make([]userlib.UUID, 0)
			v2 := userlib.DatastoreGetMap()
			for key := range v2 {
				_, ok := v1Screenshot[key]
				if !ok {
					targets = append(targets, key)
				}
			}

			userlib.DebugMsg("creating invite for Bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			for _, target := range targets {
				userlib.DatastoreSet(target, []byte("haha get tampered you BOT"))
			}

			userlib.DebugMsg("Bob accepting invite")
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob loading file")
			_, err = bob.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Revoke", func() {

		Specify("File DNE", func() {

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user bob")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("creating invite for Bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite")
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking access")
			err = alice.RevokeAccess(bobFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("File not shared", func() {

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user bob")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file %s with content: %s", bobFile, contentTwo)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("creating invite for Bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite")
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking access")
			err = alice.RevokeAccess(bobFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Bob cant access after revoked", func() {

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user bob")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("creating invite for Bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite")
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob loading file")
			data, err := bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking access")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob loading file")
			_, err = bob.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Bob revoking owner access", func() {

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user bob")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("creating invite for Bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite")
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob revoking access")
			err = bob.RevokeAccess(aliceFile, "alice")
			Expect(err).ToNot(BeNil())
		})

		Specify("Chain revokes", func() {

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user bob")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charlie.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice")
			charles, err = client.GetUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("creating invite for Bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite")
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob invites Charles")
			invite2, err := bob.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles accepting invite")
			err = charles.AcceptInvitation("bob", invite2, aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob loading file")
			data, err := bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Charles loading file")
			data2, err := charles.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data2).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking access")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob loading file")
			_, err = bob.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Charles loading file")
			_, err = charles.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})
		Specify("Non revoked user have access after a revoke", func() {

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user bob")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charles.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Charles")
			charles, err = client.GetUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("creating invite for Bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite")
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice invites Charles")
			invite2, err := alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles accepting invite")
			err = charles.AcceptInvitation("alice", invite2, aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob loading file")
			data, err := bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Charles loading file")
			data2, err := charles.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data2).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking access")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob loading file")
			_, err = bob.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Charles loading file")
			_, err = charles.LoadFile(aliceFile)
			Expect(err).To(BeNil())
		})
		Specify("Accept invite after shared person revoked", func() {

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user bob")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charlie.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user charles")
			charles, err = client.GetUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("creating invite for Bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite")
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob invites charles")
			invite2, err := bob.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("revoking bob")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("charles accepting invite")
			err = charles.AcceptInvitation("alice", invite2, aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("bob loading file")
			_, err = bob.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Accept invite, revoked, store file with same name", func() {

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user bob")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("creating invite for Bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite")
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("revoking bob")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob loading file")
			_, err = bob.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("bob stores file")
			err = bob.StoreFile(aliceFile, []byte(contentThree))
			Expect(err).ToNot(BeNil())
		})

		Specify("Accept invite, file tampered, revoke", func() {

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user bob")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Screenshotting Datastore")
			v1 := userlib.DatastoreGetMap()
			v1Screenshot := make(map[userlib.UUID][]byte)
			for k, v := range v1 {
				v1Screenshot[k] = v
			}

			userlib.DebugMsg("Storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			targets := make([]userlib.UUID, 0)
			v2 := userlib.DatastoreGetMap()
			for key := range v2 {
				_, ok := v1Screenshot[key]
				if !ok {
					targets = append(targets, key)
				}
			}

			userlib.DebugMsg("creating invite for Bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite")
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).To(BeNil())

			for _, target := range targets {
				userlib.DatastoreSet(target, []byte("screw you"))
			}

			userlib.DebugMsg("revoking bob")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Accept invite, file deleted, revoke", func() {

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user bob")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Screenshotting Datastore")
			v1 := userlib.DatastoreGetMap()
			v1Screenshot := make(map[userlib.UUID][]byte)
			for k, v := range v1 {
				v1Screenshot[k] = v
			}

			userlib.DebugMsg("Storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			targets := make([]userlib.UUID, 0)
			v2 := userlib.DatastoreGetMap()
			for key := range v2 {
				_, ok := v1Screenshot[key]
				if !ok {
					targets = append(targets, key)
				}
			}

			userlib.DebugMsg("creating invite for Bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite")
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).To(BeNil())

			for _, target := range targets {
				userlib.DatastoreDelete(target)
			}

			userlib.DebugMsg("revoking bob")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Accept invite, tamper invite, revoke", func() {

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user bob")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Screenshotting Datastore")
			v1 := userlib.DatastoreGetMap()
			v1Screenshot := make(map[userlib.UUID][]byte)
			for k, v := range v1 {
				v1Screenshot[k] = v
			}

			userlib.DebugMsg("creating invite for Bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			targets := make([]userlib.UUID, 0)
			v2 := userlib.DatastoreGetMap()
			for key := range v2 {
				_, ok := v1Screenshot[key]
				if !ok {
					targets = append(targets, key)
				}
			}

			userlib.DebugMsg("Bob accepting invite")
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).To(BeNil())

			for _, target := range targets {
				userlib.DatastoreSet(target, []byte("haha get tampered you BOT"))
			}

			userlib.DebugMsg("revoking bob")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Accept invite, delete invite, revoke", func() {

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user bob")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Screenshotting Datastore")
			v1 := userlib.DatastoreGetMap()
			v1Screenshot := make(map[userlib.UUID][]byte)
			for k, v := range v1 {
				v1Screenshot[k] = v
			}

			userlib.DebugMsg("creating invite for Bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			targets := make([]userlib.UUID, 0)
			v2 := userlib.DatastoreGetMap()
			for key := range v2 {
				_, ok := v1Screenshot[key]
				if !ok {
					targets = append(targets, key)
				}
			}

			userlib.DebugMsg("Bob accepting invite")
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).To(BeNil())

			for _, target := range targets {
				userlib.DatastoreDelete(target)
			}

			userlib.DebugMsg("revoking bob")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Bob not initialized", func() {

		Specify("bro you dont even work here", func() {

			userlib.DebugMsg("Getting user Bob.")
			_, err := client.GetUser("bob", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob stores a file")
			err = bob.StoreFile(bobFile, []byte(contentOne))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob loads a file")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob appends a file")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob revokes access")
			err = bob.RevokeAccess(bobFile, "alice")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob creates an invite")
			invite, err := bob.CreateInvitation(bobFile, "alice")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob accepts an invite")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

		})
	})
})
