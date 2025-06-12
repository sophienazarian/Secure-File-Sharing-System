package client

import (
	"encoding/json"
	"strconv"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

/*
********************************************
**                Structs                 **
********************************************
 */

/* User struct to hold information relevant to the current user. */
type User struct {
	Username     string
	Password     string
	UserBytes    []byte
	PublicRSA    userlib.PKEEncKey
	PrivateRSA   userlib.PKEDecKey
	PublicVerify userlib.DSVerifyKey
	PrivateSign  userlib.DSSignKey
}

/* File struct to hold the metadata of the file and track the number of appends. */
type File struct {
	Curr int // number of appends
}

/* Blob struct to hold the content(s) of a file. */
type Blob struct {
	Contents []byte
}

/* Invitation struct to represent the contents of the original file being shared. */
type Invitation struct {
	FileHash      []byte
	FileSourceKey []byte
}

/*
********************************************
**               Constants                **
********************************************
 */

const Keymap = "Keymap"
const Namespace = "Namespace"
const Ownedmap = "Ownedmap"
const WhoShared = "WhoShared"

/*
********************************************
**             Core Functions             **
********************************************
 */

/*
Abort if username exists in keystore or invalid username is supplied (empty string). Initialize a new User struct. Generate RSA and Digital Signature keys with PKEKeyGen() and DSKeyGen() and store in User struct fields. Fill the User struct fields with the entered username and password, and save randomBytes() into the field UserBytes. In the Keystore, create two mappings. First, create a mapping of username || “0” to the RSA public key. Second, create a mapping of username || “1” to the public Digital Signature Key. Generate salt from randomBytes() for user and store a mapping of Hash(username) to salt in datastore. Then, generate a UUID for the user with Argon2Key(salt,  password). Serialize the user struct. Using the encryption key Getkey(username, password), Encrypt-then-Mac the serialized struct. In the datastore, make a mapping of the generated UUID to the encrypted user.
*/
func InitUser(username string, password string) (userdataptr *User, err error) {
	// Error case: if username is empty string, abort
	if username == "" {
		err = errors.New("username cannot be empty")
		return nil, err
	}

	// Error case: if username exists in keystore, abort
	_, ok := userlib.KeystoreGet(username + "0")
	if ok {
		err = errors.New("username already exists")
		return nil, err
	}

	// Generate new user struct and fill its fields
	var newuser User
	newuser.Username = username
	newuser.Password = password
	newuser.UserBytes = userlib.RandomBytes(16)
	newuser.PublicRSA, newuser.PrivateRSA, err = userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	newuser.PrivateSign, newuser.PublicVerify, err = userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}

	// Put public keys in keystore
	userlib.KeystoreSet(username+"0", newuser.PublicRSA)
	userlib.KeystoreSet(username+"1", newuser.PublicVerify)

	// Genrate salt with random bytes and store a mapping of Hash(username) to salt in Datastore
	salt := userlib.RandomBytes(16)
	hash := (userlib.Hash([]byte(username)))
	userUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(userUUID, salt)

	// Generate a UUID for the user with Argon2Key(password, salt)
	struct_UUID, err := uuid.FromBytes(userlib.Argon2Key([]byte(password), salt, 16))
	if err != nil {
		return nil, err
	}

	// Serialize user struct
	serialized_struct, err := json.Marshal(newuser)
	if err != nil {
		return nil, err
	}

	// Generate encryption key E = GetKey(username, password)
	E, err := GetKey(username, password)
	if err != nil {
		return nil, err
	}

	// Encrypt-then-Mac serialized struct
	EnM_sruct, err := EncryptThenMac(E, serialized_struct)
	if err != nil {
		return nil, err
	}

	// Put encrypted struct in datastore at the generated UUID
	userlib.DatastoreSet(struct_UUID, EnM_sruct)
	return &newuser, nil
}

/*
Check to see if username exists by checking the keystore for a key labeled username || “0”.  If this key is not present in the Keystore, abort. If it is, Getsalt(). To authenticate a user, compute Hash(salt || password). If this value is a key in the datastore, then we know that the provided username and password combination is valid. Otherwise, abort. Retrieve the encrypted user struct at the computed UUID. GetKey(), VerifyAndDecrypt() the user struct and deserialize.
*/
func GetUser(username string, password string) (userdataptr *User, err error) {
	// Error case: check to see if user exists
	_, ok := userlib.KeystoreGet(username + "0")
	if !ok {
		err = errors.New("username does not exist")
		return nil, err
	}

	// get salt from datastore
	salt, err := GetSalt(username)
	if err != nil {
		return nil, err
	}

	// compute Argon2Key(password, salt) to authenticate user existence in Datastore
	uuid, err := uuid.FromBytes(userlib.Argon2Key([]byte(password), salt, 16))
	if err != nil {
		return nil, err
	}
	struct_value, exists := userlib.DatastoreGet(uuid)
	if !exists {
		return nil, errors.New("password is incorrect")
	}

	// verify and decrypt struct
	E, err := GetKey(username, password)
	if err != nil {
		return nil, err
	}
	Dec_struct, err := VerifyAndDecrypt(E, struct_value)
	if err != nil {
		return nil, err
	}

	// Deserialize into user variable
	var user User
	err = json.Unmarshal(Dec_struct, &user)
	if err != nil {
		return nil, err
	}

	// Return reference to user struct
	return &user, nil
}

/*
CheckIn(Namespace, filename). If false, then that file has not been generated yet; randomly generate bytes using randomBytes() for the filebytes and StoreIn(Namespace, filename, filebytes), and store in empty list in the Ownedmap. Then, create a new File struct initialized with curr = 1, a new Blob struct with the supplied contents, and a new File encryption key E = randomBytes() and StoreIn(Keyspace, filename, E). Place a mapping in the datastore <fileUUID = Hash(userBytes || fileBytes) : serialized and EncrptandMac()  File struct>, and a mapping <Hash(fileUUID || 1) : encrypted blob struct>. If CheckIn(Namespace, filename) == true, then the file has been generated previously. Since the file has been generated, Hash(userBytes || filebytes) is a key in the datastore. KeyandUUID(user, filename) will generate the decryption key and file UUID based on whether or not the user is the owner. verify and decrypt using the key returned. while File.curr != 1: delete the mapping in datastore <Hash(uuID of file || curr) : Blob struct>, then decrement curr. With curr = 1, overwrite the mapping at Hash(uuID of file + curr) to be the serialized, Encrypted-then-Mac’d new Blob (with encryption key = keygen(file encryption key, curr)) containing the supplied contents. Update the mapping of the fileUUID to the new filestruct with the updated cur variable (1).
*/
func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// Error Case: check if namespace is compromised
	exists, err := userdata.CheckIn(Namespace, filename)
	if err != nil {
		return err
	}

	if !exists { // File has not been generated yet
		// genrate random file bytes and save it in Namespace
		filebytes := userlib.RandomBytes(16)
		err := userdata.StoreIn(Namespace, filename, filebytes)
		if err != nil {
			return err
		}
		// generate OwnedMap mapping to itself
		err = userdata.StoreIn(Ownedmap, filename+"0", []byte(userdata.Username))
		if err != nil {
			return err
		}
		// generate empty list and store in OwnedMap
		emptyList := make([]string, 0)
		serializedEmptyList, err := json.Marshal(emptyList)
		if err != nil {
			return err
		}
		userdata.StoreIn(Ownedmap, filename, serializedEmptyList)

		//genrate new file and blob structs with Curr = 1 and Contents = content
		var newfile File
		newfile.Curr = 1
		var newblob Blob
		newblob.Contents = content

		// Generate random file encryption key and save it in the Keymap
		enckey := userlib.RandomBytes(16)
		err = userdata.StoreIn(Keymap, filename, enckey)
		if err != nil {
			return err
		}

		//genrate file uuid = Hash(userBytes || fileBytes)
		filehash := userlib.Hash(append(userdata.UserBytes, filebytes...))[:16]
		fileuuid, err := uuid.FromBytes(filehash)
		if err != nil {
			return err
		}
		//serialize and encrypt filestruct
		serialized_file, err := json.Marshal(newfile)
		if err != nil {
			return err
		}
		EnkMac, err := EncryptThenMac(enckey, serialized_file)
		if err != nil {
			return err
		}
		//put file uuid and encrypted file in datastore
		userlib.DatastoreSet(fileuuid, EnkMac)

		// Generate the UUID of the first blob according to Hash(fileUUID || blobNum). In this case, blobNum = 1
		blobuuid, err := uuid.FromBytes(userlib.Hash([]byte(string(filehash) + "1"))[:16])
		if err != nil {
			return err
		}

		// serialize and encrypt blobstruct
		blobkey, err := userlib.HashKDF(enckey, []byte("1"))
		if err != nil {
			return err
		}
		serialized_blob, err := json.Marshal(newblob)
		if err != nil {
			return err
		}
		EnkMacBlob, err := EncryptThenMac(blobkey, serialized_blob)
		if err != nil {
			return err
		}

		//put blob uuid and encrypted blob in datastore
		userlib.DatastoreSet(blobuuid, EnkMacBlob)
		return nil

	} else { // File has already been generated
		// Obtain the decKey and fileUUID (either from datastore + keymap directly or by accessing inv struct)
		decKey, filehash, err := userdata.KeyandHash(userdata.Username, filename)
		if err != nil {
			return err
		}
		// Determine fileUUID from filehash
		fileUUID, err := uuid.FromBytes(filehash)
		if err != nil {
			return err
		}

		// Download the file struct
		encFile, ok := userlib.DatastoreGet(fileUUID)
		if !ok {
			return err
		}
		serializedFile, err := VerifyAndDecrypt(decKey, encFile)
		if err != nil {
			return err
		}
		var file File
		err = json.Unmarshal(serializedFile, &file)
		if err != nil {
			return err
		}

		// iterate through all blobs, checking for tampering. Delete after verifying not compromised.
		for file.Curr >= 1 {
			blobNum := strconv.Itoa(file.Curr)

			// Generate the UUID of the blob according to Hash(fileUUID || blobNum)
			blobUUID, err := uuid.FromBytes(userlib.Hash([]byte(string(filehash) + blobNum))[:16])
			if err != nil {
				return err
			}

			// Generate the current blob's blobKey from the file source key
			blobKey, err := userlib.HashKDF(decKey, []byte(blobNum))
			if err != nil {
				return err
			}

			// Download the current blob from the Datastore and verify its integrity
			tagged_ciphertext, ok := userlib.DatastoreGet(blobUUID)
			if !ok {
				return errors.New("Blob does not exist, but it should")
			}
			err = Verify(blobKey, tagged_ciphertext)
			if err != nil {
				return err
			}

			// Delete the old blob from the Datastore
			userlib.DatastoreDelete(blobUUID)
			file.Curr -= 1
		}

		// Generate the UUID of the first blob according to Hash(fileUUID || blobNum). In this case, blobNum = 1
		blobUUID, err := uuid.FromBytes(userlib.Hash([]byte(string(filehash) + "1"))[:16])
		if err != nil {
			return err
		}

		// Derive the encryption key for the first blob
		blobkey, err := userlib.HashKDF(decKey, []byte("1"))
		if err != nil {
			return err
		}

		// Generate new blob struct
		var blob Blob
		blob.Contents = content

		// Serialize and encrypt new blob struct
		serialized_blob, err := json.Marshal(blob)
		if err != nil {
			return err
		}
		encBlob, err := EncryptThenMac(blobkey, serialized_blob)
		if err != nil {
			return err
		}

		// Upload the new first blob to the Datastore
		userlib.DatastoreSet(blobUUID, encBlob)

		// Reset file.Curr = 1, now that a new blob exists
		file.Curr = 1

		// Re-encrypt the file object, updating it in the datastore
		serialized_struct, err := json.Marshal(file)
		if err != nil {
			return err
		}
		EnkMac, err := EncryptThenMac(decKey, serialized_struct)
		if err != nil {
			return err
		}

		// Upload the updated file object to the datastore
		userlib.DatastoreSet(fileUUID, EnkMac)
		return nil
	}
}

/* Check if the file exists in Namespace. If it does not, abort. If the user appending is the owner of the file, access the verify and decrypt the File struct as in previous sections.  Increment File.Curr and create and store a new mapping in the datastore at UUID =  Hash(fileUUID || curr) to a new blob containing the contents of this append, encrypted and Mac’d as in previous sections.  If the user is not the owner of this file, retrieve the UUID of the invitation from Hash(userBytes || filebytes), access the  invitation (as in previous sections) to find the UUID of the file to append to and its decryption keys. Then, follow the same procedure as if you were the owner. */
func (userdata *User) AppendToFile(filename string, content []byte) error {
	//Error case: check to see if file exists in Namespace
	exists, err := userdata.CheckIn(Namespace, filename)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("file not found")
	}
	// Access the fileUUID and sourceKey (whether owner or not)
	key, filehash, err := userdata.KeyandHash(userdata.Username, filename)
	if err != nil {
		return err
	}
	fileUUID, err := uuid.FromBytes(filehash)
	if err != nil {
		return err
	}
	// Download the encrypted file struct at the fileUUID
	struct_value, exists := userlib.DatastoreGet(fileUUID)
	if !exists {
		return errors.New("not a valid UUID")
	}
	// verify and decrypt struct
	Dec_struct, err := VerifyAndDecrypt(key, struct_value)
	if err != nil {
		return err
	}
	// Deserialize the file struct
	var file File
	err = json.Unmarshal(Dec_struct, &file)
	if err != nil {
		return err
	}

	// Update file struct by incrementing file.Curr
	file.Curr += 1

	//genrate new blob struct amd set contents
	var addblob Blob
	addblob.Contents = content
	blobNum := strconv.Itoa(file.Curr)

	// Generate the UUID of the blob according to Hash(fileUUID || blobNum)
	blobuuid, err := uuid.FromBytes(userlib.Hash([]byte(string(filehash) + blobNum))[:16])
	if err != nil {
		return err
	}

	// Derive the blobKey from the file sourcekey
	blobkey, err := userlib.HashKDF(key, []byte(blobNum))
	if err != nil {
		return err
	}

	// Serialize and Encrypt the new blob struct to be appended
	serialized_blob, err := json.Marshal(addblob)
	if err != nil {
		return err
	}
	EnkMacBlob, err := EncryptThenMac(blobkey, serialized_blob)
	if err != nil {
		return err
	}

	// Add the encrypted blob to the Datastore at blobUUID
	userlib.DatastoreSet(blobuuid, EnkMacBlob)

	// Re-upload the updated file struct to the Datastore
	serialized_struct, err := json.Marshal(file)
	if err != nil {
		return err
	}
	EnkMac, err := EncryptThenMac(key, serialized_struct)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileUUID, EnkMac)

	return nil
}

/*
If no file struct at Hash(userBytes || filebytes), fail. Otherwise, if the user is the owner of file, access file struct (like in previous sections) to gather Curr. For i in range(1, curr): Access blob struct at Hash(fileUUID || i) as in previous sections and add their contents to in-memory result String. Return result. If user is not the owner, access UUID of Invitation struct at Hash(userBytes || fileBytes) Retrieve UUID of file and decryption keys from invitation struct. Verify and decrypt file at UUID to retrieve file struct and then follow the same procedure as if you were the owner.
*/
func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	// Error case: check to see if file exists
	exists, err := userdata.CheckIn(Namespace, filename)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.New(strings.ToTitle("file not found"))
	}

	// get sourcekey and fileUUID (whether you are owner or not)
	key, filehash, err := userdata.KeyandHash(userdata.Username, filename)
	if err != nil {
		return nil, err
	}
	fileUUID, err := uuid.FromBytes(filehash)
	if err != nil {
		return nil, err
	}

	// Download the encrypted file struct at fileUUID
	struct_value, exists := userlib.DatastoreGet(fileUUID)
	if !exists {
		err = errors.New("not a valid UUID")
		return nil, err
	}

	//verify and decrypt struct
	Dec_struct, err := VerifyAndDecrypt(key, struct_value)
	if err != nil {
		return nil, err
	}

	// Deserialize the file struct
	var file File
	err = json.Unmarshal(Dec_struct, &file)
	if err != nil {
		return nil, err
	}

	// Retrieve contents; collect content from each blob, appending to the end of "contents"
	var contents []byte
	blobNum := 1
	for blobNum <= file.Curr {
		// Generate the UUID of the blob according to Hash(fileUUID || blobNum)
		blobUUID, err := uuid.FromBytes(userlib.Hash([]byte(string(filehash) + strconv.Itoa(blobNum)))[:16])
		if err != nil {
			return nil, err
		}

		// Download the encrypted blob struct
		encBlob, ok := userlib.DatastoreGet(blobUUID)
		if !ok {
			return nil, errors.New("Blob does not exist, but it should")
		}

		// Derive the blobKey and decrypt the blob struct
		blobkey, err := userlib.HashKDF(key, []byte(strconv.Itoa(blobNum)))
		if err != nil {
			return nil, err
		}
		serialized_blob, err := VerifyAndDecrypt(blobkey, encBlob)
		if err != nil {
			return nil, err
		}

		// Deserialize the blob struct
		var blob Blob
		err = json.Unmarshal(serialized_blob, &blob)
		if err != nil {
			return nil, err
		}

		// Collect into contents
		contents = append(contents, blob.Contents...)
		blobNum += 1
	}
	return contents, nil
}

/*
Verify that the filename exists in the Namespace, that the receiver exists, and is not already shared with the recipient. If those conditions are not met, abort. If the owner is creating the invite, an invitation struct will be made and stored in the Datastore at UUID = Hash(filename || recipient username), encrypted with the public RSA key of the receiver in the Keystore and signed with the private Digital Signature key of sender. In OwnedMap, add the username of the recipient to the List associated with the filename. If a non-owner is creating the invite, the same process will be followed, but rather than creating a new struct, it will be a copy of the one the recipient has, and no modifications to the OwnedMap will be made.
*/
func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	// Error case: Verify that filename exists in Namespace
	exists, err := userdata.CheckIn(Namespace, filename)
	if err != nil {
		return uuid.Nil, err
	}
	if !exists {
		return uuid.Nil, errors.New("attempted to share a file that doesn't exist")
	}

	// Error case: Check that recipient exists, and extract their keys
	receiverRSAKey, ok := userlib.KeystoreGet(recipientUsername + "0")
	if !ok {
		return uuid.Nil, errors.New("recipient user does not exist")
	}

	// Determine ownership
	owner, err := userdata.CheckIn(Ownedmap, filename+"0")
	if err != nil {
		return uuid.Nil, err
	}

	if owner { // if owner:
		// generate UUID = Hash(filename + recipientUsername)
		invUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + recipientUsername))[:16])
		if err != nil {
			return uuid.Nil, err
		}

		// extract filebytes to generate fileUUID, which is loaded into invitation struct
		filebytes, err := userdata.RetrieveFrom(Namespace, filename)
		if err != nil {
			return uuid.Nil, err
		}

		// make new invitation struct, loading sourcekey from Keymap and fileHash = Hash(userbytes || filebytes)
		var newInv Invitation
		newInv.FileSourceKey, err = userdata.RetrieveFrom(Keymap, filename)
		if err != nil {
			return uuid.Nil, err
		}
		newInv.FileHash = userlib.Hash(append(userdata.UserBytes, filebytes...))[:16]

		// serialize struct
		serialized_Inv, err := json.Marshal(newInv)
		if err != nil {
			return uuid.Nil, err
		}

		//encrypt invitation struct with RSA key.
		encInv, err := userlib.PKEEnc(receiverRSAKey, serialized_Inv)
		if err != nil {
			return uuid.Nil, err
		}

		// sign with digital sig key of sender
		signedInv, err := userdata.digitalSign(encInv)
		if err != nil {
			return uuid.Nil, err
		}

		// store in Datastore
		userlib.DatastoreSet(invUUID, signedInv)

		// in OwnedMap, add the recipient to the list by retrieving
		serializedList, err := userdata.RetrieveFrom(Ownedmap, filename)
		if err != nil {
			return uuid.Nil, err
		}

		// then deserializing
		var sharedUsers []string
		err = json.Unmarshal(serializedList, &sharedUsers)
		if err != nil {
			return uuid.Nil, err
		}

		// finally, add the recipient to sharedUsers
		sharedUsers = append(sharedUsers, recipientUsername)

		// reserialize
		serializedList, err = json.Marshal(sharedUsers)
		if err != nil {
			return uuid.Nil, err
		}

		// then update in Ownedmap
		userdata.UpdateIn(Ownedmap, filename, serializedList)

		// return the invUUID
		return invUUID, nil

	} else { // if not owner:

		//If a non-owner is creating the invite, the same process will be followed, but rather than creating a new struct, it will be a copy of the one the recipient has, and no modifications to the OwnedMap will be made.

		// access sender username
		senderBytes, err := userdata.RetrieveFrom(WhoShared, filename)
		if err != nil {
			return uuid.Nil, err
		}
		senderUsername := string(senderBytes)

		// access my invitation struct, starting by extracting filebytes
		filebytes, err := userdata.RetrieveFrom(Namespace, filename)
		if err != nil {
			return uuid.Nil, err
		}

		// grab invitationPtr from datastore at UUID = Hash(userbytes || filebytes)
		invitationPtrUUID, err := uuid.FromBytes(userlib.Hash(append(userdata.UserBytes, filebytes...))[:16])
		if err != nil {
			return uuid.Nil, err
		}
		encinvUUIDBytes, ok := userlib.DatastoreGet(invitationPtrUUID)
		if !ok {
			return uuid.Nil, errors.New("Invitation pointer absent on access")
		}

		sourcekey, err := userdata.RetrieveFrom(Keymap, filename)
		if err != nil {
			return uuid.Nil, err
		}
		invUUIDBytes, err := VerifyAndDecrypt(sourcekey, encinvUUIDBytes)
		if err != nil {
			return uuid.Nil, err
		}

		// Convert invUUIDBytes to invUUID
		invUUID, err := uuid.FromBytes(invUUIDBytes)
		if err != nil {
			return uuid.Nil, err
		}

		// get the encrypted invitation struct
		encSignedInvStruct, ok := userlib.DatastoreGet(invUUID)
		if !ok {
			return uuid.Nil, errors.New("Invitation struct does not exist, but it should")
		}

		// Use sender username from WhoShared to verify that nothing has been compromised
		err = digitalVerify(senderUsername, encSignedInvStruct)
		if err != nil {
			return uuid.Nil, err
		}

		// split into encrypted invitation
		encInvStruct, _, err := digitalSigSplit(encSignedInvStruct)
		if err != nil {
			return uuid.Nil, err
		}

		// decrypt using my RSA decKey
		serialized_Inv, err := userlib.PKEDec(userdata.PrivateRSA, encInvStruct)
		if err != nil {
			return uuid.Nil, err
		}

		// deserialize the invitation
		var myInv Invitation
		err = json.Unmarshal(serialized_Inv, &myInv)
		if err != nil {
			return uuid.Nil, err
		}

		// make a copy of my invitation struct
		var copyInv Invitation
		copyInv.FileHash = myInv.FileHash
		copyInv.FileSourceKey = myInv.FileSourceKey

		// serialize struct
		serialized_CopyInv, err := json.Marshal(copyInv)
		if err != nil {
			return uuid.Nil, err
		}

		// generate UUID = Hash(filename + recipientUsername)
		copyInvUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + recipientUsername))[:16])
		if err != nil {
			return uuid.Nil, err
		}

		//encrypt invitation struct with RSA key.
		encInv, err := userlib.PKEEnc(receiverRSAKey, serialized_CopyInv)
		if err != nil {
			return uuid.Nil, err
		}

		// sign with my digital sig key
		signedInv, err := userdata.digitalSign(encInv)
		if err != nil {
			return uuid.Nil, err
		}

		// store in Datastore
		userlib.DatastoreSet(copyInvUUID, signedInv)

		// return the UUID of copied invitation struct
		return copyInvUUID, nil
	}
}

/*
Verify that the filename does not exist and verify it is from the sender by using the public Verification key in the Keystore. Check if the UUID of the invitation exists in the datastore. If not, then access has been revoked and fail. Add filename to namespace and generate new  filebytes for that file. Create new <UUID = Hash(userbytes || filebytes) : UUID of invite> and store it in the Datastore.
*/
func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// Error case: filename already exists in namespace
	exists, err := userdata.CheckIn(Namespace, filename)
	if err != nil {
		return err
	}
	if exists {
		return errors.New("filename already exists in namespace")
	}

	// Error case: filename has already been shared with me
	exists, err = userdata.CheckIn(WhoShared, filename)
	if err != nil {
		return err
	}
	if exists {
		return errors.New("filename has already been shared with user")
	}

	// obtain encrypted and serialized invitation from Datastore
	encSerializedInv, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("invitationPtr leads to nothing, expected an Invitation struct")
	}

	// verify that invitationPtr is from sender
	err = digitalVerify(senderUsername, encSerializedInv)
	if err != nil {
		return err
	}

	// try to decrypt, catch error
	encInv, _, err := digitalSigSplit(encSerializedInv)
	if err != nil {
		return err
	}
	_, err = userlib.PKEDec(userdata.PrivateRSA, encInv)
	if err != nil {
		return err
	}

	// generate new filebytes and encryption key
	filebytes := userlib.RandomBytes(16)
	sourcekey := userlib.RandomBytes(16)

	// add filename to namespace, sourcekey to keymap
	err = userdata.StoreIn(Namespace, filename, filebytes)
	if err != nil {
		return err
	}
	err = userdata.StoreIn(Keymap, filename, sourcekey)
	if err != nil {
		return err
	}

	// generate UUID = Hash(userbytes + filebytes)
	invPtrUUID, err := uuid.FromBytes(userlib.Hash(append(userdata.UserBytes, filebytes...))[:16])
	if err != nil {
		return err
	}

	// Store mapping of UUID : invitationPtr in Datastore
	serializedInvPtr, err := invitationPtr.MarshalBinary()
	if err != nil {
		return err
	}

	encryptedInvPtr, err := EncryptThenMac(sourcekey, serializedInvPtr)
	if err != nil {
		return err
	}

	// Save who shared this with us
	userdata.StoreIn(WhoShared, filename, []byte(senderUsername))

	// Create mapping from invPtrUUID = Hash(userbytes || filebytes) to the serialized invitationPtr
	userlib.DatastoreSet(invPtrUUID, encryptedInvPtr)
	return nil
}

/*
Verify that the filename exists in the user's OwnedMap and the recipient has access. Save the old bytes and keys in memory and generate new random bytes associated with the file. Copy file struct associated with filename into a new FileUUID = Hash(userbytes || newFilebytes) and all blobs into the following locations (as in previous sections). Delete all files and blobs at old filebyte location Hash(userbytes || old filebytes). Update invitation to the non-revoked users with new keys and new UUID and delete the old invitation at Hash(filename || revoked username).
*/
func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// Error case: verify that user is owner (filename exists in OwnedMap)
	exists, err := userdata.CheckIn(Ownedmap, filename+"0")
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("User does not own file")
	}

	// Error case: verify that file is shared with recipient User
	serialized_sharedUsers, err := userdata.RetrieveFrom(Ownedmap, filename)
	if err != nil {
		return err
	}
	var sharedUsers []string
	err = json.Unmarshal(serialized_sharedUsers, &sharedUsers)
	if err != nil {
		return err
	}
	// Iterate over sharedUsers, copying non-revoked usernames into remainingUsers.
	// Flag when revoked user is found, aborting if not found
	sharedWithRecipient := false
	remainingUsers := make([]string, 0)
	for _, user := range sharedUsers {
		if user == recipientUsername {
			sharedWithRecipient = true
		} else {
			remainingUsers = append(remainingUsers, user)
		}
	}
	if !sharedWithRecipient {
		return errors.New("recipient user does not have access to the file")
	}

	// Extract old filebytes and sourcekey for file
	oldFilebytes, err := userdata.RetrieveFrom(Namespace, filename)
	if err != nil {
		return err
	}
	oldSourcekey, err := userdata.RetrieveFrom(Keymap, filename)
	if err != nil {
		return err
	}
	// Generate new filebytes and sourcekey, saving in Datastore
	newFilebytes := userlib.RandomBytes(16)
	newSourceKey := userlib.RandomBytes(16)
	userdata.UpdateIn(Namespace, filename, newFilebytes)
	userdata.UpdateIn(Keymap, filename, newSourceKey)
	// Copy file struct and all blobs into new location, rooted at FileUUID = Hash(userbytes + newFilebytes)
	// Calculate file struct locations
	oldfilehash := userlib.Hash(append(userdata.UserBytes, oldFilebytes...))[:16]
	oldfileUUID, err := uuid.FromBytes(oldfilehash)
	if err != nil {
		return err
	}
	newfilehash := userlib.Hash(append(userdata.UserBytes, newFilebytes...))[:16]
	newfileUUID, err := uuid.FromBytes(newfilehash)
	if err != nil {
		return err
	}
	// Grab file struct from Datastore
	encFile, ok := userlib.DatastoreGet(oldfileUUID)
	if !ok {
		return errors.New("attempting to move file, but File struct not in Datastore")
	}
	serialized_file, err := VerifyAndDecrypt(oldSourcekey, encFile)
	if err != nil {
		return err
	}
	var file File
	err = json.Unmarshal(serialized_file, &file)
	if err != nil {
		return err
	}

	// Begin copying blobs to new locations in Datastore, re-encrypting them with newSourceKey
	for blobNum := 1; blobNum <= file.Curr; blobNum++ {
		newblobhash := userlib.Hash([]byte(string(newfilehash) + strconv.Itoa(blobNum)))[:16]
		newblobUUID, err := uuid.FromBytes(newblobhash)
		if err != nil {
			return err
		}
		oldblobhash := userlib.Hash([]byte(string(oldfilehash) + strconv.Itoa(blobNum)))[:16]
		oldblobUUID, err := uuid.FromBytes(oldblobhash)
		if err != nil {
			return err
		}

		// Download old blob
		encBlob, ok := userlib.DatastoreGet(oldblobUUID)
		if !ok {
			return errors.New("Blob does not exist, but it should")
		}
		// Derive blobkey from oldSourcekey and decrypt
		blobkey, err := userlib.HashKDF(oldSourcekey, []byte(strconv.Itoa(blobNum)))
		if err != nil {
			return err
		}
		serialized_blob, err := VerifyAndDecrypt(blobkey, encBlob)
		if err != nil {
			return err
		}

		// Derive new blobkey from newSourceKey and re-encrypt
		blobkey, err = userlib.HashKDF(newSourceKey, []byte(strconv.Itoa(blobNum)))
		if err != nil {
			return err
		}
		encBlob, err = EncryptThenMac(blobkey, serialized_blob)
		if err != nil {
			return err
		}

		// Update Datastore with blob at new UUID
		userlib.DatastoreSet(newblobUUID, encBlob)

		// Delete Datastore mapping at old blob UUID
		userlib.DatastoreDelete(oldblobUUID)
	}

	// Re-encrypt File, but with new sourceKey
	encFile, err = EncryptThenMac(newSourceKey, serialized_file)
	if err != nil {
		return err
	}

	// Update Datastore with re-encrypted file at new UUID
	userlib.DatastoreSet(newfileUUID, encFile)

	// Delete Datastore mapping at old file UUID
	userlib.DatastoreDelete(oldfileUUID)

	// Delete revoked invitation at UUID = Hash(filename || revoked username)
	oldInvUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + recipientUsername))[:16])
	if err != nil {
		return err
	}

	// But first check if it was compromised
	encInv, ok := userlib.DatastoreGet(oldInvUUID)
	if !ok {
		return errors.New(" expected an invitation struct to revoke, but none exists")
	}

	// use my username here because I was the one who signed it.
	err = digitalVerify(userdata.Username, encInv)
	if err != nil {
		return err
	}
	userlib.DatastoreDelete(oldInvUUID)

	// Update OwnedMap to only contain the remaining users
	serializedRemainingUsers, err := json.Marshal(remainingUsers)
	if err != nil {
		return err
	}
	userdata.UpdateIn(Ownedmap, filename, serializedRemainingUsers)

	// Update remaining invitations at UUID = Hash(filename || sharedUser)
	for _, user := range remainingUsers {
		if user == "" {
			continue
		}
		invUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + user))[:16])
		if err != nil {
			return err
		}
		// First verify that the invitation struct has not been compromised.
		// Grab Invitation struct from Datastore
		encAndSignedInv, ok := userlib.DatastoreGet(invUUID)
		if !ok {
			return errors.New(" attempting to update invitation, but Invitation struct not in Datastore")
		}
		// Verify that it has not been compromised. Use my username because I sent it
		err = digitalVerify(userdata.Username, encAndSignedInv)
		if err != nil {
			return err
		}

		// Then, replace the old struct with a new invitation containing updated permissions.

		// Obtain this user's public RSA key
		userRSAKey, ok := userlib.KeystoreGet(user + "0")
		if !ok {
			return errors.New(" attempting to update permission of non-revoked user, but cannot find enc key")
		}

		// Create new invitation to this user.
		var newInv Invitation
		newInv.FileHash = newfilehash
		newInv.FileSourceKey = newSourceKey

		// serialize struct
		serialized_Inv, err := json.Marshal(newInv)
		if err != nil {
			return err
		}

		//encrypt invitation struct with RSA key
		encInv, err := userlib.PKEEnc(userRSAKey, serialized_Inv)
		if err != nil {
			return err
		}

		// sign with my digital sig key
		signedInv, err := userdata.digitalSign(encInv)
		if err != nil {
			return err
		}

		// update invStruct in Datastore
		userlib.DatastoreSet(invUUID, signedInv)
	}

	return nil
}

/*
********************************************
**             Helper Methods             **
********************************************
 */

/* Split a tagged ciphertext into its components. */
func sliceTaggedCipher(tagged_ciphertext []byte) (ciphertext []byte, tag []byte, err error) {
	if len(tagged_ciphertext) < 64 {
		return nil, nil, errors.New("tried splitting ciphertext smaller than 64 bytes")
	}
	l := len(tagged_ciphertext) - 64
	tag = tagged_ciphertext[l:]
	ciphertext = tagged_ciphertext[:l]
	return
}

/* Returns an error if the tagged ciphertext has been compromised. */
func Verify(key []byte, tagged_ciphertext []byte) error {
	// manually shrink the provided sourcekey to 16 bytes. Allows you to pass in variable length sourcekeys
	source := key[:16]
	macKey, err := userlib.HashKDF(source, []byte("mac"))
	if err != nil {
		return err
	}
	ciphertext, tag, err := sliceTaggedCipher(tagged_ciphertext)
	if err != nil {
		return err
	}
	generatedTag, err := userlib.HMACEval(macKey[:16], ciphertext)
	if err != nil {
		return err
	}
	if userlib.HMACEqual(tag, generatedTag) {
		return nil
	}
	return errors.New(strings.ToTitle("file has been tampered with"))
}

/* Decrypts the tagged ciphertext iff it has not been compromised. Returns the plaintext. */
func VerifyAndDecrypt(sourcekey []byte, tagged_ciphertext []byte) (plaintext []byte, err error) {
	// manually shrink the provided sourcekey to 16 bytes. Allows you to pass in variable length sourcekeys
	source := sourcekey[:16]
	encKey, err := userlib.HashKDF(source, []byte("encryption"))
	if err != nil {
		return nil, err
	}

	err = Verify(source, tagged_ciphertext)
	if err != nil {
		return nil, err
	}

	ciphertext, _, err := sliceTaggedCipher(tagged_ciphertext)
	if err != nil {
		return nil, err
	}
	plaintext = userlib.SymDec(encKey[:16], ciphertext)

	return plaintext, nil
}

/*
Securely encrypts-then-macs the plaintext, returning the tagged ciphertext.
Returns an error if any operations fail.
*/
func EncryptThenMac(sourcekey []byte, plaintext []byte) (tagged_ciphertext []byte, err error) {
	// manually shrink the provided sourcekey to 16 bytes. Allows you to pass in variable length sourcekeys
	source := sourcekey[:16]
	encKey, err := userlib.HashKDF(source, []byte("encryption"))
	if err != nil {
		return nil, err
	}

	macKey, err := userlib.HashKDF(source, []byte("mac"))
	if err != nil {
		return nil, err
	}

	IV := userlib.RandomBytes(16)
	ciphertext := userlib.SymEnc(encKey[:16], IV, plaintext)
	tag, err := userlib.HMACEval(macKey[:16], ciphertext)
	if err != nil {
		return nil, err
	}

	tagged_ciphertext = append(ciphertext, tag...)
	return tagged_ciphertext, nil
}

/*
Stores a mapping of filename to object in the provided user space, which must be one of
"Keymap", "Ownedmap", or "Namespace". Throws an error if the filename has an existing
mapping in the provided user space, or if any operations fail.
*/
func (userdata *User) StoreIn(space string, filename string, object []byte) error {
	exists, err := userdata.CheckIn(space, filename)
	if err != nil {
		return err
	}
	if exists {
		err = errors.New("attempted to storeIn, but filename already has mapping")
		return err
	}

	E, err := GetKey(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}
	K, err := userlib.HashKDF(E, []byte(space+filename))
	if err != nil {
		return err
	}
	concat := append([]byte(space+filename), userdata.UserBytes...)
	hash := (userlib.Hash(concat))
	uuid, err := uuid.FromBytes(hash[:16])
	if err != nil {
		return err
	}

	tagged_ciphertext, err := EncryptThenMac(K, object)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(uuid, tagged_ciphertext)
	return nil
}

/*
Updates a mapping of filename to object in the provided user space, which must be one of
"Keymap", "Ownedmap", "WhoShared", or "Namespace". Throws an error if the filename does not already have a
mapping in the provided user space, or if any operations fail.
*/
func (userdata *User) UpdateIn(space string, filename string, object []byte) error {
	exists, err := userdata.CheckIn(space, filename)
	if err != nil {
		return err
	}
	if !exists {
		err = errors.New("attempted to updateIn, but filename mapping does not exist")
		return err
	}

	E, err := GetKey(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}
	K, err := userlib.HashKDF(E, []byte(space+filename))
	if err != nil {
		return err
	}
	concat := append([]byte(space+filename), userdata.UserBytes...)
	hash := (userlib.Hash(concat))
	uuid, err := uuid.FromBytes(hash[:16])
	if err != nil {
		return err
	}

	tagged_ciphertext, err := EncryptThenMac(K, object) // key reuse? storing different object with same encryption key
	if err != nil {
		return err
	}

	userlib.DatastoreSet(uuid, tagged_ciphertext)
	return nil
}

/*
Retrieves the mapping of filename to object in the provided user space, which must be one of
"Keymap", "Ownedmap", "WhoShared", or "Namespace". Throws an error if the filename does not exist
in the provided user space, or if any operations fail.
*/
func (userdata *User) RetrieveFrom(space string, filename string) (plaintext []byte, err error) {
	exists, err := userdata.CheckIn(space, filename)
	if err != nil {
		return nil, err
	}
	if !exists {
		err = errors.New("attempted to retrieve, but filename does not exist")
		return nil, err
	}

	E, err := GetKey(userdata.Username, userdata.Password)
	if err != nil {
		return nil, err
	}
	K, err := userlib.HashKDF(E, []byte(space+filename))
	if err != nil {
		return nil, err
	}
	concat := append([]byte(space+filename), userdata.UserBytes...)
	hash := (userlib.Hash(concat))
	uuid, err := uuid.FromBytes(hash[:16])
	if err != nil {
		return nil, err
	}

	tagged_ciphertext, ok := userlib.DatastoreGet(uuid)
	if !ok {
		err = errors.New("attempted to retrieve, but uuid does not exist")
		return nil, err
	}
	plaintext, err = VerifyAndDecrypt(K, tagged_ciphertext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

/*
Returns a boolean indicating whether the filename has a mapping in the provided space,
which must be one of "Keymap", "Ownedmap", "WhoShared", or "Namespace". Throws an error if any of the
operations fail, or if the filename has an existing mapping that has been compromised.
*/
func (userdata *User) CheckIn(space string, filename string) (exists bool, err error) {
	concat := append([]byte(space+filename), userdata.UserBytes...)
	hash := (userlib.Hash(concat))
	uuid, err := uuid.FromBytes(hash[:16])
	if err != nil {
		return false, err
	}

	tagged_ciphertext, exist := userlib.DatastoreGet(uuid)
	if !exist {
		return false, nil
	}

	E, err := GetKey(userdata.Username, userdata.Password)
	if err != nil {
		return true, err
	}

	K, err := userlib.HashKDF(E, []byte(space+filename))
	if err != nil {
		return true, err
	}

	err = Verify(K, tagged_ciphertext)
	if err != nil {
		return true, err
	}
	return true, nil
}

/* Obtains the salt associated with this username from the datastore. */
func GetSalt(user string) ([]byte, error) {
	hash := userlib.Hash([]byte(user))
	userUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		return nil, errors.New("byte length not 16")
	}
	salt, exists := userlib.DatastoreGet(userUUID)
	if !exists {
		return nil, errors.New("UUID not found")
	}
	return salt, nil
}

/* Calculates E, the secure key used to encrypt this user. */
func GetKey(username string, password string) (E []byte, err error) {
	salt, err := GetSalt(username)
	if err != nil {
		return nil, err
	}
	E = userlib.Argon2Key([]byte(password+username), salt, 16)
	return E, nil
}

/* Gathers the decryption key and UUID location of this file, whether the user is the owner or not. */
func (userdata *User) KeyandHash(user string, filename string) (key []byte, hash []byte, err error) {
	filebytes, err := userdata.RetrieveFrom(Namespace, filename)
	if err != nil {
		return nil, nil, err
	}
	filehash := userlib.Hash(append(userdata.UserBytes, filebytes...))[:16]
	fileUUID, err := uuid.FromBytes(filehash)
	if err != nil {
		return nil, nil, err
	}
	owner, err := userdata.CheckIn(Ownedmap, filename+"0")
	if err != nil {
		return nil, nil, err
	}
	if !owner {
		//If this user is not the owner of the file, access the invitation struct by first accessing the invitation pointer at UUID = Hash(userBytes + filebytes),
		encInvUUIDBytes, ok := userlib.DatastoreGet(fileUUID)
		if !ok {
			return nil, nil, errors.New("Invitation pointer not found")
		}

		sourcekey, err := userdata.RetrieveFrom(Keymap, filename)
		if err != nil {
			return nil, nil, err
		}
		marshaledInvUUID, err := VerifyAndDecrypt(sourcekey, encInvUUIDBytes)
		if err != nil {
			return nil, nil, err
		}

		invUUID, err := uuid.FromBytes(marshaledInvUUID)
		if err != nil {
			return nil, nil, err
		}

		// Grab invitation struct
		encSignedInvitation, ok := userlib.DatastoreGet(invUUID)
		if !ok {
			return nil, nil, errors.New("file not found")
		}
		invdeckey := userdata.PrivateRSA
		encInvitation, _, err := digitalSigSplit(encSignedInvitation)
		if err != nil {
			return nil, nil, err
		}
		serializedInvitation, err := userlib.PKEDec(invdeckey, encInvitation)
		if err != nil {
			return nil, nil, err
		}
		var inv Invitation
		err = json.Unmarshal(serializedInvitation, &inv)
		if err != nil {
			return nil, nil, err
		}

		hash = inv.FileHash
		key = inv.FileSourceKey
		//if user is owner
	} else {
		key, err = userdata.RetrieveFrom(Keymap, filename)
		if err != nil {
			return nil, nil, err
		}
		hash = filehash
	}
	return key, hash, nil
}

/*
Computes a digital signature on the message, hashing the message first. Outputs the signed message in the form 'msg + sig'.
*/
func (userdata *User) digitalSign(message []byte) (signedMsg []byte, err error) {
	hashedMsg := userlib.Hash(message)
	signature, err := userlib.DSSign(userdata.PrivateSign, hashedMsg)
	if err != nil {
		return nil, err
	}
	signedMsg = append(message, signature...)
	return signedMsg, nil
}

/*
Verifies the message, assuming that it comes in the form 'msg + sig'. Assumes that sig is 256 bytes long. Returns a nil error if it verifies.
*/
func digitalVerify(senderUsername string, message []byte) (err error) {
	senderVerKey, ok := userlib.KeystoreGet(senderUsername + "1")
	if !ok {
		return errors.New("sender does not have digital signature key")
	}

	msg, sig, err := digitalSigSplit(message)
	if err != nil {
		return err
	}
	hashedMsg := userlib.Hash(msg)
	err = userlib.DSVerify(senderVerKey, hashedMsg, sig)
	if err != nil {
		return err
	}
	return nil
}

/*
Splits the message into the plaintext and signature, assuming that it comes in the form 'msg + sig' and that sig is 256 bytes long.
*/
func digitalSigSplit(message []byte) (msg []byte, sig []byte, err error) {
	if len(message) < 256 {
		return nil, nil, errors.New("tried splitting signature smaller than 256 bytes")
	}
	l := len(message) - 256
	msg = message[:l]
	sig = message[l:]
	return
}
