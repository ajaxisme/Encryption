import base64
from Crypto.Cipher import AES
from Crypto import Random
import hashlib
import getpass

BLOCKSIZE = 16
pad = lambda s: s + (BLOCKSIZE - len(s) % BLOCKSIZE) * chr(BLOCKSIZE - len(s) % BLOCKSIZE) 
unpad = lambda s : s[:-ord(s[len(s)-1:])]

class AESCipher:
	def __init__(self, key):
		self.key = hashlib.sha256(key.encode()).digest()

	def encrypt(self, raw):
		raw  = pad(raw)
		iv = Random.new().read(AES.block_size)
		cipher = AES.new(self.key, AES.MODE_CBC, iv)
		return base64.b64encode(iv + cipher.encrypt(raw))

	def decrypt(self, enc):
		enc = base64.b64decode(enc)
		iv = enc[:16]
		cipher = AES.new(self.key, AES.MODE_CBC, iv)
		return unpad(cipher.decrypt(enc[16:]))


if __name__ == "__main__":
	#key = raw_input('Enter key: ')
	key = getpass.getpass('Enter key: ')
	aes = AESCipher(key)
	message = raw_input('Enter message: ')

	print 'Encrypted message:\n%s'%(aes.encrypt(message))

	enc = raw_input('Enter encrypted message: ')
	try:
		print 'Decrypted message:\n%s'%(aes.decrypt(enc))
	except TypeError:
		print 'Invalid encrypted message'
