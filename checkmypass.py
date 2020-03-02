import requests
import hashlib 
import sys
from pathlib import Path

def usage():
	print('Supply a text file with passwords on a single line as a single argument.')
	print(f'  ex. {sys.argv[0]} passwords.txt')

def read_password_file(file):
	f = Path(file)
	if f.exists():
		with open(f, 'r') as pass_file:
			passwords = {i.strip() for i in pass_file.readlines()}
			return passwords
	else:
		print(f'Please supply a valid password file: {file} cannot be found or is not valid')
		exit()

def request_api_data(query_char):
	url = 'https://api.pwnedpasswords.com/range/' + query_char
	res = requests.get(url)
	if res.status_code != 200:
		raise RuntimeError(f'Error fetching: {res.status_code}, check the API and try again.')
	return res

def get_password_leaks_count(hashes, hash_to_check):
	hashes = (line.split(':') for line in hashes.text.splitlines())

	for h, count in hashes:
		if h == hash_to_check:
			return count
	return 0

def pwned_api_check(password):
	sha1password = hashlib.sha1(password.encode('utf8')).hexdigest().upper()
	first5_char, tail = sha1password[:5], sha1password[5:]
	response = request_api_data(first5_char)
	return get_password_leaks_count(response, tail)

def main(args):
	passwords = read_password_file(args)
	for password in passwords:
		count = pwned_api_check(password)
		if count:
			print(f'{password} was found {count} times... You should probably change your password')
		else:
			print(f'{password} was NOT found. Carry on!')
	
	print(f'Be responsible! Delete your password file when finished!')
	return 'done!'

if __name__ == '__main__':
	if len(sys.argv) != 2:
 		usage()
	else:
 		main(sys.argv[1])
