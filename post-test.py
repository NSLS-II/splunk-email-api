import requests

url = 'http://127.0.0.1:5000/'
test_args = { 'username': 'jwlodek', 'hostname': 'jwlodek-vm1.nsls2.bnl.local' }

print('Pinging Lockout API to make sure it is alive...')
r = requests.get(url)
print(r.text)

print('Testing example post request...')
r = requests.post(f'{url}/lockout', json=test_args)
print(r.text)

