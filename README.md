# RemoteAuthClient

### Installing
Python 3.7 or higher is required
```sh
pip install remoteauthclient
```

### Example
```py
from asyncio import run
from remoteauthclient import RemoteAuthClient

c = RemoteAuthClient()

@c.event("on_fingerprint")
async def on_fingerprint(data):
    print(f"Fingerprint: {data}")
    print(f"QrCode url: https://api.qrserver.com/v1/create-qr-code/?size=256x256&data={data}")

@c.event("on_userdata")
async def on_userdata(user):
    print(f"ID: {user.id}")
    print(f"Username: {user.username}")
    print(f"Discriminator: {user.discriminator}")
    print(f"Avatar hash: {user.avatar}")
    print(f"Name: {user.getName()}")
    print(f"Avatar URL: {user.getAvatarURL()}")

@c.event("on_token")
async def on_fingerprint(token):
    print(f"Token: {token}")

@c.event("on_cancel")
async def on_cancel():
    print(f"Auth canceled!")

@c.event("on_timeout")
async def on_timeout():
    print(f"Timeout")

run(c.run())
```