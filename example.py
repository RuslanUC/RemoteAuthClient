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
async def on_token(token):
    print(f"Token: {token}")

@c.event("on_cancel")
async def on_cancel():
    print(f"Auth canceled!")

@c.event("on_timeout")
async def on_timeout():
    print(f"Timeout")

@c.event("on_captcha")
async def on_captcha(captcha_data):
    # captcha_data contains captcha_sitekey, captcha_service (hcaptcha), captcha_rqdata and captcha_rqtoken
    print(f"Captcha!")
    captcha_key = ... # Solve captcha and get captcha_key, you must provide captcha_sitekey and captcha_rqdata to solving service
    return captcha_key

@c.event("on_error")
async def on_error(exc, client):
    print(f"Error: {exc.__class__.__name__}")
    if client.retries == 1:
        await client.run_task()

run(c.run())