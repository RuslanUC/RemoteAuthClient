from re import findall
from typing import Any, Optional
from websockets import connect
from websockets.exceptions import ConnectionClosedOK, ConnectionClosedError
from websockets.typing import Origin
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from json import loads, dumps
from base64 import b64decode, urlsafe_b64encode, b64encode
from hashlib import sha256
from asyncio import get_event_loop, sleep as asleep, CancelledError
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from aiohttp import ClientSession, BasicAuth
from httpagentparser import detect
import logging

log = logging.getLogger("RemoteAuthClient")

class User:
    def __init__(self, uid, username, discriminator, avatar):
        self.id = uid
        self.username = username
        self.discriminator = discriminator
        self.avatar = avatar

    def getName(self) -> str:
        return f"{self.username}#{self.discriminator}"

    def getAvatarURL(self) -> str:
        return f"https://cdn.discord.com/avatars/{self.id}/{self.avatar}.png"

class RemoteAuthClient:
    def __init__(self, proxy=None, proxy_auth=None, proxy_type="http", user_agent=None, captcha_attempts=1):
        if proxy_type not in ["http", "socks5"]:
            raise ValueError('The proxy type is not supported, choose "http" or "socks5".')
        self._task = None
        self._heartbeatTask = None
        self._ws = None

        self._privateKey = None
        self._publicKey = None
        self._publicKeyString = None

        self.on_fingerprint = self.ev
        self.on_userdata = self.ev
        self.on_token = self.ev
        self.on_cancel = self.ev
        self.on_timeout = self.ev
        self.on_error = self.ev
        self.on_captcha = self.ev

        self._retries = 0
        self._rqtoken = None

        self.captcha_attempts = captcha_attempts
        self.captcha_attempts_use = 0
        self.proxy = proxy
        self.proxy_type = proxy_type
        self.proxy_auth = proxy_auth
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"

    @property
    def retries(self) -> int:
        return self._retries

    def initCrypto(self) -> None:
        self._privateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._publicKey = self._privateKey.public_key()
        publicKeyString = self._publicKey.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("utf8")
        self._publicKeyString = "".join(publicKeyString.split("\n")[1:-2])

    def event(self, t):
        def registerhandler(handler):
            if t not in ("on_fingerprint", "on_userdata", "on_token", "on_cancel", "on_timeout", "on_error", "on_captcha"):
                return log.warning(f"Unknown event type '{t}'.")
            setattr(self, t, handler)
            return handler
        return registerhandler

    async def ev(self, *args, **kwargs) -> None:
        pass

    async def _sendHeartbeat(self, interval: int) -> None:
        while True:
            await asleep(interval/1000)
            log.debug(f"Sending heartbeat.")
            await self._send({"op": 'heartbeat'})

    async def _send(self, json: dict) -> None:
        await self._ws.send(dumps(json))

    def _decryptPayload(self, payload: str) -> bytes:
        payload = bytes(payload, "utf8")
        payload = b64decode(payload)
        decrypted = self._privateKey.decrypt(
            payload,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted

    async def _event(self, name: str, **kwargs) -> Any:
        handler = getattr(self, f"on_{name}")
        if handler is self.ev:
            return
        if "client" in handler.__code__.co_varnames:
            kwargs["client"] = self
        return await handler(**kwargs)

    async def _cleanup(self, cancel_main_task=True) -> None:
        if self._ws:
            await self._ws.close()
        if self._heartbeatTask:
            self._heartbeatTask.cancel()
        if self._task and cancel_main_task:
            self._task.cancel()
        self._privateKey = None
        self._publicKey = None
        self._publicKeyString = None

    async def _getHeaders(self) -> dict:
        headers = {
            "User-Agent": self.user_agent,
            "Accept": '*/*',
            "Content-Type": "application/json",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "X-Debug-Options": "bugReporterEnabled",
        }
        ua = detect(self.user_agent)
        sprop = {
            "os": ua.get("os", {}).get("name", "Windows"),
            "browser": ua.get("browser", {}).get("name", "Chrome"),
            "device": "", "system_locale": "en-US", "browser_user_agent": self.user_agent,
            "browser_version": ua.get("browser", {}).get("version", "103.0.0.0"),
            "os_version": ua.get("os", {}).get("version", "100"),
            "referrer": "", "referring_domain": "", "referrer_current": "", "referring_domain_current": "",
            "release_channel": "stable",  "client_build_number": 154750, "client_event_source": None
        }
        async with ClientSession() as sess:
            r = await sess.get("https://discord.com/login")
            build = findall(r'\{"buildId"\: {0,}"([a-f0-9]{40})"', await r.text())
            if build:
                build = build[0]
                try:
                    r = await sess.get(f"https://api.discord.sale/builds/{build}")
                    r = await r.json()
                    sprop["client_build_number"] = r.get("number", 154750)
                except:
                    pass
        headers["X-Super-Properties"] = b64encode(dumps(sprop).encode("utf8")).decode("utf8")
        return headers

    async def _getToken(self, ticket: str, captcha_key: Optional[str]=None) -> Optional[str]:
        _proxy = {}
        if self.proxy:
            _proxy["proxy"] = f"{self.proxy_type}://{self.proxy}"
            if self.proxy_auth:
                _proxy["proxy_auth"] = BasicAuth(**self.proxy_auth)
        async with ClientSession(headers=await self._getHeaders()) as sess:
            data = {"ticket": ticket}
            if captcha_key:
                data["captcha_key"] = captcha_key
                data["captcha_rqtoken"] = self._rqtoken
            log.debug(f"Trying to get a token with request body: {data}")
            resp = await sess.post("https://discord.com/api/v9/users/@me/remote-auth/login", json=data, **_proxy)
            j = await resp.json()
            log.debug(f"Response code: {resp.status}")
            log.debug(f"Response body: {j}")
            if "encrypted_token" not in j and "captcha_key" in j and self.captcha_attempts_use < self.captcha_attempts:
                log.debug(f"Detected captcha response. Calling on_captcha method with {j}")
                del j["captcha_key"]
                self.captcha_attempts_use += 1
                self._rqtoken = j["captcha_rqtoken"]
                captcha_key = await self._event("captcha", captcha_data=j)
                log.debug(f"on_captcha result: {captcha_key}")
                if not captcha_key:
                    return
                return await self._getToken(ticket, captcha_key)
            return j["encrypted_token"] if "encrypted_token" in j else None

    async def _run(self) -> None:
        err = None
        while True:
            try:
                data = await self._ws.recv()
            except ConnectionClosedOK:
                break
            except ConnectionClosedError as e:
                if e.code == 4003:
                    await self.on_timeout()
                else:
                    err = e
                break
            p = loads(data)
            if p["op"] == "hello":
                await self._send({"op": "init", "encoded_public_key": self._publicKeyString})
                self._heartbeatTask = get_event_loop().create_task(self._sendHeartbeat(p["heartbeat_interval"]))
            elif p["op"] == "nonce_proof":
                decryptedNonce = self._decryptPayload(p["encrypted_nonce"])
                nonceHash = sha256()
                nonceHash.update(decryptedNonce)
                nonceHash = urlsafe_b64encode(nonceHash.digest()).decode("utf8")
                nonceHash = nonceHash.replace("/", "").replace("+", "").replace("=", "")
                await self._send({"op": 'nonce_proof', "proof": nonceHash})
            elif p["op"] == "pending_remote_init":
                fingerprint = p["fingerprint"]
                log.debug(f"Received fingerprint: {fingerprint}.")
                data = f"https://discord.com/ra/{fingerprint}"
                await self._event("fingerprint", data=data)
            elif p["op"] == "pending_ticket":
                decryptedUser = self._decryptPayload(p["encrypted_user_payload"]).decode("utf8")
                log.debug(f"Received userdata: {decryptedUser}.")
                decryptedUser = decryptedUser.split(':')
                user = User(decryptedUser[0], decryptedUser[3], decryptedUser[1], decryptedUser[2])
                await self._event("userdata", user=user)
            elif p["op"] == "pending_login":
                encryptedToken = await self._getToken(p["ticket"])
                if not encryptedToken:
                    log.error("Unable to get a token.")
                else:
                    decryptedToken = self._decryptPayload(encryptedToken).decode("utf8")
                    await self._event("token", token=decryptedToken)
                break
            elif p["op"] == 'cancel':
                get_event_loop().create_task(self._event("cancel"))
                break
        await self._cleanup(cancel_main_task=False)
        if err:
            log.error("RemoteAuthClient disconnected with error.", err)
            get_event_loop().create_task(self._event("error", error=err))

    async def run(self) -> None:
        await self.run_task()
        try:
            await self._task
        except CancelledError:
            pass

    async def run_task(self) -> None:
        await self._cleanup()
        self._retries += 1
        self.initCrypto()
        self._ws = await connect(
            "wss://remote-auth-gateway.discord.gg/?v=2",
            origin=Origin("https://discord.com")
        ).__await_impl__()
        self._task = get_event_loop().create_task(self._run())

    async def cancel(self) -> None:
        await self._cleanup()
        await self._event("cancel")
