from websockets import connect
from websockets.exceptions import ConnectionClosedOK, ConnectionClosedError
from websockets.typing import Origin
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from json import loads, dumps
from base64 import b64decode, b64encode, urlsafe_b64encode
from time import time
from hashlib import sha256
from asyncio import get_event_loop, sleep as asleep
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from aiohttp import ClientSession
import logging

log = logging.getLogger("RemoteAuthClient")

class User:
    def __init__(self, _id, _username, _discriminator, _avatar):
        self.id = _id
        self.username = _username
        self.discriminator = _discriminator
        self.avatar = _avatar

    def getName(self):
        return f"{self.username}#{self.discriminator}"

    def getAvatarURL(self):
        return f"https://cdn.discordapp.com/avatars/{self.id}/{self.avatar}.png"

class RemoteAuthClient:
    def __init__(self):
        self.initCrypto()
        self._heartbeatTask = None

        self.on_fingerprint = self.ev
        self.on_userdata = self.ev
        self.on_token = self.ev
        self.on_cancel = self.ev
        self.on_timeout = self.ev

    def initCrypto(self):
        self.privateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.publicKey = self.privateKey.public_key()
        publicKeyString = self.publicKey.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("utf8")
        self.publicKeyString = "".join(publicKeyString.split("\n")[1:-2])

    def event(self, t):
        def registerhandler(handler):
            if t == "on_fingerprint":
                self.on_fingerprint = handler
            elif t == "on_userdata":
                self.on_userdata = handler
            elif t == "on_token":
                self.on_token = handler
            elif t == "on_cancel":
                self.on_cancel = handler
            elif t == "on_timeout":
                self.on_timeout = handler
            else:
                log.info(f"Unknown event type '{t}'.")
            return handler
        return registerhandler

    def ev(self, *args, **kwargs):
        pass

    async def run(self):
        err = False
        async with connect("wss://remote-auth-gateway.discord.gg/?v=2", origin=Origin("https://discord.com")) as ws:
            while True:
                try:
                    data = await ws.recv()
                except ConnectionClosedOK:
                    break
                except ConnectionClosedError as e:
                    if e.code == 4003:
                        await self.on_timeout()
                    else:
                        err = True
                    break
                p = loads(data)
                if p["op"] == "hello":
                    await self.send({"op": "init", "encoded_public_key": self.publicKeyString}, ws)
                    self._heartbeatTask = get_event_loop().create_task(self.sendHeartbeat(p["heartbeat_interval"], ws))
                elif p["op"] == "nonce_proof":
                    decryptedNonce = self.decryptPayload(p["encrypted_nonce"])
                    nonceHash = sha256()
                    nonceHash.update(decryptedNonce)
                    nonceHash = urlsafe_b64encode(nonceHash.digest()).decode("utf8")
                    nonceHash = nonceHash.replace("/", "").replace("+", "").replace("=", "")
                    await self.send({"op": 'nonce_proof', "proof": nonceHash}, ws)
                elif p["op"] == "pending_remote_init":
                    fingerprint = p["fingerprint"]
                    log.debug(f"Received fingerprint: {fingerprint}.")
                    data = f"https://discordapp.com/ra/{fingerprint}"
                    await self.on_fingerprint(data=data)
                elif p["op"] == "pending_ticket":
                    decryptedUser = self.decryptPayload(p["encrypted_user_payload"]).decode("utf8")
                    log.debug(f"Received userdata: {decryptedUser}.")
                    decryptedUser = decryptedUser.split(':')
                    await self.on_userdata(user=User(decryptedUser[0], decryptedUser[3], decryptedUser[1], decryptedUser[2]))
                elif p["op"] == "pending_login":
                    async with ClientSession() as sess:
                        async with sess.post("https://discord.com/api/v9/users/@me/remote-auth/login", json={"ticket": p["ticket"]}) as resp:
                            assert resp.status == 200
                            encryptedToken = (await resp.json())["encrypted_token"]
                    decryptedToken = self.decryptPayload(encryptedToken).decode("utf8")
                    await self.on_token(token=decryptedToken)
                    break
                elif p["op"] == 'cancel':
                    await self.on_cancel()
                    break
        if self._heartbeatTask:
            self._heartbeatTask.cancel()
        if err:
            log.error("RemoteAuthClient disconnected with error.")
            self.initCrypto()
            log.info("Reconnecting...")
            await self.run()

    async def sendHeartbeat(self, interval, _ws):
        while True:
            await asleep(interval/1000)
            log.debug(f"Sending heartbeat.")
            await self.send({"op": 'heartbeat'}, _ws)

    async def send(self, json, _ws):
        await _ws.send(dumps(json))

    def decryptPayload(self, payload):
        payload = bytes(payload, "utf8")
        payload = b64decode(payload)
        decrypted = self.privateKey.decrypt(payload, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return decrypted
