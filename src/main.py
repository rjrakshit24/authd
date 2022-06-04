#!/usr/bin/env python3
import asyncio
from asyncio.log import logger
from pickle import FALSE
import time
import tomlkit
import sys
import messageStructure_pb2 as proto
from google.protobuf.message import DecodeError
from passlib.context import CryptContext
import os
import logging
logging.basicConfig(level=logging.DEBUG)
SERVER_PORT = 1300
SERVER_IP = "0.0.0.0"

class UserDB:

    myCryptCtx=CryptContext(schemes=['bcrypt','sha256_crypt','sha512_crypt','argon2'])

    @classmethod
    def setDB(cls, userDB):
        cls.users = {x['username']:x['password_hash'] for x in userDB}

    @classmethod
    def verifyUser(cls, username: str, password: str):
        pHash=cls.users.get(username)
        if pHash and cls.myCryptCtx.verify(password,pHash):
            return True
        return False            

class Firewall:
    iptable = dict()
    
    @classmethod
    def insertIP(cls, ip):
        cls.iptable.update({
            ip : {
                "block" : False,
                "timestamps" : list() #Will store only 3 time stamps
                }
        })
    
    @classmethod
    def logIP(cls, ip, t):
        if not cls.iptable.get(ip):
            cls.insertIP(ip)

        x = cls.iptable.get(ip)
        x['block']=False
        if len(x['timestamps']) == 3:
            x['timestamps'].pop(0)
        x['timestamps'].append(t)
        x['timestamps'].sort()
        cls.isBlockedIP(ip)
        
    @classmethod
    def blacklistIP(cls, ip):
        if not cls.iptable.get(ip):
            cls.insertIP(ip)

        cls.iptable.get(ip)['block']=True

    @classmethod
    def isBlockedIP(cls, ip):
        if cls.iptable.get(ip):
            x = cls.iptable.get(ip)
            if len(x['timestamps'])==3:
                if (x['timestamps'][2] - x['timestamps'][0]) <= 30:
                    x['block'] = True
            return x['block']
        return False

    @classmethod
    def reset(cls):
        cls.iptable.clear()

async def expressionMessageHandler(request: proto.Request, peer_addr, peer_port, recv_time):
    response = proto.Response()
    if UserDB.verifyUser(request.expr.username, request.expr.password):
        
        try:
            p = await asyncio.create_subprocess_exec(sys.executable,"-c",request.expr.expression,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(p.communicate(), timeout=5)
            if stderr:
                response = None
                Firewall.logIP(peer_addr,recv_time)
            
            elif stdout:
                response.expr.authenticated = True
                response.expr.result = stdout

        except Exception as e:
            p.kill()
            Firewall.blacklistIP(peer_addr)
            response = None
    else:
        response.expr.authenticated = False
        response.expr.result = "undefined"
        Firewall.logIP(peer_addr,recv_time)

    return response

async def resetMessageHandler(request: proto.Request, peer_addr, peer_port, recv_time):
    response = proto.Response()
    Firewall.reset()
    response.reset.CopyFrom(proto.ResetBlockListsResponse())
    return response

async def stopMessageHandler(request: proto.Request, peer_addr, peer_port, recv_time):
    response = proto.Response()
    response.stop.CopyFrom(proto.StopResponse())
    return response

async def ipValidator(peer_addr, peer_port):
    return Firewall.isBlockedIP(peer_addr)

async def processClient(clientReader: asyncio.StreamReader, clientWriter: asyncio.StreamWriter):
    peer_addr, peer_port = clientWriter.get_extra_info("peername")
    recv_time = time.time()

    try:
        request_size = int.from_bytes(await asyncio.wait_for(clientReader.readexactly(2),timeout=10), byteorder="big")
        request_data = await asyncio.wait_for(clientReader.readexactly(request_size),timeout=10)
        request = proto.Request()
        request.ParseFromString(request_data)

        if request.HasField('stop'):
            rsp = await stopMessageHandler(request, peer_addr, peer_port, recv_time)
            if type(rsp)==proto.Response:
                resp_data = rsp.SerializeToString()
                clientWriter.write(len(resp_data).to_bytes(2,byteorder="big"))
                clientWriter.write(resp_data)
                await clientWriter.drain()
            os.kill(os.getpid(),os.WSTOPPED)

        elif request.HasField('reset'):
            rsp = await resetMessageHandler(request, peer_addr, peer_port, recv_time)
            if type(rsp)==proto.Response:
                resp_data = rsp.SerializeToString()
                clientWriter.write(len(resp_data).to_bytes(2,byteorder="big"))
                clientWriter.write(resp_data)
                await clientWriter.drain()

        elif request.HasField('expr'):
            p = await ipValidator(peer_addr,peer_port)
            if not p:
                logging.info("Yes")
                rsp = await expressionMessageHandler(request, peer_addr, peer_port, recv_time)
                if type(rsp)==proto.Response:
                    x = await ipValidator(peer_addr,peer_port)
                    if not x:
                        logging.info("Sending Response")
                        resp_data = rsp.SerializeToString()
                        clientWriter.write(len(resp_data).to_bytes(2,byteorder="big"))
                        clientWriter.write(resp_data)
                        await clientWriter.drain()
        else:
            Firewall.logIP(peer_addr,recv_time)

    except DecodeError as e:
        Firewall.logIP(peer_addr,recv_time)
    
    except asyncio.TimeoutError as e:
        Firewall.blacklistIP(peer_addr)
    
    except KeyboardInterrupt as e:
        os._exit(0)
    except Exception as e:
        Firewall.logIP(peer_addr,recv_time)
    
    finally:
        clientWriter.close()
        await clientWriter.wait_closed()

async def processClients(r,w,sem):
    async with sem:
        await processClient(r,w)
        
async def run_server():
    sem = asyncio.Semaphore(7)
    server = await asyncio.start_server((lambda r,w: processClients(r,w,sem)), SERVER_IP,SERVER_PORT)
    async with server:
        await server.serve_forever()
        
def main():

    userDBFile = sys.argv[1]
    UserDB.setDB(tomlkit.load(open(userDBFile, 'r'))['users'])
    asyncio.run(run_server())

if __name__ == "__main__":
    main()