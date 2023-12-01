import base64
import json
import os
import sqlite3
from flask import Flask, request
import datetime
from dateutil.parser import parse
from gmssl.sm4 import CryptSM4
from TimeStamp import ValidTimestamp2, ValidTimestamp
from util.sm4Util import encrypt, decrypt

app = Flask(__name__)
crypt_sm4 = CryptSM4()
MyServiceKey = "R7+AjJ0HqqkhxQ/rY/E+Vw=="


@app.route('/SS', methods=["POST"])
def SS():
    try:

        MsgE = request.json.get('MsgE')
        MsgG = request.json.get('MsgG')
    except AttributeError:
        data = {
            "code": "-1",
            "msg": "参数错误"
        }
        response = json.dumps(data, ensure_ascii=False)
        return response, 200, {"Content-Type": "application/json"}

    dec_value = decrypt(crypt_sm4, base64.b64decode(MyServiceKey.encode()), MsgE)
    # print(dec_value)
    TicketData = dec_value.split("||")
    TicketData_userID = TicketData[0]
    TicketData_ServiceID = TicketData[1]
    TicketData_Timestamp = TicketData[2]
    TicketData_lifeTime = TicketData[3]
    TicketData_ServiceSeesionKey = TicketData[4]

    userDataValue = decrypt(crypt_sm4, base64.b64decode(TicketData_ServiceSeesionKey.encode()), MsgG)
    userData = userDataValue.split("||")
    # print(userData)
    # print(dec_value)
    # print(userData[0] == TicketData[0])
    # print(ValidTimestamp2(userData[1], TicketData[2], 2))
    # print(ValidTimestamp(TicketData[3], 0))

    if userData[0] == TicketData[0] and ValidTimestamp2(userData[1], TicketData[2], 2) and ValidTimestamp(TicketData[3],
                                                                                                          0):
        data = {
            "code": "200",
            "msg": "服务认证成功",
        }
        response = json.dumps(data, ensure_ascii=False)
        return response, 200, {"Content-Type": "application/json"}

    data = {
        "code": "-1",
        "msg": "服务认证失败",
    }
    response = json.dumps(data, ensure_ascii=False)
    return response, 200, {"Content-Type": "application/json"}


if __name__ == '__main__':
    app.run(port=8102)
