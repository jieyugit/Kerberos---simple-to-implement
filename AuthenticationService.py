import base64
import json
import os
import sqlite3
from flask import Flask, request
import datetime
from dateutil.parser import parse
from gmssl.sm4 import CryptSM4

from TimeStamp import ValidTimestamp
from util.sm4Util import encrypt, decrypt

app = Flask(__name__)
conn = sqlite3.connect("./kerberos.db", check_same_thread=False)
cursor = conn.cursor()
crypt_sm4 = CryptSM4()





@app.route('/AuthenticationServer', methods=["POST"])
def AuthenticationServer():
    # 在数据库中检索是否含有这个用户
    try:
        # userID = request.json.get('userID')
        # timestamp = request.json.get('timestamp')
        # serviceName = request.json.get('serviceName')
        # print(userID)
        # print(timestamp)
        # print(serviceName)

        userID = request.json.get('userID')
        timestamp = request.json.get('timestamp')
        serviceName = request.json.get('serviceName')
    except AttributeError:
        data = {
            "code": "-1",
            "msg": "参数错误"
        }
        response = json.dumps(data, ensure_ascii=False)
        return response, 200, {"Content-Type": "application/json"}

    flag = ValidTimestamp(timestamp, 2)
    if flag is False:
        data = {
            "code": "-1",
            "msg": "时间过期"
        }
        response = json.dumps(data, ensure_ascii=False)
        return response, 200, {"Content-Type": "application/json"}

    # 查询用户
    cursor.execute("select * from users where userID = ?", [(userID)])
    User_obj = cursor.fetchone()

    # 查询服务对应的ID
    sql = "select * from services where service = ?"
    cursor.execute(sql, [serviceName])
    Service_Obj = cursor.fetchone()

    # 查询TGS key
    cursor.execute("select * from tgs where tgsID = ?", [("ec5aa6a0-816b-11ee-8e9d-38f3abc19342")])
    tgs_obj = cursor.fetchone()

    # 有这条数据
    if User_obj and Service_Obj:
        list1 = []
        list2 = []
        key = User_obj[1]  # 获得用户的加密key
        Service_ID = Service_Obj[0]  # 获取服务ID
        TGS_Session_Key = os.urandom(16)  # 生成SM4加密密钥
        lifetime = (datetime.datetime.now() + datetime.timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")  # 设置过期时间

        list1.append(Service_ID)
        list1.append(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        list1.append(lifetime)
        list1.append(base64.b64encode(TGS_Session_Key).decode())

        M1 = "||".join(list1)  # 构造发送给用户的数据

        key_for_encrypt_TGT = tgs_obj[1]
        list2.append(userID)
        list2.append(Service_ID)
        list2.append(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        list2.append(lifetime)
        list2.append(base64.b64encode(TGS_Session_Key).decode())

        M2 = "||".join(list2)

        eM1 = encrypt(crypt_sm4, base64.b64decode(key.encode()), bytes(M1, encoding="utf8"))

        eM2 = encrypt(crypt_sm4, base64.b64decode(key_for_encrypt_TGT.encode()), bytes(M2, encoding="utf8"))

        res = eM1 + "||" + eM2

        data = {
            "code": "200",
            "msg": res
        }
        response = json.dumps(data, ensure_ascii=False)
        return response, 200, {"Content-Type": "application/json"}





if __name__ == '__main__':
    app.run(port=8100)
