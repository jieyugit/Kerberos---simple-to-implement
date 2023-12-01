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
conn = sqlite3.connect("./kerberos.db", check_same_thread=False)
cursor = conn.cursor()
crypt_sm4 = CryptSM4()
tgs_key = "2UIckP3tCYFc+oUroceU3g=="


@app.route('/TGS', methods=["POST"])
def TGS():
    try:

        TGT = request.json.get('TGT')
        TGSSK = request.json.get('pkg')
    except AttributeError:
        data = {
            "code": "-1",
            "msg": "参数错误"
        }
        response = json.dumps(data, ensure_ascii=False)
        return response, 200, {"Content-Type": "application/json"}

    dec_value = decrypt(crypt_sm4, base64.b64decode(tgs_key.encode()), TGT)

    # 查找服务密钥
    cursor.execute("select key from services where serviceID = ?", [(dec_value.split("||")[1])])
    ServiceKey = cursor.fetchone()[0]
    # print(dec_value)
    TGSsessionKey = dec_value.split("||")[4]  # 得到Key

    TGTdata = decrypt(crypt_sm4, base64.b64decode(TGSsessionKey.encode()), TGSSK)
    # print(TGTdata)

    list1 = dec_value.split("||")
    list2 = TGTdata.split("||")
    if list1[0] == list2[0] and ValidTimestamp2(list1[2], list2[1], 2) and ValidTimestamp(dec_value.split("||")[3], 0):
        ServiceSessionKey = os.urandom(16)
        userpkg = list1[0] + "||" + datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "||" + base64.b64encode(
            ServiceSessionKey).decode()
        MsgF = encrypt(crypt_sm4, base64.b64decode(TGSsessionKey.encode()), bytes(userpkg, encoding="utf8"))

        userID = list1[0]
        ServiceID = list1[1]
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        lifetime = (datetime.datetime.now() + datetime.timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")  # 设置过期时间
        list_MsgE = [userID, ServiceID, timestamp, lifetime, base64.b64encode(ServiceSessionKey).decode()]
        uMsgE = "||".join(list_MsgE)
        MsgE = encrypt(crypt_sm4, base64.b64decode(ServiceKey.encode()), bytes(uMsgE, encoding="utf8"))
        data = {
            "code": "200",
            "msg": "success",
            "MsgF": MsgF,
            "MsgE": MsgE
        }
        response = json.dumps(data, ensure_ascii=False)
        return response, 200, {"Content-Type": "application/json"}


if __name__ == '__main__':
    app.run(port=8101)
