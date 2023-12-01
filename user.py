import argparse
import base64
import datetime

import requests

from util.sm4Util import decrypt
from gmssl.sm4 import CryptSM4
from util.sm4Util import encrypt
from TimeStamp import ValidTimestamp, ValidTimestamp2

crypt_sm4 = CryptSM4()



def step1(userID, key):
    data = {
        "userID": userID,
        "timestamp": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "serviceName": "HTTP"
    }
    print("用户发送数据包 ===> ",data,"\n")
    response = requests.post(url='http://127.0.0.1:8100/AuthenticationServer', json=data)
    t = response.json().get("msg")
    crypt_sm4 = CryptSM4()
    print("接收到数据包 ===> ", response.json()),"\n"
    dec_value = decrypt(crypt_sm4, base64.b64decode(key.encode()), t.split("||")[0])
    # print(dec_value)
    print("用userKey解密用户数据包 ===> ",dec_value,"\n")
    print("TGT数据包 ===> ",t.split("||")[1],"\n")

    dict = {
        "TGSSK": dec_value,
        "TGT": t.split("||")[1]
    }
    # dec_value = decrypt(crypt_sm4, base64.b64decode(key.encode()), t.split("||")[1])
    # print(dec_value)
    return dict


def step2(TGT, userID, sessionKey):
    pkg = userID + "||" + datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print("用户数据包为===> ",pkg,"\n")
    pkg = encrypt(crypt_sm4, base64.b64decode(sessionKey.encode()), bytes(pkg, encoding="utf8"))
    print("SM4加密用户数据包===> ", pkg,"\n")
    data = {
        "pkg": pkg,
        "TGT": TGT
    }
    print("用户发送数据包 ===> ", data,"\n")
    response = requests.post(url='http://127.0.0.1:8101/TGS', json=data)
    print("接收到数据包 ===> ", response.json(),"\n")
    return response.json().get("MsgE"), response.json().get("MsgF")


def step3(MsgE, userID, ServerSessionKey):
    uMsgG = userID + "||" + datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print("用户数据包为===> ", uMsgG,"\n")
    MsgG = encrypt(crypt_sm4, base64.b64decode(ServerSessionKey.encode()), bytes(uMsgG, encoding="utf8"))
    print("SM4加密用户数据包===> ", MsgG,"\n")
    data = {
        "MsgG": MsgG,
        "MsgE": MsgE
    }
    print("用户发送数据包 ===> ", data,"\n")
    response = requests.post(url='http://127.0.0.1:8102/SS', json=data)
    print("接收到数据包 ===> ", response.json(),"\n")
    print(response.text,"\n")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("userID")
    parser.add_argument("UserKey")

    args = parser.parse_args()

    userID = args.userID
    key = args.UserKey

    print("==============客户端与 Authentication Service=================")
    dic1 = step1(userID, key)
    step1info = dic1.get("TGSSK").split("||")
    serviceID = step1info[0]
    timestamp = step1info[1]
    lifetime = step1info[2]
    TGSsessionKey = step1info[3]


    print("解密 ====== >")
    print("====> serviceID: ",serviceID)
    print("====> timestamp: ", timestamp)
    print("====> lifetime: ", lifetime)
    print("====> TGSsessionKey: ", TGSsessionKey)

    print("\n********用户验证服务器的时间戳**********")
    step1Time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print("*====>现在时间为: ", step1Time)
    print("*====>得到的数据中时间戳为: ", timestamp)
    print("*验证结果为: ", )
    if ValidTimestamp2(step1Time, timestamp, 2) is False:
        print("用户侧验证失败 退出....")
        exit(-1)
    print("**********************************************\n")
    print("=============================End============================")
    print("\n")


    print("==============客户端与 Ticket Granting Service=================")
    TGT = dic1.get("TGT")
    MsgE, MsgF = step2(TGT, userID, TGSsessionKey)
    dec_value = decrypt(crypt_sm4, base64.b64decode(TGSsessionKey.encode()), MsgF)
    print("用TGSsessionKey解密用户数据包 ===> ")
    print("====> TGSsessionKey: ", TGSsessionKey)
    TGSsessionKeyData = dec_value.split("||")
    print("解密 ====== >")
    print("====> userID: ",TGSsessionKeyData[0] )
    print("====> timestamp: ", TGSsessionKeyData[1])
    print("====> ServerSessionKey: ", TGSsessionKeyData[2])



    print("\n********用户验证服务器是否是对自己进行验证**********")
    print("*====>userID为: ",userID)
    print("*====>得到的数据中userID为: ",TGSsessionKeyData[0])
    print("*验证结果为: ",userID==TGSsessionKeyData[0])
    if userID == TGSsessionKeyData[0] is False :
        print("用户侧验证失败 退出....")
        exit(-1)
    print("**********************************************\n")

    print("\n********用户验证服务器的时间戳**********")
    step2Time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print("*====>现在时间为: ", step2Time)
    print("*====>得到的数据中时间戳为: ", TGSsessionKeyData[1])
    print("*验证结果为: ", )
    if ValidTimestamp2(step2Time,TGSsessionKeyData[1],2)  is False:
        print("用户侧验证失败 退出....")
        exit(-1)
    print("**********************************************\n")

    print("=============================End============================")
    print("\n")

    print("==============客户端与 Service=================")
    ServerSessionKey = dec_value.split("||")[2]
    print("====> 获取ServerSessionKey: ", ServerSessionKey)
    step3(MsgE, userID, ServerSessionKey)
    print("=============================End============================")