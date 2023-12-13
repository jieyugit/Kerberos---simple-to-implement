import argparse
import base64
import datetime
import json
from time import sleep

import requests

from kerberos import register_user, register_service
from util.sm4Util import decrypt
from gmssl.sm4 import CryptSM4
from util.sm4Util import encrypt
from TimeStamp import ValidTimestamp, ValidTimestamp2

crypt_sm4 = CryptSM4()


def step1(userID, key):
    print("========== 步骤 1: 客户端向认证服务器发送请求 ==========")
    serviceName = input("输入需要请求的服务名称")
    data = {
        "userID": userID,
        "timestamp": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "serviceName": str(serviceName)
    }
    print("\n[发送数据包]")
    print(json.dumps(data, indent=4), "\n")  # 美化打印

    response = requests.post(url='http://127.0.0.1:8100/AuthenticationServer', json=data)
    t = response.json().get("msg")

    print("\n[接收到的响应]")
    print(json.dumps(response.json(), indent=4), "\n")  # 美化打印

    print("\n[解密用户数据包]")
    dec_value = decrypt(crypt_sm4, base64.b64decode(key.encode()), t.split("||")[0])
    print(dec_value, "\n")

    print("\n[TGT数据包]")
    print(t.split("||")[1], "\n")

    print("\n========== 步骤 1 结束 ==========\n")

    dict = {
        "TGSSK": dec_value,
        "TGT": t.split("||")[1]
    }
    # 返回结果
    return dict


def step2(TGT, userID, sessionKey):
    #print("\n========== 步骤 2: 加密和发送数据 ==========")

    # 创建用户数据包
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    pkg = f"{userID}||{timestamp}"
    print("\n[创建用户数据包]")
    print(f"  数据包内容: {pkg}")

    # 加密用户数据包
    pkg_encrypted = encrypt(crypt_sm4, base64.b64decode(sessionKey.encode()), bytes(pkg, encoding="utf8"))
    print("\n[加密用户数据包]")
    print(f"  加密后数据: {pkg_encrypted}")

    # 发送数据包
    data = {"pkg": pkg_encrypted, "TGT": TGT}
    print("\n[发送数据包]")
    print(json.dumps(data, indent=4))

    # 发送请求并接收响应
    response = requests.post(url='http://127.0.0.1:8101/TGS', json=data)
    print("\n[接收到的响应]")
    print(json.dumps(response.json(), indent=4))

    print("============================================\n")

    return response.json().get("MsgE"), response.json().get("MsgF")


def step3(MsgE, userID, ServerSessionKey):
    #print("\n========== 构建和发送加密数据包 ==========")

    # 构建用户数据包
    uMsgG = f"{userID}||{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    print("\n[构建用户数据包]")
    print(f"  数据包内容: {uMsgG}")

    # 加密用户数据包
    MsgG = encrypt(crypt_sm4, base64.b64decode(ServerSessionKey.encode()), bytes(uMsgG, encoding="utf8"))
    print("\n[SM4加密用户数据包]")
    print(f"  加密后数据: {MsgG}")

    # 准备发送的数据包
    data = {"MsgG": MsgG, "MsgE": MsgE}
    print("\n[准备发送的数据包]")
    print(json.dumps(data, indent=4))

    # 发送数据包并接收响应
    print("\n[发送数据包并接收响应]")
    response = requests.post(url='http://127.0.0.1:8102/SS', json=data)
    print(json.dumps(response.json(), indent=4))

    print("\n原始响应文本:")
    print(response.text)



if __name__ == '__main__':
    # parser = argparse.ArgumentParser()
    # parser.add_argument("type")
    # parser.add_argument("userID")
    # parser.add_argument("UserKey")
    #
    # args = parser.parse_args()
    # SelectedType = args.type
    # userID = args.userID
    # key = args.UserKey

    parser = argparse.ArgumentParser(description='操作')
    subparsers = parser.add_subparsers(dest='type', help='类型')

    # 创建注册用户的子命令
    user_parser = subparsers.add_parser('registerUser', help='注册新用户')

    # 创建注册服务的子命令
    service_parser = subparsers.add_parser('registerService', help='注册新服务')
    service_parser.add_argument('serviceName', help='服务的名称')

    vaild_parser = subparsers.add_parser('vaild', help='认证')
    vaild_parser.add_argument('userID', help='服务的名称')
    vaild_parser.add_argument('UserKey', help='服务的名称')


    args = parser.parse_args()




    if args.type=='registerUser':
        userinfo = register_user().split("||")
        print("************ 注册用户成功 *************")
        print(f"  userID      : {userinfo[0]}")
        print(f"  userKey     : {userinfo[1]}")
        print("***********************************\n")

    elif args.type=='registerService':
        ret = register_service(args.serviceName)
        if ret is None:
            print("************ 注册服务失败 *************")
            print(f"  info      : 服务名已存在")
            print("***********************************\n")
        else:
            print("************ 注册服务成功 *************")
            print(f"  serviceName      : {args.serviceName}")
            print(f"  serviceKey       : {ret}")
            print("***********************************\n")
    elif args.type=='vaild':
        userID = args.userID
        key = args.UserKey
        # print("==============客户端与 Authentication Service=================")
        dic1 = step1(userID, key)
        step1info = dic1.get("TGSSK").split("||")
        serviceID, timestamp, lifetime, TGSsessionKey = step1info

        sleep(2)
        print("\n\n=============== 步骤 1 用户验证开始 ===============\n")

        print("\n********** 步骤 1 解密结果 ************")
        print(f"  serviceID      : {serviceID}")
        print(f"  timestamp      : {timestamp}")
        print(f"  lifetime       : {lifetime}")
        print(f"  TGSsessionKey  : {TGSsessionKey}")
        print("*************************************\n")

        print("************ 验证服务器时间戳 *************")
        step1Time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"* 当前时间      : {step1Time}")
        print(f"* 数据中时间戳  : {timestamp}")

        validation_result = ValidTimestamp2(step1Time, timestamp, 2)
        print(f"* 验证结果      : {'成功' if validation_result else '失败'}")

        if not validation_result:
            print("用户侧验证失败，退出程序...")
            exit(-1)

        print("******************************************\n")
        print("=============== 步骤 1 验证结束 ===============\n")
        sleep(2)

        TGT = dic1.get("TGT")
        print("\n========== 步骤 2: 客户端与 Ticket Granting Service ==========")

        # 解密数据包
        MsgE, MsgF = step2(TGT, userID, TGSsessionKey)
        sleep(2)
        dec_value = decrypt(crypt_sm4, base64.b64decode(TGSsessionKey.encode()), MsgF)

        print("\n[解密用户数据包]")
        print(f"  使用的 TGS Session Key: {TGSsessionKey}")
        TGSsessionKeyData = dec_value.split("||")

        print("\n[解密结果]")
        print(f"  UserID           : {TGSsessionKeyData[0]}")
        print(f"  Timestamp        : {TGSsessionKeyData[1]}")
        print(f"  ServerSessionKey : {TGSsessionKeyData[2]}")

        # 验证用户ID
        print("\n******** 验证服务器是否对用户进行验证 ********")
        print(f"* 本地 UserID    : {userID}")
        print(f"* 解密后 UserID  : {TGSsessionKeyData[0]}")
        validation_result = userID == TGSsessionKeyData[0]
        print(f"* 验证结果       : {'成功' if validation_result else '失败'}")

        if not validation_result:
            print("用户侧验证失败，退出程序...")
            exit(-1)

        # 验证时间戳
        print("\n******** 验证服务器的时间戳 ********")
        step2Time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"* 当前时间       : {step2Time}")
        print(f"* 解密后时间戳   : {TGSsessionKeyData[1]}")
        timestamp_validation = ValidTimestamp2(step2Time, TGSsessionKeyData[1], 2)
        print(f"* 验证结果       : {'成功' if timestamp_validation else '失败'}")

        if not timestamp_validation:
            print("时间戳验证失败，退出程序...")
            exit(-1)

        print("==========================================================\n")
        sleep(2)
        print("\n============== 步骤 3: 客户端与服务交互 ==============")

        # 提取 Server Session Key
        ServerSessionKey = dec_value.split("||")[2]
        print("\n[获取 Server Session Key]")
        print(f"  Server Session Key: {ServerSessionKey}")

        # 执行第三步骤
        step3(MsgE, userID, ServerSessionKey)

        print("\n============================= 步骤 3 结束 =============================\n")
        print("可以与服务开始后续通信......")
    else:
        parser.print_help()