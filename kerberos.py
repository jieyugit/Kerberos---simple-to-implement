import base64
import os
import sqlite3
import uuid
import snowflake.client

conn = sqlite3.connect('kerberos.db')
c = conn.cursor()

# 创建用户表
c.execute('''CREATE TABLE IF NOT EXISTS users
             (userID TEXT PRIMARY KEY, password TEXT)''')

# 创建服务表
c.execute('''CREATE TABLE IF NOT EXISTS services
             (serviceID TEXT PRIMARY KEY,service TEXT, key TEXT)''')

c.execute('''CREATE TABLE IF NOT EXISTS tgs
             (tgsID TEXT PRIMARY KEY, key TEXT)''')

# 提交更改
conn.commit()


def register_service(serviceName):
    serviceID = str(uuid.uuid1())
    key = base64.b64encode(os.urandom(16)).decode()
    c.execute("INSERT INTO services (serviceID,service, key) VALUES (?, ?, ?)", (serviceID, serviceName, key))
    conn.commit()
    return key


def register_user():
    userID = str(uuid.uuid1())
    rkey = os.urandom(16)
    key = base64.b64encode(rkey).decode()
    c.execute("INSERT INTO users (userID, key) VALUES (?, ?)", (userID, key))
    conn.commit()
    return userID + "||" + key


if __name__ == '__main__':
    pass
