# Kerberos - simple to implement

## Directory structure

```
│  AuthenticationService.py
│  HTTPServer.py
│  kerberos.db
│  kerberos.py
│  requirements.txt
│  TicketGrantingService.py
│  TimeStamp.py
│  user.py
└─util
    │  APIResponse.py
    │  sm4Util.py
```



## Install

```
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt
```



## Run

To run the following three files separately in the terminals：` TicketGrantingService.py` `HTTPServer.py` `AuthenticationService.py`



## Usage

### View the user information

Check the corresponding `userID` and `key` in the database (you can't see them directly in the Community Edition)

![](https://imagerepoyu.oss-cn-hangzhou.aliyuncs.com/blogimage-20231113125526300.png)

![image-20231113125601133](https://imagerepoyu.oss-cn-hangzhou.aliyuncs.com/blogimage-20231113125601133.png)



## Request verification

```shell
python .\user.py [userID] [key]
```

![image-20231113125659646](https://imagerepoyu.oss-cn-hangzhou.aliyuncs.com/blogimage-20231113125659646.png)

You can see the complete authentication process on the **user side**:

![image-20231113125835642](https://imagerepoyu.oss-cn-hangzhou.aliyuncs.com/blogblogimage-20231113125835642.png)
