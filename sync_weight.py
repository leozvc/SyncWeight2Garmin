import requests
import json
import argparse
from datetime import datetime
import hashlib
import time
import base64
import urllib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import os

class WeightSync:
    def __init__(self):
        self.yunmai_base_url = "http://intl.yunmai.com/app/"
        self.garmin_base_url = "https://cn.garmin.com/api/"
        self.token_file = "yunmai_token.json"  # 用于存储token的文件
        
    def encrypt_account_password(self, account, password):
        """使用RSA加密账号密码"""
        account_b64 = base64.b64encode(account.encode()).decode()
        account_URI = urllib.parse.quote(account_b64)

        rsakey = RSA.importKey(
            "-----BEGIN PUBLIC KEY-----\n"
            "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJKcIu+iATe0QPGIVDzMYsMA6kH9FcY9\n"
            "Or0I4WJJfEgw/N2e0Us/9JVV1CwdV6W2XIl4KqTeH3ydw6tagagPkSsCAwEAAQ==\n"
            "-----END PUBLIC KEY-----\n"
        )
        cipher = PKCS1_v1_5.new(rsakey)
        cipher_text = base64.b64encode(cipher.encrypt(password.encode("utf-8")))
        password_RSA = cipher_text.decode("utf-8").replace("\n", "")  # Remove newlines
        password_URI = urllib.parse.quote(password_RSA)

        return account_b64, account_URI, password_RSA, password_URI
        
    def save_token(self, phone, refresh_token, user_id):
        """保存token到本地文件"""
        token_data = {
            "phone": phone,
            "refresh_token": refresh_token,
            "user_id": user_id,
            "timestamp": int(time.time())
        }
        try:
            with open(self.token_file, 'w') as f:
                json.dump(token_data, f)
        except Exception as e:
            print(f"保存token失败: {str(e)}")

    def load_token(self, phone):
        """从本地文件加载token"""
        try:
            if not os.path.exists(self.token_file):
                return None, None
            
            with open(self.token_file, 'r') as f:
                token_data = json.load(f)
            
            # 验证token是否属于当前用户
            if token_data.get("phone") != phone:
                return None, None
            
            # 验证token是否过期（7天）
            if int(time.time()) - token_data.get("timestamp", 0) > 7 * 24 * 3600:
                return None, None
            
            return token_data.get("refresh_token"), token_data.get("user_id")
        except Exception as e:
            print(f"加载token失败: {str(e)}")
            return None, None

    def get_yunmai_data(self, phone, password):
        """从云麦获取体重数据"""
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "google/android(10,29) channel(huawei) app(4.25,42500010)screen(w,h=1080,1794)/scale",
        }
        
        timestamp = str(int(time.time()))
        code = timestamp[:8] + "00"
        
        # 尝试从本地加载token
        refresh_token, user_id = self.load_token(phone)
        
        session = requests.Session()
        session.verify = False
        requests.packages.urllib3.disable_warnings()
        
        if refresh_token and user_id:
            print("使用缓存的refreshToken...")
            # 尝试使用缓存的token
            token_sign = f"code={code}&refreshToken={refresh_token}&signVersion=3&versionCode=2&secret=AUMtyBDV3vklBr6wtA2putAMwtmVcD5b"
            token_data = (
                f"code={code}&refreshToken={refresh_token}&sign={hashlib.md5(token_sign.encode()).hexdigest()}"
                f"&signVersion=3&versionCode=2"
            )
            
            try:
                token_resp = session.post(
                    "https://account.iyunmai.com/api/android/auth/token.d",
                    data=token_data,
                    headers=headers,
                    timeout=10
                )
                
                token_json = token_resp.json()
                if token_json["result"]["code"] == 0:
                    access_token = token_json["data"]["accessToken"]
                    print("refreshToken有效，获取accessToken成功")
                else:
                    print("refreshToken已失效，需要重新登录")
                    refresh_token = None
            except Exception as e:
                print(f"使用refreshToken获取accessToken失败: {str(e)}")
                refresh_token = None
        
        if not refresh_token:
            print("开始云麦登录流程...")
            # 原有的登录流程代码
            deviceUUID = "abcd"
            userId = "199999999"
            
            account_b64, account_URI, password_RSA, password_URI = self.encrypt_account_password(phone, password)
            
            print("\n=== 签名细节 ===")
        print("\n=== 签名细节 ===")
        print(f"手机号: {phone}")
        print(f"手机号Base64编码: {account_b64}")
        print(f"手机号URI编码: {account_URI}")
        print(f"密码RSA: {password_RSA}")
        print(f"密码URI编码: {password_URI}")
        
        loginsign = (
            f"code={code}&deviceUUID={deviceUUID}&loginType=1&password={password_RSA}\n"
            f"&signVersion=3&userId={userId}&userName={account_b64}\n"
            f"&versionCode=7&secret=AUMtyBDV3vklBr6wtA2putAMwtmVcD5b"
        )
        
        print("\n=== 登录签名字符串详情 ===")
        print("原始签名字符串:")
        print(loginsign)
        print("\n字节编码:")
        print(loginsign.encode("utf-8"))
        print("\nMD5签名:")
        sign = hashlib.md5(loginsign.encode("utf-8")).hexdigest()
        print(sign)
        
        login_data = (
            f"password={password_URI}%0A&code={code}&loginType=1&userName={account_URI}%0A"
            f"&deviceUUID={deviceUUID}&versionCode=7&userId={userId}&signVersion=3&sign={sign}"
        )
        
        print("\n=== 最终请求数据 ===")
        print("编码前:")
        print(urllib.parse.unquote(login_data))
        print("\n编码后:")
        print(login_data)
        
        print("\n登录云麦请求:")
        print(f"URL: https://account.iyunmai.com/api/android/user/login.d")
        print("Headers:")
        print(json.dumps(headers, indent=2, ensure_ascii=False))
        print("Params:")
        print(f"  code: {code}")
        print(f"  deviceUUID: {deviceUUID}")
        print(f"  userId: {userId}")
        print(f"  sign: {sign}")
        print("————————————————————")
        
        try:
            session = requests.Session()
            session.verify = False
            requests.packages.urllib3.disable_warnings()
            
            login_resp = session.post(
                "https://account.iyunmai.com/api/android/user/login.d",
                data=login_data,
                headers=headers,
                timeout=10
            )
            
            login_json = login_resp.json()
            print(f"登录响应: {login_json}")
            
            if login_json["result"]["code"] != 0:
                print(f"登录失败: {login_json['result']['msg']}")
                return None
                
            refresh_token = login_json["data"]["userinfo"]["refreshToken"]
            user_id = login_json["data"]["userinfo"]["userId"]
            
            # 获取access token
            token_sign = f"code={code}&refreshToken={refresh_token}&signVersion=3&versionCode=2&secret=AUMtyBDV3vklBr6wtA2putAMwtmVcD5b"
            token_data = (
                f"code={code}&refreshToken={refresh_token}&sign={hashlib.md5(token_sign.encode()).hexdigest()}"
                f"&signVersion=3&versionCode=2"
            )
            
            print("\n=== Token请求详情 ===")
            print("URL:", "https://account.iyunmai.com/api/android/auth/token.d")
            print("Method: POST")
            print("Headers:")
            for key, value in headers.items():
                print(f"  {key}: {value}")
            print("Request Data (decoded):")
            print("  " + urllib.parse.unquote(token_data))
            print("Request Data (encoded):")
            print("  " + token_data)
            
            token_resp = session.post(
                "https://account.iyunmai.com/api/android/auth/token.d",
                data=token_data,
                headers=headers,
                timeout=10
            )
            
            print("\n=== Token响应详情 ===")
            print(f"Status Code: {token_resp.status_code}")
            print("Response Headers:")
            for key, value in token_resp.headers.items():
                print(f"  {key}: {value}")
            print("Response Body:")
            print("  " + token_resp.text)
            
            token_json = token_resp.json()
            if token_json["result"]["code"] != 0:
                print(f"获取token失败: {token_json['result']['msg']}")
                return None
                
            access_token = token_json["data"]["accessToken"]
            
            # 获取体重数据
            startTime = str(int(time.time()) - 9999 * 24 * 60 * 60)  # 获取较长时间范围的数据
            weight_url = f"https://data.iyunmai.com/api/ios/scale/chart-list.json"
            weight_params = {
                "code": code,
                "signVersion": "3",
                "startTime": startTime,
                "userId": user_id,
                "versionCode": "2"
            }
            
            headers["accessToken"] = access_token
            weight_resp = session.get(
                weight_url,
                params=weight_params,
                headers=headers,
                timeout=10
            )
            
            print(f"获取体重数据响应状态码: {weight_resp.status_code}")
            print(f"获取体重数据响应内容: {weight_resp.text}")
            
            weight_json = weight_resp.json()
            if weight_json.get("code") != 0:
                print(f"获取体重数据失败: {weight_json.get('msg')}")
                return None
                
            # 转换数据格式
            weight_list = []
            for item in weight_json["data"]["rows"]:
                weight_list.append({
                    "measureTime": int(item["createTime"]),
                    "weight": float(item["weight"]),
                    "bodyFat": float(item.get("bfr", 0)),
                    "bodyWater": float(item.get("whr", 0)),
                    "muscleMass": float(item.get("rom", 0))
                })
                
            return weight_list
            
        except requests.exceptions.RequestException as e:
            print(f"网络请求错误: {str(e)}")
            return None
        except json.JSONDecodeError as e:
            print(f"JSON解析错误: {str(e)}")
            print(f"响应内容: {login_resp.text if 'login_resp' in locals() else '未获得响应'}")
            return None
        except Exception as e:
            print(f"其他错误: {str(e)}")
            return None

    def sync_to_garmin(self, weight_data, garmin_email, garmin_password):
        """同步数据到佳明"""
        try:
            # 登录佳明
            session = requests.Session()
            login_resp = session.post(
                f"{self.garmin_base_url}auth/login",
                json={
                    "email": garmin_email,
                    "password": garmin_password
                }
            )
            
            if login_resp.status_code != 200:
                print("佳明登录失败")
                return False
                
            # 转换并上传数据
            for record in weight_data:
                weight_payload = {
                    "dateTime": datetime.fromtimestamp(record["measureTime"]).strftime("%Y-%m-%d %H:%M:%S"),
                    "weight": record["weight"],
                    "bodyFat": record.get("bodyFat", 0),
                    "bodyWater": record.get("bodyWater", 0),
                    "muscleMass": record.get("muscleMass", 0)
                }
                
                upload_resp = session.post(
                    f"{self.garmin_base_url}weight",
                    json=weight_payload
                )
                
                if upload_resp.status_code == 200:
                    print(f"成功同步体重记录: {weight_payload['dateTime']}")
                else:
                    print(f"同步失败: {weight_payload['dateTime']}")
                    
                time.sleep(1)  # 避免请求过快
                
            return True
            
        except Exception as e:
            print(f"��步到佳明失败: {str(e)}")
            return False

def main():
    parser = argparse.ArgumentParser(description="云麦好轻体重数据同步到佳明")
    parser.add_argument("--phone", required=True, help="云麦账号手机号")
    parser.add_argument("--password", required=True, help="云麦账号密码")
    parser.add_argument("--garmin-email", required=True, help="佳明账号邮箱")
    parser.add_argument("--garmin-password", required=True, help="佳明账号密码")
    
    args = parser.parse_args()
    
    syncer = WeightSync()
    
    # 获取云麦数据
    print("正在获取云麦数据...")
    weight_data = syncer.get_yunmai_data(args.phone, args.password)
    
    if not weight_data:
        print("获取云麦数据失败")
        return
        
    print(f"获取到 {len(weight_data)} 条体重记录")
    
    # 同步到佳明
    print("正在同步到佳明...")
    if syncer.sync_to_garmin(weight_data, args.garmin_email, args.garmin_password):
        print("同步完成")
    else:
        print("同步失败")

if __name__ == "__main__":
    main() 