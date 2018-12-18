from requests import post

def send_msg(msg, hook_url):
    header = 'Content-type: application/json'
    post(url = hook_url, data = msg)

    return
