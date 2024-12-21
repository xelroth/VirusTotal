import requests
import hashlib
import urllib.parse
from core.funtions import FileAnalyzer
from fp.fp import FreeProxy

class VirusTotalAPI:
    def __init__(self):
        self.__Session__ = requests.Session()
        self.__Proxy__ = FreeProxy().get()
        self.__Session__.proxies = {self.__Proxy__}
        self.Funcs = FileAnalyzer()
        self.__UpdateHeaders__()

    def __UpdateHeaders__(self):
        self.__X_VT_Header__ = self.Funcs.__GenerateRandomHeaderId__()
        self.__Basic_Header__ = {
            "X-Tool": "vt-ui-main",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.53 Safari/537.36",
            "Content-Type": "application/json",
            "X-App-Version": "v1x98x0",
            "Accept": "application/json",
            "Referer": "https://www.virustotal.com/",
            "Accept-Language": "en-US,en;q=0.9,es;q=0.8",
            "X-VT-Anti-Abuse-Header": self.__X_VT_Header__,
        }

        self.__Upload_Headers__ = {
            "Authority": "www.virustotal.com",
            "Accept": "*/*",
            "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
            "Cookie": "VT_PREFERRED_LANGUAGE=en",
            "Origin": "https://www.virustotal.com",
            "Referer": "https://www.virustotal.com/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "Sec-GPC": "1",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.53 Safari/537.36",
            "X-App-Version": "v1x98x0",
            "X-Tool": "vt-ui-main",
            "X-VT-Anti-Abuse-Header": self.__X_VT_Header__,
        }

    def __CheckFileExist__(self, file_hash):
        response = self.__Session__.get(
            f"https://www.virustotal.com/ui/files/{file_hash}",
            headers=self.__Upload_Headers__,
            allow_redirects=False
        ) 
        return 1 if response.status_code == 200 else 0

    def __UploadFile__(self, filename, force=False):
        if self.__CheckFileExist__(self.__GetFileHash__(filename)) and not force:
            return self.__GetFileHash__(filename)

        upload_url = self.__GetUploadURL__()

        response = requests.post(
            upload_url,
            cookies={"VT_PREFERRED_LANGUAGE": "en"},
            headers=self.__Upload_Headers__,
            files={"file": open(filename, "rb")},
        )

        return self.__GetFileHash__(filename) if response.status_code == 200 else 0

    def __GetUploadURL__(self):
        response = self.__Session__.get(
            "https://www.virustotal.com/ui/files/upload_url", headers=self.__Basic_Header__
        )
        if response.ok:
            return response.text[15:-3]
        else:
            raise Exception(f"Invalid response: {response.status_code}")

    def __UploadURL__(self, url):            
        url_id = self.__Session__.post("https://www.virustotal.com/ui/urls", data=f"url={urllib.parse.quote_plus(url)}", headers=self.__Upload_Headers__)
        if url_id.ok:
            url_id = url_id.json()['data']['id']
            response = self.__Session__.get(f"https://www.virustotal.com/ui/analyses/{url_id}", headers=self.__Upload_Headers__)
            if response.ok:
                return url_id[2:66]
            else:
                raise Exception(f"Error in validating the URL {url}")
        else:
            raise Exception("Error in uploading URL")
        
    def __CheckURLExists__(self, url):
        return 0 if self.__Session__.get(f"https://www.virustotal.com/ui/search?query={urllib.parse.quote_plus(url)}", headers=self.__Upload_Headers__).json()['data'] == [] else 1
    
    @staticmethod
    def __GetFileHash__(filename):
        with open(filename, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    def __FileInfo__(self, file_hash):
        if not self.__CheckFileExist__(file_hash):
            return None
        return self.Funcs.__FillFileInfo__(self.__Session__.get(f"https://www.virustotal.com/ui/files/{file_hash}", headers=self.__Upload_Headers__).json())

    def __URLInfo__(self, url_hash):
        if not self.__CheckFileExist__(url_hash):
            return None
        return self.__Session__.get(f"https://www.virustotal.com/ui/urls/{url_hash}", headers=self.__Upload_Headers__).json()
