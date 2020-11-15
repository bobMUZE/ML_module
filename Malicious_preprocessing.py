import re
import math
import threading
import pandas as pd

from tld import get_tld
from urllib.parse import urlparse
from tld.exceptions import TldDomainNotFound

class Preprocessing(threading.Thread):
    def __init__(self, url):
        threading.Thread.__init__(self)
        self.url = url

    def run(self):
        self.RunData()

    def UrlLength(self):
        return len(str(self.url))

    def Entropy(self):
        string = self.url.strip()
        prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
        entropy = - sum([(p * math.log(p) / math.log(2.0)) for p in prob])
        return entropy

    def PathEntropy(self):
        string = urlparse(self.url).path.strip()
        prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
        entropy = - sum([(p * math.log(p) / math.log(2.0)) for p in prob])
        return entropy

    def DomainEntropy(self):
        try:
            string = get_tld(self.url, as_object=True).domain.strip()
            prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
            entropy = - sum([(p * math.log(p) / math.log(2.0)) for p in prob])
            return entropy
        except TldDomainNotFound:
            match = re.search(
                '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
                '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
                '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  # IPv4 in hexadecimal
                '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', self.url)  # Ipv6
            if match:
                # print match.group()
                return -1
            else:
                # print 'No matching pattern found'
                return 1

    def SubDomainEntropy(self):
        try:
            string = get_tld(self.url, as_object=True).subdomain.strip()
            prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
            entropy = - sum([(p * math.log(p) / math.log(2.0)) for p in prob])
            return entropy
        except TldDomainNotFound:
            match = re.search(
                '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
                '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
                '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  # IPv4 in hexadecimal
                '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', self.url)  # Ipv6
            if match:
                # print match.group()
                return -1
            else:
                # print 'No matching pattern found'
                return 1

    def TldEntropy(self):
        try:
            string = get_tld(self.url, as_object=True).tld.strip()
            prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
            entropy = - sum([(p * math.log(p) / math.log(2.0)) for p in prob])
            return entropy
        except TldDomainNotFound:
            return -1

    def FldEntropy(self):
        try:
            string = get_tld(self.url, as_object=True).fld.split()
            prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
            entropy = - sum([(p * math.log(p) / math.log(2.0)) for p in prob])
            return entropy
        except TldDomainNotFound:
            match = re.search(
                '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
                '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
                '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  # IPv4 in hexadecimal
                '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', self.url)  # Ipv6
            if match:
                # print match.group()
                return -1
            else:
                # print 'No matching pattern found'
                return 1

    def HostnameLength(self):
        return len(urlparse(self.url).netloc)

    def PathLength(self):
        return len(urlparse(self.url).path)

    def FdLength(self):
        urlpath = urlparse(self.url).path
        try:
            return len(urlpath.split("/")[1])
        except:
            return 0

    def TldLength(self):
        try:
            return len(get_tld(self.url, fail_silently=True))
        except:
            return -1

    def HavingSymbol(self):
        search_symbol = re.search("@", self.url)
        return -1 if search_symbol else 1

    def PrefixSuffix(self):
        search_suffix = re.search("-", self.url)
        return -1 if search_suffix else 1

    def SpecialCharcter(self):
        count = self.url.count("?") + self.url.count("#") + self.url.count(".") + self.url.count("=")
        return count

    def count_http(self):
        return self.url.count("http")

    def count_htts(self):
        return self.url.count("https")

    def count_www(self):
        return self.url.count("www")

    def numDigits(self):
        digits = [i for i in self.url if i.isdigit()]
        return len(digits)

    def letter_count(self):
        letters = 0
        for i in self.url:
            if i.isalpha():
                letters = letters + 1
        return letters

    def no_of_dir(self):
        urldir = urlparse(self.url).path
        return urldir.count('/')

    def having_ip_address(self):
        match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
            '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
            '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
            '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', self.url)  # Ipv6
        if match:
            # print match.group()
            return -1
        else:
            # print 'No matching pattern found'
            return 1

    def RunData(self):
        data = {
            "url": [self.url], "url_length": [self.UrlLength()], "entropy": [self.Entropy()],
            "pathentropy": [self.PathEntropy()], "domainentropy": [self.DomainEntropy()],
            "tldentropy": [self.TldEntropy()],
            "subdomainentropy": [self.SubDomainEntropy()], "FldEntropy": [self.FldEntropy()],
            "hostname_length": [self.HostnameLength()], "path_length": [self.PathLength()],
            "fd_length": [self.FdLength], "tld_length": [self.TldLength()], "count-": [self.PrefixSuffix()],
            "count-@": [self.HavingSymbol()], "special_chacter": [self.SpecialCharcter()],
            "count-http": [self.count_http()], "count-https": [self.count_htts()], "count-www": [self.count_www()],
            "count-digit": [self.numDigits()], "count-letter": [self.letter_count()], "count_dir": [self.no_of_dir()],
            "use_of_ip": [self.having_ip_address()]}
        data = pd.DataFrame(data)
        print(data)
        return data


if __name__ == "__main__":
    data = pd.read_csv("/home/lmsky/PycharmProjects/Malicious_URL/PhishingURL/data/url_data2.csv")
    data_stack = []

    ts = [Preprocessing(i).RunData() for i in data["url"]]
    try:
        for t in ts:
            t.start()
        for t in ts:
            data_stack.append(t)
            t.join()
    except:
        for t in ts:
            t.stop_event.set()
        for t in ts:
            data_stack.append(t)
            t.join()
    data_make = pd.concat(data_stack)

    data_frame = pd.DataFrame(data_make)
    data_frame["label"] = data["label"]
    labeling = {"good": 0, "bad": 1}
    data_frame["label"] = data_frame["label"].map(labeling)
    data_frame.to_csv("REAL_DATA_TEST.csv", index=False)