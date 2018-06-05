from bs4 import BeautifulSoup
import requests

class Crawler:
    def __init__(self, start, domain):
        self.start = start
        self.domain = domain
        self.urls = set()
        self.visitedurls = set()

        # Attack Vectors
        self.forms = []
        self.getargs = []


    def parseForLinks(self, url):
        try:
            data = requests.get(url, verify=False, headers={'User-agent': 'yogurt 0.1'})
        except UnicodeError:
            print("Couldn't connect to "+url)
            return 0
        if data.status_code == 200:
            print("Connection successful !")
        else:
            print("Couldn't connect to "+url)
            print("Status code : "+str(data.status_code))
            return 0
        soup = BeautifulSoup(data.content, "lxml")
        for link in soup.find_all('a'):
            if (link.get('href') is not None) & (link.get('href') is not ""):
                if (not link.get('href')[0] == "#"):  # Avoid js stuff
                    formattedurl = self.formatLink(url, link.get('href'))
                    if ("@" not in formattedurl)\
                            &(self.domain in formattedurl)\
                            &(formattedurl not in self.visitedurls)\
                            &(" " not in formattedurl)\
                            &("(" not in formattedurl):
                        argdict = self.grabGETargs(formattedurl)
                        if (bool(argdict))&(argdict not in self.getargs):
                            self.urls.add(argdict["URL"])
                            self.getargs.append(dict(argdict))
                        elif argdict:
                            self.urls.add(argdict["URL"])
                        else:
                            self.urls.add(formattedurl)
        newurls = list(set(self.urls) - set(self.visitedurls))      #Only consider new URLs
        print(str(len(newurls))+" total relevant URLs successfully found")

    def parseForForms(self, url):
        data = requests.get(url, verify=False, headers={'User-agent': 'yogurt 0.1'})
        soup = BeautifulSoup(data.content, "lxml")
        form = {}
        for e in soup.find_all('form'):
            form.clear()
            if "action" in e.attrs:
                if len(e["action"]) > 0:
                    dest = self.formatLink(url, e["action"])
                    form["Destination"] = dest  # Initialize form data object
                    self.parseForInputs(form, str(e))
            if "name" in e.attrs:
                form["Name"] = e["name"]
            if (form not in self.forms) & (form is not {}):
                self.forms.append(dict(form))

    def parseForInputs(self, form, data):
        soup = BeautifulSoup(data, "lxml")
        inputlist = []
        passiveinputs = []
        for e in soup.find_all('input'):
            if "type" not in e.attrs:
                pass
            elif ("name" in e.attrs) & (e["type"] == "text"):
                inputlist.append(str(e["name"]))
            elif ("name" in e.attrs) & (e["type"] is not "text"):
                if "value" in e.attrs:
                    passiveinputs.append((str(e["name"]), str(e["value"])))
                else:
                    passiveinputs.append((str(e["name"]), ""))
        form["Inputs"] = list(inputlist)
        form["PassiveInputs"] = list(passiveinputs)

    def grabGETargs(self, url):
        if "?" in url:
            args = []
            data = url.split("?")
            argpairs = data[1].split("&")
            for each in argpairs:
                if "javascript" not in each:
                    args.append(str(each.split("=")[0]))
            return {"URL": data[0], "Arguments": args}
        return {}

    def formatLink(self, url, input):
        if (input == "./") | (input == "/"):
            return url
        if "http" in input:
            input = input.strip("/")
            if not input[0:4] == "http":
                input = "http://" + input
            return input
        else:
            if input[0] is not "/":
                input = "/"+input
            if "?" not in url:
                return self.getRootURL(url) + input
            else:
                return self.getRootURL(url.split("?")[0]) + input

    def getRootURL(self, url):
        if url[0:4] == "http":
            root = url.split("/")[0:3]
            return "/".join(root)
        else:
            root = url.split("/")[0]
            return "http://" + "".join(root)

    def clearData(self):  # Run before each scan
        pass


    def launchCrawler(self):
        self.visitedurls.add(str(self.start.split("?")[0]))
        self.parseForLinks(self.start)
        self.parseForForms(self.start)
        # Call payloads.py on the forms and other gathered data
        while 1:
            if len(self.forms) > 0:
                print("\nExample form :\n\n" +str(self.forms[0]))
            if len(self.getargs) > 0:
                print("\nExample GET args :\n\n"+str(self.getargs[0]))
            newpass = input("\nCurrently, "+str(len(self.visitedurls))+" unique URLs have been scanned,"
                            " the next pass will scan "+str(len(self.urls))+" URLs, proceed ? y/n\n ")
            if newpass == "y":
                urlbuffer = list(self.urls)
                self.urls.clear()  # clear the URL list to start harvesting new ones for the next pass
                for each in urlbuffer:
                    self.clearData()
                    print("\n --- Scanning " + each + " --- ")
                    self.visitedurls.add(str(each.split("?")[0]))
                    self.parseForLinks(each)
                    self.parseForForms(each)
                    # Call payloads.py and gather more data
            elif newpass == "n":
                break
            else:
                print("\nUnrecognized answer.")
        return [self.getargs, self.forms]


