import os
import time


class ReportMgr:
    def __init__(self, vulns):
        self.vulns = vulns
        self.xssforms = []
        self.xssargs = []
        self.sqliforms = []
        self.sqliargs = []
        self.crlf = []
        self.rce = []
        self.filename = ""

    def createFolder(self, vulntype):
        currtime = time.strftime("%Y%m%d-%H%M%S")
        self.filename = "report_"+str(vulntype)+"_"+str(currtime)

        os.makedirs("../reports/"+self.filename)
        print("\n"+self.filename+" successfully generated.")

    def generateXSSreport(self):
        self.createFolder("XSS")
        name = "unknown"
        xssstr = ""
        f = open("../reports/"+self.filename+"/report", "w+")
        s = open("../assets/xss_report_stub", "r")

        for each in self.xssforms:
            url = each["Destination"]
            if "Name" in each:
                name = each["Name"]
            inputs = each["Inputs"]
            xssstr += "\nXSS found on form "+str(name)+" targetting URL "+url+". The vulnerable inputs are "+str(inputs)

        for each in self.xssargs:
            url = each["URL"]
            args = each["Arguments"]
            xssstr += "\nXSS found targetting URL " + url + " with vulnerable arguments " + str(args)
        xssstr = s.read() + xssstr
        f.write(xssstr)
        f.close()
        s.close()

    def generateSQLireport(self):
        self.createFolder("SQLi")
        name = "unknown"
        sqlistr = ""
        f = open("../reports/"+self.filename+"/report", "w+")
        s = open("../assets/sqli_report_stub", "r")

        for each in self.sqliforms:
            url = each["Destination"]
            if "Name" in each:
                name = each["Name"]
            inputs = each["Inputs"]
            sqlistr += "\nSQLi found on form "+str(name)+" targetting URL "+url+". The vulnerable inputs are "+str(inputs)

        for each in self.sqliargs:
            url = each["URL"]
            args = each["Arguments"]
            sqlistr += "\nSQLi found targetting URL " + url + " with vulnerable arguments " + str(args)
        sqlistr = s.read() + sqlistr
        f.write(sqlistr)
        f.close()
        s.close()

    def generateRCEreport(self):
        self.createFolder("RCE")
        name = "unknown"
        rcestr = ""
        f = open("../reports/"+self.filename+"/report", "w+")
        s = open("../assets/rce_report_stub", "r")

        for each in self.rce:
            url = each["URL"]
            args = each["Arguments"]
            rcestr += "\nRCE found targetting URL " + url + " with vulnerable arguments " + str(args)
        rcestr = s.read() + rcestr
        f.write(rcestr)
        f.close()
        s.close()

    def generateCRLFreport(self):
        self.createFolder("CRLF")
        name = "unknown"
        crlfstr = ""
        f = open("../reports/"+self.filename+"/report", "w+")
        s = open("../assets/crlf_report_stub", "r")

        for each in self.crlf:
            url = each["URL"]
            args = each["Arguments"]
            crlfstr += "\nCRLF found targetting URL " + url + " with vulnerable arguments " + str(args)
        crlfstr = s.read() + crlfstr
        f.write(crlfstr)
        f.close()
        s.close()


    def launchReportMgr(self):
        self.xssforms = self.vulns["XSS forms"]
        self.xssargs = self.vulns["XSS args"]
        self.sqliforms = self.vulns["SQLi forms"]
        self.sqliargs = self.vulns["SQLi args"]
        self.crlf = self.vulns["CRLF"]
        self.rce = self.vulns["RCE"]

        repgen = False

        if len(self.xssforms)+len(self.xssargs) > 0:
            self.generateXSSreport()
            repgen = True
        if len(self.sqliforms) + len(self.sqliargs) > 0:
            self.generateSQLireport()
            repgen = True
        if len(self.crlf) > 0:
            self.generateCRLFreport()
            repgen = True
        if len(self.rce) > 0:
            self.generateRCEreport()
            repgen = True
        if repgen:
            return "\nAll reports were successfully generated in the \"reports\" folder."
        return "\nNo vulnerabilities to report"
