import crawler
import payloads
import reports


if __name__ == "__main__":
    print("Welcome to Beovulf !\n\n")
    domain = input("What domain would you like to target ?\n")
    if domain == "test":
        domain = "iit.edu"
        starturl = "http://support.iit.edu/MRcgi/MRhomepage.pl" \
                   "?USER=&PROJECTID=1&MRP=0&OPTION=none&WRITECACHE=1" \
                   "&FIRST_TIME_IN_FP=1&FIRST_TIME_IN_PROJ=1&"
    else:
        starturl = input("What URL will you chose as a starting point ?\n")
        if not starturl[0:4] == "http":
            starturl = "http://" + starturl

    crawler = crawler.Crawler(starturl, domain)
    attvectors = crawler.launchCrawler()

    payloadMgr = payloads.PayloadMgr(attvectors)
    vulns = payloadMgr.launchPayloadMgr()

    reportMgr = reports.ReportMgr(vulns)
    print(reportMgr.launchReportMgr())
