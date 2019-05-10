import requests as req
import dns.resolver
import socket
from urllib.parse import urlparse

class Scan:
    def __init__(self, ip, maskOCT):
        print("About scanned network: \n")
        ipv4 = ip.split(".")
        octet_list_bin = [format(int(i), '08b') for i in ipv4]

        binary = ("").join(octet_list_bin)
        octet_list_bin = list(binary)
        print("Address: " + str(self.obs(binary)))

        maskLIST=[]
        negativeLIST=[]

        for i in range(32):
          if i < maskOCT:
            maskLIST.append(str(1))
            negativeLIST.append(str(0))
          else:
            maskLIST.append(str(0))
            negativeLIST.append(str(1))
        maskBIN = ("").join(maskLIST)
        negativeBIN = ("").join(negativeLIST)

        print("Mask: " + str(self.obs(maskBIN)))

        gatewayBIN = []

        for i in range (len(octet_list_bin)):
            if (maskLIST[i] == "1"):
                gatewayBIN.append(octet_list_bin[i])
            else:
                gatewayBIN.append(maskLIST[i])

        gatewayBIN = ("").join(gatewayBIN[0:32])
        gatewayDEC = self.obs( gatewayBIN )

        broadcastBIN =  (bin(int(gatewayBIN, 2) + int(negativeBIN, 2))) [2:]
        gatewayBIN =  (bin(int(gatewayBIN, 2) + int("1", 2))) [2:]
        print("Gateway: " + str(self.obs(gatewayBIN)))
        print("Broadcast: " + str(self.obs(broadcastBIN)))

        broadcastBIN =  (bin(int(gatewayBIN, 2) + int("100000000000", 2))) [2:]



        print("\n")

        self.start(gatewayBIN, broadcastBIN)
        print("That's all, n-joy ;)")
        #print(self.server(url))

        #self.url = url


    def start(self, gatewayBIN, broadcastBIN):
        addressBIN = gatewayBIN
        while ( bin(int(addressBIN,2 )) < bin(int(broadcastBIN, 2))):
            addressBIN = (bin(int(addressBIN, 2) + int("1", 2)))[2:]
            try:
                addresDEC = self.obs(addressBIN)
                code = (req.head(("http://"+addresDEC), timeout=0.1).status_code)
                if (code<400):
                    print("")
                    try:
                        print("Code: ", code)
                        print("Name: " + self.name(addresDEC))
                        print("Title: " + self.title("http://"+addresDEC))
                        print("Email: " + str(self.mail("http://" + addresDEC)))
                        print("DNS Address: " + self.address("http://" + addresDEC))

                        print("Server: " + self.server("http://"+addresDEC))

                    except:
                        try:
                            print("Address: " + addresDEC)
                            print("Email: " + str(self.mail2("http://" + addresDEC)))

                        except:
                              try:
                                  continue

                              except:
                                  continue

                    #print(self.server("http://"+addresDEC))
            except req.exceptions.RequestException:
                #print("Nie ma takiego serwera")
                continue
            #print(str(self.obs(addressBIN)))


    def obs(self, long): #OctoBinarySeperator xD
        short = [ int(("").join(long[0:8]),2), int(("").join(long[8:16]),2), int(("").join(long[16:24]),2), int(("").join(long[24:32]),2) ]
        short = (str(short[0])+"."+str(short[1])+"."+str(short[2])+"."+str(short[3]))
        return(short)

    def name(self, url):
        return(socket.gethostbyaddr(url)[0])

    def title(self, url):
        resp = req.head(url)
        n = req.get(url, resp.headers)
        name1 = n.text
        namez = name1[name1.find('<title>') + 7: name1.find('</title>')]
        if (len(namez) > 100):
            return ("None")
        else:
            return(namez)

    def address(self, url):
        resp = req.head(url)
        address = str(resp.headers['Location'])
        return(address)

    def server(self, url):
        resp = req.head(url)
        server = str(resp.headers['server'])
        return(server)

    def mail(self, url):
        resp = req.head(url)
        address = str(resp.headers['Location'])
        location = urlparse(address).netloc
        mailadr = (dns.resolver.query(location, 'SOA')[0]).rname

        return(mailadr)

    def mail2(self, url):
        resp = req.head(url)
        address = str(resp.headers['server'])
        location = urlparse(address).netloc
        mailadr = (dns.resolver.query(location, 'SOA')[0]).rname

        return(mailadr)


Scan("156.17.88.0", 24)