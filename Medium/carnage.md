# Carnage - WireShark Challenge

URL: [Linke](https://tryhackme.com/r/room/c2carnage)

## Scenario:

Eric Fischer from the Purchasing Department at Bartell Ltd has received an email from a known contact with a Word document attachment.  Upon opening the document, he accidentally clicked on "Enable Content."  The SOC Department immediately received an alert from the endpoint agent that Eric's workstation was making suspicious connections outbound. The pcap was retrieved from the network sensor and handed to you for analysis.

**Task**: Investigate the packet capture and uncover the malicious activities.

- Credit goes to [Brad Duncan](https://www.malware-traffic-analysis.net/) for capturing the traffic and sharing the pcap packet capture with InfoSec community.**

NOTE: DO NOT directly interact with any domains and IP addresses in this challenge.

## Write-Up:

Are you ready for the journey?

Please, load the pcap file in your Analysis folder on the Desktop into Wireshark to answer the questions below.

Answer the questions below

- What was the date and time for the first HTTP connection to the malicious IP?

(**answer format**: yyyy-mm-dd hh:mm:ss)

- Answer
    
    We’ll start by filtering `http`. The first packet is a GET command to download a zip file. We’ll then look at the time of that packet and copy it to the answer.
    
    *Make sure to delete the decimal number in the seconds.*
    
  <img width="1284" alt="1" src="https://github.com/yottam205/Try-Hack-Me-Challenges/assets/117525375/d6b438a2-c423-4898-bfd8-9a2ac9927e8b">

    
- What is the name of the zip file that was downloaded?
- Answer
    
    The name of the file is in the packet details or at the info column.
    
- What was the domain hosting the malicious zip file?
- Answer
    
    The answer is located in the packet details window as well
    
- Without downloading the file, what is the name of the file in the zip file?
- Answer
    
    <img width="679" alt="2" src="https://github.com/yottam205/Try-Hack-Me-Challenges/assets/117525375/8ec0265d-a028-410a-a77a-80eda5369a97">

    
- What is the name of the webserver of the malicious IP from which the zip file was downloaded?
- Answer
    
    If we right-click the packet and follow the TCP stream, we’ll be shown another window with more details and the full stream conversation. From here, we can answer the previous questions as well as this one. To find the answer, we’ll scroll down.
    
    <img width="960" alt="3" src="https://github.com/yottam205/Try-Hack-Me-Challenges/assets/117525375/519386cf-e242-4758-846f-fbe4817cc850">

    
     
    
- What is the version of the webserver from the previous question?
- Answer
    
    The answer is under `x-powered-by:` at the same window
    
- Malicious files were downloaded to the victim host from multiple domains. What were the three ****domains involved with this activity?
- Hint
    
    Check HTTPS traffic. Narrow down the timeframe from 16:45:11 to 16:45:30.
    
- Answer
    
    To answer this question, by using the hint, we’ll have to narrow down the timeframe, as well as the handshake type. So we’ll use the filter `tls.handshake.type==1) and (frame.time >= "2021-09-24 16:45:11") && (frame.time <= "2021-09-24 16:45:30")`. I looked at the other packets to see the domain names and picked the names that were suspicious.
    
- Which certificate authority issued the SSL certificate to the first domain from the previous question?
- Answer
    
    By following the stream of the first packet, we can see the certificates and the answer to this question.
    
    <img width="965" alt="4" src="https://github.com/yottam205/Try-Hack-Me-Challenges/assets/117525375/4dcaa042-8101-40a2-a62c-63d1eb6b8d83">

    
- What are the two IP addresses of the Cobalt Strike servers? Use VirusTotal (the Community tab) to confirm if IPs are identified as Cobalt Strike C2 servers. (answer format: enter the IP addresses in sequential order)
- Hint
    
    Check the Conversations menu option
    
- Answer
    
    To view the conversation window, we’ll use the filter `http.request.method == "GET"`. We’ll then go to statistics → conversations. Here we’ll click the TCP tab. There are a lot of IPs recorded. To narrow down our search, we’ll look at the most communicating IPs because C2 servers communicate with GET and POST methods. If we take them to VirusTotal and look at the community tab, that will confirm that it is a Cobalt Strike C2 server.
    
    <img width="1440" alt="5" src="https://github.com/yottam205/Try-Hack-Me-Challenges/assets/117525375/11283239-7508-4eaf-84dc-f81c5d399ba7">

    
    <img width="430" alt="6" src="https://github.com/yottam205/Try-Hack-Me-Challenges/assets/117525375/85fd9a50-3360-4bde-9c2b-f91cb7cea4d8">

    
- What is the Host header for the first Cobalt Strike IP address from the previous question?
- Answer
    
    We can find the Host header by looking at the same place in the community tab.
    
- What is the domain name for the first IP address of the Cobalt Strike server? You may use VirusTotal to confirm if it's the Cobalt Strike server (check the Community tab).
- Hint
    
    Filter out for DNS queries
    
- Answer
    
    To find the answer, I used the filter `ip.addr == 185.106.96.158` which is the IP of the first C2. I then clicked on edit → preferences → name resolution → resolve network (IP) address and OK. It’ll show the domain name instead of the IP address. I then went to VirusTotal to confirm that.
    
    <img width="723" alt="7" src="https://github.com/yottam205/Try-Hack-Me-Challenges/assets/117525375/7b6f9d08-e24f-48d7-9a86-b59f615d2382">

    
    <img width="430" alt="8" src="https://github.com/yottam205/Try-Hack-Me-Challenges/assets/117525375/53ce5618-f2f9-4636-8f43-21d188d7eecc">

    
- What is the domain name of the second Cobalt Strike server IP?  You may use VirusTotal to confirm if it's the Cobalt Strike server (check the Community tab).
- Hint
    
    Look for traffic over port 443/HTTPS
    
- Answer
    
    I used the same method as the previous question.
    
- What is the domain name of the post-infection traffic?
- Hint
    
    Filter Post HTTP traffic.
    
- Answer
    
    Here we’ll have to follow the POST command, just like we did with the GET command. So we’ll use the filter `http.request.method == "POST"` and we’ll follow the TCP stream to find out the answer.
    
    <img width="959" alt="9" src="https://github.com/yottam205/Try-Hack-Me-Challenges/assets/117525375/fb4e45aa-e587-41ce-929e-b0651b1864d0">

    
- What are the first eleven characters that the victim host sends out to the malicious domain involved in the post-infection traffic?
- Answer
    
    If we look at the same window, it is just right above the last answer.
    
    <img width="961" alt="10" src="https://github.com/yottam205/Try-Hack-Me-Challenges/assets/117525375/4d4db76f-f86a-4876-9b7f-0dc5c0b51f59">

    
- What was the length for the first packet sent out to the C2 server?
- Answer
    
    Here we’ll have to go back to the filter we’ve used before and look at packet 3822, which is the first packet we see when we use the filter `http.request.method == "POST"`. We can see the answer under the length column.
    
    <img width="661" alt="11" src="https://github.com/yottam205/Try-Hack-Me-Challenges/assets/117525375/94b8f988-fcbe-4a53-8ca6-7f7267b604dd">

    
- What was the Server header for the malicious domain from the previous question?
- Answer
    
    If we look at the TCP stream from the last packet we looked at, we’ll be able to see the answer.
    
    <img width="965" alt="12" src="https://github.com/yottam205/Try-Hack-Me-Challenges/assets/117525375/39399701-0bae-4f82-89cb-8dcac1b04d2a">

    
- The malware used an API to check for the IP address of the victim’s machine. What was the date and time when the ****DNS ****query for the IP check domain occurred? (**answer format**: yyyy-mm-dd hh:mm:ss UTC)
- Answer
    
    To find the answer, we’ll have to use a filter that looks at DNS queries and the use of the API. So we’ll use this filter, which shows all the DNS queries combined with an API use: `dns && frame contains "api"`. If we look at the info of the packets, we see that the first packet (number 990) is the only packet that connects with a different domain. The third packet (number 24147), which connects with the other domain and has the use of the API, has our answer.
    
    <img width="1381" alt="13" src="https://github.com/yottam205/Try-Hack-Me-Challenges/assets/117525375/2e2f355c-8508-44d5-a1ee-422eccc6e1ac">

    
- What was the domain in the DNS query from the previous question?
- Answer
    
    The answer here is pretty simple. You can just look at the info column using the same packet and filter from the previous question.
    
- Looks like there was some malicious spam (malspam) activity going on. What was the first MAIL FROM address observed in the traffic?
- Answer
    
    If we use the filter `frame contains "MAIL FROM"` (case sensitive) because that’s what the question says the malicious mail contains, we’ll be able to see the answer right away.
    
    <img width="1220" alt="14" src="https://github.com/yottam205/Try-Hack-Me-Challenges/assets/117525375/67634f83-d48e-426e-95c4-31e8361cabab">

    
- How many packets were observed for the SMTP ****traffic?
- Answer
    
    If we just filter for `smtp` here, we’ll see the answer.
    
    <img width="1440" alt="15" src="https://github.com/yottam205/Try-Hack-Me-Challenges/assets/117525375/be5e2e16-159f-4625-983d-4d779f36788a">
