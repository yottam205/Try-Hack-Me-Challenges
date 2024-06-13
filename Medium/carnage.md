#Carnage - WireShark Challenge

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
    
    ![Screenshot 2024-06-06 at 10.54.50.png](/Users/yottam205/Documents/GitHub/Try-Hack-Me-Challenges/assets/carnage/1.png)
    
- What is the name of the zip file that was downloaded?
- Answer
    
    The name of the file is in the packet details or at the info column.
    
- What was the domain hosting the malicious zip file?
- Answer
    
    The answer is located in the packet details window as well
    
- Without downloading the file, what is the name of the file in the zip file?
- Answer
    
    ![Screenshot 2024-06-06 at 10.58.10.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/98e0a4b1-ac4f-485c-b14c-f2c379e38a49/5b7df4b7-0c44-4a19-a69c-803b2ccea0de/Screenshot_2024-06-06_at_10.58.10.png)
    
- What is the name of the webserver of the malicious IP from which the zip file was downloaded?
- Answer
    
    If we right-click the packet and follow the TCP stream, we’ll be shown another window with more details and the full stream conversation. From here, we can answer the previous questions as well as this one. To find the answer, we’ll scroll down.
    
    ![Screenshot 2024-06-06 at 11.07.47.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/98e0a4b1-ac4f-485c-b14c-f2c379e38a49/0b745e6f-0ab0-4027-b8f0-53dd798f4640/Screenshot_2024-06-06_at_11.07.47.png)
    
     
    
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
    
    ![Screenshot 2024-06-06 at 11.32.28.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/98e0a4b1-ac4f-485c-b14c-f2c379e38a49/312f4767-2ee7-4493-b80e-d8b52980a028/Screenshot_2024-06-06_at_11.32.28.png)
    
- What are the two IP addresses of the Cobalt Strike servers? Use VirusTotal (the Community tab) to confirm if IPs are identified as Cobalt Strike C2 servers. (answer format: enter the IP addresses in sequential order)
- Hint
    
    Check the Conversations menu option
    
- Answer
    
    To view the conversation window, we’ll use the filter `http.request.method == "GET"`. We’ll then go to statistics → conversations. Here we’ll click the TCP tab. There are a lot of IPs recorded. To narrow down our search, we’ll look at the most communicating IPs because C2 servers communicate with GET and POST methods. If we take them to VirusTotal and look at the community tab, that will confirm that it is a Cobalt Strike C2 server.
    
    ![Screenshot 2024-06-06 at 11.49.27.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/98e0a4b1-ac4f-485c-b14c-f2c379e38a49/006fe36c-45e3-454b-98c4-fc565616c983/Screenshot_2024-06-06_at_11.49.27.png)
    
    ![Screenshot 2024-06-06 at 11.49.20.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/98e0a4b1-ac4f-485c-b14c-f2c379e38a49/afc338e8-4efc-4c88-8a6e-109dd6f509c0/Screenshot_2024-06-06_at_11.49.20.png)
    
- What is the Host header for the first Cobalt Strike IP address from the previous question?
- Answer
    
    We can find the Host header by looking at the same place in the community tab.
    
- What is the domain name for the first IP address of the Cobalt Strike server? You may use VirusTotal to confirm if it's the Cobalt Strike server (check the Community tab).
- Hint
    
    Filter out for DNS queries
    
- Answer
    
    To find the answer, I used the filter `ip.addr == 185.106.96.158` which is the IP of the first C2. I then clicked on edit → preferences → name resolution → resolve network (IP) address and OK. It’ll show the domain name instead of the IP address. I then went to VirusTotal to confirm that.
    
    ![Screenshot 2024-06-06 at 12.06.21.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/98e0a4b1-ac4f-485c-b14c-f2c379e38a49/1190f01b-b5cc-485e-b20c-925423b8fdb9/Screenshot_2024-06-06_at_12.06.21.png)
    
    ![Screenshot 2024-06-06 at 11.49.20.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/98e0a4b1-ac4f-485c-b14c-f2c379e38a49/d345d666-a9b1-4dee-a99e-8eef4c7606b6/Screenshot_2024-06-06_at_11.49.20.png)
    
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
    
    ![Screenshot 2024-06-06 at 15.50.38.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/98e0a4b1-ac4f-485c-b14c-f2c379e38a49/f8b20857-12ba-4224-8302-84453cfda46e/Screenshot_2024-06-06_at_15.50.38.png)
    
- What are the first eleven characters that the victim host sends out to the malicious domain involved in the post-infection traffic?
- Answer
    
    If we look at the same window, it is just right above the last answer.
    
    ![Screenshot 2024-06-06 at 15.52.11.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/98e0a4b1-ac4f-485c-b14c-f2c379e38a49/91856126-ad67-4b50-a112-65bed63c2abd/Screenshot_2024-06-06_at_15.52.11.png)
    
- What was the length for the first packet sent out to the C2 server?
- Answer
    
    Here we’ll have to go back to the filter we’ve used before and look at packet 3822, which is the first packet we see when we use the filter `http.request.method == "POST"`. We can see the answer under the length column.
    
    ![Screenshot 2024-06-06 at 15.54.39.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/98e0a4b1-ac4f-485c-b14c-f2c379e38a49/ff60faa1-3779-4511-b7ba-f9a9d200bed4/Screenshot_2024-06-06_at_15.54.39.png)
    
- What was the Server header for the malicious domain from the previous question?
- Answer
    
    If we look at the TCP stream from the last packet we looked at, we’ll be able to see the answer.
    
    ![Screenshot 2024-06-06 at 15.59.10.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/98e0a4b1-ac4f-485c-b14c-f2c379e38a49/d485a53f-e64d-41a7-9a34-6c2999d9d88c/Screenshot_2024-06-06_at_15.59.10.png)
    
- The malware used an API to check for the IP address of the victim’s machine. What was the date and time when the ****DNS ****query for the IP check domain occurred? (**answer format**: yyyy-mm-dd hh:mm:ss UTC)
- Answer
    
    To find the answer, we’ll have to use a filter that looks at DNS queries and the use of the API. So we’ll use this filter, which shows all the DNS queries combined with an API use: `dns && frame contains "api"`. If we look at the info of the packets, we see that the first packet (number 990) is the only packet that connects with a different domain. The third packet (number 24147), which connects with the other domain and has the use of the API, has our answer.
    
    ![Screenshot 2024-06-06 at 16.08.17.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/98e0a4b1-ac4f-485c-b14c-f2c379e38a49/c30cddef-3a2b-47b7-b4e4-5b38afb8dac8/Screenshot_2024-06-06_at_16.08.17.png)
    
- What was the domain in the DNS query from the previous question?
- Answer
    
    The answer here is pretty simple. You can just look at the info column using the same packet and filter from the previous question.
    
- Looks like there was some malicious spam (malspam) activity going on. What was the first MAIL FROM address observed in the traffic?
- Answer
    
    If we use the filter `frame contains "MAIL FROM"` (case sensitive) because that’s what the question says the malicious mail contains, we’ll be able to see the answer right away.
    
    ![Screenshot 2024-06-06 at 16.13.02.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/98e0a4b1-ac4f-485c-b14c-f2c379e38a49/b1b4bdcd-1af9-4aae-85ca-7991a0eca42a/Screenshot_2024-06-06_at_16.13.02.png)
    
- How many packets were observed for the SMTP ****traffic?
- Answer
    
    If we just filter for `smtp` here, we’ll see the answer.
    
    ![Screenshot 2024-06-06 at 16.14.23.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/98e0a4b1-ac4f-485c-b14c-f2c379e38a49/c8a75046-f3c2-4884-a9a4-b2650ab5240a/Screenshot_2024-06-06_at_16.14.23.png)