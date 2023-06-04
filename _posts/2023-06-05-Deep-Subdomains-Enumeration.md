---
title: Deep-Subdomains-Enumeration
author: h0tak88r
date: 2023-06-05
categories: [Recon]
tags: [Recon,Subdomain_Enumeration]
pin: true
---

## What's the need?

- A good subdomain enumeration will help you find those hidden/untouched subdomains, resulting lesser people finding bugs on that particular domain. Hence lesser **duplicates**.
- Finding applications running on hidden, forgotten(by the organization) sub-domains may lead to uncovering critical vulnerabilities.
- For large organizations, to find what services have they exposed to the internet while performing an internal pentest.
- The methodology of collecting subdomains from tools like `amass`, `subfinder`, `findomain` and directly sending them to httpx/httprobe is **absolutely wrong**. Instead, you should first DNS resolve them using tools like [puredns](https://github.com/d3mondev/puredns) or [shuffledns](https://github.com/projectdiscovery/shuffledns).

<aside>
💡 There are many tools that you may think it is better than the mentioned ones  in some techniques, In this methodology I focus on the Techniques Themselves, You can go ahead and try your preferred Tools

</aside>

**From the This image you can get the idea of  horizontal/Vrtical domain correlation:**

![Untitled](https://h0tak88r.github.io\assets\Deep-Subdomains-Enumeration-Methodology 4b5c3da2008f4bd8b482a401314a0dcd/Untitled.png)

# **Horizontal Enumeration**

### Discovering the IP space

1. First We need to get the **ASN** from websites like [https://bgp.he.net/](https://bgp.he.net/) or you can use any other tool that gets the job done

> **ASN**(Autonomous System Number) is a unique identifier for a set of IP-ranges an organizations owns. Very large organizations such as Apple, GitHub, Tesla have their own significant IP space.
>

2. find out the IP ranges that reside inside that ASN. For this, we will use a tool called **whois.**

   
```bash
 apt-get install whois
 whois -h whois.radb.net  -- '-i origin AS8983' | grep -Eo "([0-9.]+){4}/[0-9]+" | uniq -u > ip_ranges.txt
```
    

### PTR records (Reverse DNS)

Since we already know the IP space of an organization we can, we can **reverse query** the IP addresses and find the valid domains

**DNS PTR records (pointer record)** helps us to achieve this. We can query a **PTR record** of an IP address and find the associated **hostname/domain name**.

1. Chain the tools **[Mapcidr](https://github.com/projectdiscovery/mapcidr) - [Dnsx](https://github.com/projectdiscovery/dnsx)** together in one liner 
    
    ```bash
    cat ip_anges.txt | mapcidr -silent | dnsx -ptr -resp-only -o ptr_recrds.txt
    ```
    

> When an IP range is given to `mapcidr` through stdin(standard input), it performs **expansion of the CIDR range**, spitting out each **IP address** from the range onto a new line. Now when **`dnsx`** receives each IP address from stdin, it performs **reverse DNS** and checks for **PTR record**. If, found it gives us back the **hostname/domain name**.
> 

### **Favicon Search**

> **What is a favicon?**  The image/icon shown on the left-hand side of a tab is called as **favicon.ico**
 
![Untitled](https://h0tak88r.github.io\assets\Deep-Subdomains-Enumeration-Methodology 4b5c3da2008f4bd8b482a401314a0dcd/Untitled%201.png)

1. View source of the websitepage
2. Search for favicon.ico
3. download it from the link you got from source code 
4. Calculate the hash using python3
    
    ```python
    import hashlib
    
    def calculate_favicon_hash(file_path):
        with open(file_path, 'rb') as file:
            favicon_data = file.read()
            favicon_hash = hashlib.md5(favicon_data).hexdigest()
        return favicon_hash
    
    favicon_path = '/path/to/favicon.ico'
    favicon_hash = calculate_favicon_hash(favicon_path)
    print(favicon_hash)
    ```
    
5. Shodan Search `http.favicon.hash:[Favicon hash here]`

> **Hint**: Generally the favicon hash of any spring boot application is `116323821`**.** So we can use this shodan filter ****`http.favicon.hash:116323821`, You can use different favicon hashes for different services.
> 

### Automation ?

Use https://github.com/devanshbatham/FavFreak 

```bash
cat urls.txt | python3 favfreak.py -o output
http.favicon.hash:-<hash>
```

# **Vertical Enumeration**

## Passive Enum

> Here you got alot of tools that do the job but it is not about the tools you use it is about the technoque or the way you do it .You Must use the tool with all of api’s you can get
> 

Personally I prefer `subfinder` 

**Subfinder** [ `subfinder -d test.com -o passive2.txt -all` ]

Here is a list of free-api websites

1. censys
2. bevigil
3. binaryedge
4. cerspotter
5. whoisxmlapi

1. fofa
2. shodan
3. github
4. virustotal
5. zoomeye
- There are in total around **[90 passive DNS sources/services](https://gist.github.com/sidxparab/22c54fd0b64492b6ae3224db8c706228)** that provide such datasets to query them
- You can use another tool that use free services and apis to do subdomain enumeration [https://github.com/sl4x0/subfree](https://github.com/sl4x0/subfree)
- [https://dnsdumpster.com/](https://dnsdumpster.com/)   → FREE domain research tool that can discover hosts related to a domain. Finding visible hosts from the attackers perspective is an important part of the security assessment process.
- [https://chaos.projectdiscovery.io/#/](https://chaos.projectdiscovery.io/#/) → → it is like database or somthng here u can get all subdomains for public bug bounty programs , Yeah it is useless when you work in a private ones

### Another Ways (I don’t use )

- **Internet Archive →** [district →](https://github.com/lc/gau) [waybackurls](https://github.com/tomnomnom/waybackurls)
- **Github Scraping →** [github-subdomains](https://github.com/gwen001/github-subdomains)
- **GitLab Scraping →** [gitlab-subdomains](https://github.com/gwen001/gitlab-subdomains)

### **Recursive Enumeration**

- In easy words, we again run tools like Amass, Subfinder, Assetfinder again each of the subdomains that were found.
- If you have set up API keys, this technique may consume your entire querying quota
- This technique is only useful when your target has a large number of multi-level subdomains*(not effective for small & medium scope targets).*
- It is a huge use of resources and power and takes time to return the final results so be careful and make this technique the last step of you process if you can :)))
- Do it exclusively on a validated list of subdomains that you have collected through other **Passive + Active** techniques.

**Workflow:**

1. Read the list of subdomains from the file "subdomains.txt".
2. Process the subdomains in two steps: **a)**  Find the Top-10 most frequent occuring **Second-Level Domain** names with the help of tools like `cut`, `sort`, `rev`, `uniq`  **b)**  Find the Top-10 most frequent occuring **Third-Level domains**.
3. Now run passive subdomain enumeration on these 10 Second-level domain names and 10 Third-level domain names using tools like **amass, subfinder, assetfinder, findomain.**
4. Keep appending the results to `passive_recursive.txt` file. 
5. Now after finding out the a list of domain names, run puredns to DNS resolve them and find the alive subdomains

### Automation

```bash
#!/bin/bash

go install -v github.com/tomnomnom/anew@latest
subdomain_list="subdomains.txt"

for sub in $( ( cat $subdomain_list | rev | cut -d '.' -f 3,2,1 | rev | sort | uniq -c | sort -nr | grep -v '1 ' | head -n 10 && cat subdomains.txt | rev | cut -d '.' -f 4,3,2,1 | rev | sort | uniq -c | sort -nr | grep -v '1 ' | head -n 10 ) | sed -e 's/^[[:space:]]*//' | cut -d ' ' -f 2);do 
    subfinder -d $sub -silent -max-time 2 | anew -q passive_recursive.txt
    assetfinder --subs-only $sub | anew -q passive_recursive.txt
    amass enum -timeout 2 -passive -d $sub | anew -q passive_recursive.txt
    findomain --quiet -t $sub | anew -q passive_recursive.txt
done
```

## Active Enum

- [ ]  **DNS Brute Forcing**
    
    ```bash
    #Prerequisites
    git clone https://github.com/blechschmidt/massdns.git
    cd massdns
    make
    sudo make install
    
    #Installing the tool
    go install github.com/d3mondev/puredns/v2@latest
    
    # Download Resolvers List
    wget https://github.com/trickest/resolvers/blob/main/resolvers-trusted.txt
    wget https://public-dns.info/nameservers.txt
    # Download dns wordlist  
    wget https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt
    
    # Brute Forcing
    puredns bruteforce dns_bf_wordlist.txt example.com -r resolvers.txt -w dns_bf.txt
    or
    amass enum -brute wordlist.txt -d target.com -o dns_bf.txt
    or
    shuffledns -d target.com -list wordlist.txt -r resolvers.txt -o dns_bf.txt
    ```
    
- [ ]  **Permutations**

1. generate various combinations or permutations of a root domain
2. DNS resolve them and check if we get any valid subdomains    
    ```bash
    # Permutation words Wordlist
    wget https://gist.githubusercontent.com/six2dez/ffc2b14d283e8f8eff6ac83e20a3c4b4/raw
    # Run 
    gotator -sub subdomains.txt -perm dns_permutations_list.txt -depth 1 -numbers 10 -mindup -adv -md | sort -u > perms.txt
    # DNS resolve them and check for valid ones.
    puredns resolve permutations.txt -r resolvers.txt > resolved_perms
    ```
    
- [ ]  **Google analytics**
    
- Most organizations use Google Analytics to track website visitors and for more statistics. Generally, they have the same Google Analytics ID across all subdomains of a root domain. This means we can perform a reverse search and find all the subdomains having the same ID. Hence, it helps us in the enumeration process.
    ```bash
    > git clone https://github.com/Josue87/AnalyticsRelationships.git
    > cd AnalyticsRelationships/Python
    > sudo pip3 install -r requirements.txt
    python3 analyticsrelationships.py -u https://www.example.com
    ```
    
- [ ]  **TLS, CSP, CNAME Probing**
- In order to use HTTPS, the website owner needs to issue an SSL(Secure Socket Layer) certificate.
- CSP headers sometimes contain **domains/subdomains** from where the content is usually imported
    
    ```bash
    go install github.com/glebarez/cero@latest
    #tls
    cero in.search.yahoo.com | sed 's/^*.//' | grep -e "\." | sort -u
    #cls
    cat subdomains.txt | httpx -csp-probe -status-code -retries 2 -no-color | anew csp_probed.txt | cut -d ' ' -f1 | unfurl -u domains | anew -q csp_subdomains.txt
    # cname
    dnsx -retry 3 -cname -l subdomains.txt
    ```
    

# Finish Work

```bash
cd subs/
cat horizontal/ptr_records.txt | sort -u > horizontal.txt
cat Vertical/Active/* | sort -u > active.txt
cat Vertical/Pssive/* | sort -u > passive.txt
cat * | sort -u > all_subs.txt
cat all_subs.txt | httpx -random-agent -retries 2 -no-color -o filtered_subs.txt
```