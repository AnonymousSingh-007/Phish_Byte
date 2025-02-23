import sys
import email.utils
import re
from urllib.parse import urlparse
from html.parser import HTMLParser
import dns.resolver
import socket
import ipaddress

def Domain(mail):
    '''Function to extract basic domains from the email, like sender, receiver, reply to, etc. headers'''
    def extract(header):
        if header:
            name, addr = email.utils.parseaddr(header)
            if "@" in addr:
                return addr.split("@")[1]  # Split the domain from the email address
        return None
    
    mail = email.message_from_string(mail)
    
    H_From = mail.get("From")
    H_ReplyTo = mail.get("Reply-To")
    H_ReturnPath = mail.get("Return-Path")
    
    # Extract the domains
    From = extract(H_From)
    ReplyTo = extract(H_ReplyTo)
    ReturnPath = extract(H_ReturnPath)
    
    domains = [d for d in [From, ReplyTo, ReturnPath] if d is not None]
    is_same = len(set(domains)) == 1  # Check if all domains are the same
    if is_same:
        detail = "All domains are the same"
    else:
        detail = "Different domains found"
    
    return {
        "From Domain": From,
        "ReplyTo Domain": ReplyTo,
        "ReturnPath Domain": ReturnPath,
        "Detail": detail
    }

def Url(mail):
    '''Function to find count of secure URLs, unsecure URLs and misleading anchor tags'''
    body = ""
    if mail.is_multipart():
        for part in mail.walk():  # Walking through all parts of the mail body, both plain text and HTML
            C_type = part.get_content_type()
            if C_type in ["text/plain", "text/HTML"]:
                payload = part.get_payload(decode=True)  # Extract and decode payload
                if payload:
                    try:
                        body += payload.decode('utf-8', errors='ignore')
                    except Exception:
                        body += payload.decode('latin1', errors='ignore')
    else:
        payload = mail.get_payload(decode=True)
        if payload:
            try:
                body += payload.decode('utf-8', errors='ignore')
            except Exception:
                body += payload.decode('latin1', errors='ignore')
    
    return body

class Anchors(HTMLParser):
    '''HTML Parser to extract anchor tags and validate URLs down to HTML syntax level'''
    
    def __init__(self):
        '''Constructor method'''
        super().__init__()
        self.anchors = []      
        self.current_anchor = None  # Temporary hold the current anchor tag
        self.checking = False  # To check if the anchor tag is being checked
        
    def handle_starttag(self, tag, attrs):
        '''Called when a start tag is encountered'''
        if tag.lower() == "a":
            self.current_anchor = {'href': None, 'text': ''}
            for attr, value in attrs:
                if attr.lower() == "href":
                    self.current_anchor['href'] = value  # Extract the URL and store it
            self.checking = True
    
    def handle_data(self, data):
        '''Handles the text encountered between the tags'''
        if self.checking and self.current_anchor is not None:
            self.current_anchor['text'] += data.strip()  # Add the text to the anchor dictionary
    
    def handle_endtag(self, tag):
        '''Called when the end tag of an HTML anchor tag is encountered'''
        if tag.lower() == "a" and self.current_anchor is not None:
            self.anchors.append(self.current_anchor)  # Append the current anchor to the list
            self.current_anchor = None
            self.checking = False
    
def extract_domain(url):
    '''Function to extract the domain from a URL'''
    parsed = urlparse(url)
    return parsed.netloc.lower()  # Returns the network location (domain) from the parsed URL

def embed_mismatch(mail):
    '''Function to find mismatches between the URL and the domain in the anchor tags'''
    body = Url(mail)
    secure_urls = re.findall(r'https://[^\s\'"<>]+', body)
    unsecure_urls = re.findall(r'http://[^\s\'"<>]+', body)
    secured_url_count = len(secure_urls)
    unsecured_url_count = len(unsecure_urls)
    
    mismatched_anchors = []  # List to store mismatched anchor tags
    
    # Check if any anchor tags exist in the body text
    if '<a ' in body.lower():
        parser = Anchors()  # Create an instance of the Anchors parser
        parser.feed(body)  # Feed the email body to the parser
        
        # Loop through the extracted anchors
        for anchor in parser.anchors:
            href = anchor.get('href')
            text = anchor.get('text', '').strip()
            if href:
                href_domain = extract_domain(href)  # Extract domain from href URL
                
                # Check if the anchor text is a domain (contains a dot)
                if '.' in text:
                    # Normalize the anchor text (remove leading/trailing spaces)
                    anchor_text_domain = text.lower().strip()
                    
                    # If the anchor text is not found in the href domain, it's flagged as mismatched
                    if anchor_text_domain not in href_domain:
                        mismatched_anchors.append({"text": text, "href": href})
    
    detail = (
        f"Found {secured_url_count} secure URLs, {unsecured_url_count} insecure URLs, "
        f"and {len(mismatched_anchors)} mismatched anchor tag(s)."
    )
    
    return {
        "secured_url_count": secured_url_count,
        "unsecured_url_count": unsecured_url_count,
        "mismatched_anchor_tags": mismatched_anchors,
        "detail": detail
    }

def spf_validation_check(mail):
    """
    Validates the SPF record for the sender's domain and compares it
    with the sending IP address extracted from the Received headers.
    
    Returns:
        str: "original" if the sending IP is authorized by the SPF record,
             "likely spoofed" otherwise.
    """
    # Convert the mail string into an email message object if needed
    if isinstance(mail, str):
        mail = email.message_from_string(mail)
    
    # 1. Extract the sender's email address from Return-Path (or From)
    return_path = mail.get('Return-Path')
    from_header = mail.get('From')
    sender_email = None
    if return_path:
        sender_email = return_path.strip('<>')
    elif from_header:
        sender_email = email.utils.parseaddr(from_header)[1]
    
    if not sender_email or "@" not in sender_email:
        return "likely spoofed"
    
    sender_domain = sender_email.split('@')[1].lower()
    
    # 2. Retrieve SPF record from DNS TXT records
    try:
        answers = dns.resolver.resolve(sender_domain, 'TXT')
    except Exception:
        return "likely spoofed"  # DNS lookup failed or no SPF record
    
    spf_record = None
    for rdata in answers:
        txt = "".join([s.decode() if isinstance(s, bytes) else s for s in rdata.strings])
        if txt.startswith("v=spf1"):
            spf_record = txt
            break
    if spf_record is None:
        return "likely spoofed"
    
    # 3. Parse allowed IPv4 ranges from the SPF record
    ip4_patterns = re.findall(r'ip4:([0-9./]+)', spf_record)
    allowed_networks = []
    for pattern in ip4_patterns:
        try:
            if '/' not in pattern:
                pattern += '/32'
            network = ipaddress.ip_network(pattern, strict=False)
            allowed_networks.append(network)
        except Exception:
            continue
    
    # 4. Determine the sending IP address from Received headers
    received_headers = mail.get_all('Received', [])
    sending_ip = None
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    for header in received_headers:
        ips = re.findall(ip_pattern, header)
        if ips:
            sending_ip = ips[0]  # Taking the first IP encountered
            break
    if not sending_ip:
        return "likely spoofed"
    
    # 5. Validate: Check if the sending IP is in any allowed network
    try:
        sending_ip_obj = ipaddress.ip_address(sending_ip)
        for network in allowed_networks:
            if sending_ip_obj in network:
                return "original"
    except Exception:
        return "likely spoofed"
    
    return "likely spoofed"

# Main Program Execution
print("Hello user, welcome to Phish_Byte, a tool designed to analyze input mail scripts.")
print("And generate a report on whether it is spam or not.")
print("Please enter the mail script, the original message of the email you want to analyze.")
print("When you're done, press Ctrl+Z (Windows) to finish entering the email.")

# Read the entire email input until EOF (Ctrl+D or Ctrl+Z)
mail = sys.stdin.read()

print("Analyzing mail script...")

# Domain Consistency Check
a1 = Domain(mail)
print(a1)

# Embedded URL Check (mismatches, secure/insecure counts)
# Convert mail to email message object for functions that expect it
email_msg = email.message_from_string(mail)
a2 = embed_mismatch(email_msg)
print(a2)

# SPF Validation Check
spf_result = spf_validation_check(mail)
print("SPF Check:", spf_result)
