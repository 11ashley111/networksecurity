from urllib.parse import urlparse
import re
import whois
import tldextract
from datetime import datetime
import socket
import requests
from bs4 import BeautifulSoup
import warnings
warnings.filterwarnings("ignore")

def extract_features_from_url(url: str) -> list:
    """
    Extract features from URL for phishing detection according to the specified feature list.
    Returns a list of 30 features with values: -1 (phishing), 0 (suspicious), 1 (legitimate)
    
    Features in order:
    1. having_IP_Address
    2. URL_Length  
    3. Shortining_Service
    4. having_At_Symbol
    5. double_slash_redirecting
    6. Prefix_Suffix
    7. having_Sub_Domain
    8. SSLfinal_State
    9. Domain_registeration_length
    10. Favicon
    11. port
    12. HTTPS_token
    13. Request_URL
    14. URL_of_Anchor
    15. Links_in_tags
    16. SFH
    17. Submitting_to_email
    18. Abnormal_URL
    19. Redirect
    20. on_mouseover
    21. RightClick
    22. popUpWidnow
    23. Iframe
    24. age_of_domain
    25. DNSRecord
    26. web_traffic
    27. Page_Rank
    28. Google_Index
    29. Links_pointing_to_page
    30. Statistical_report
    """
    
    # Ensure URL has a scheme
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        path = parsed_url.path
        
        # Clean domain (remove www and port)
        clean_domain = domain.replace('www.', '') if domain.startswith('www.') else domain
        clean_domain = clean_domain.split(':')[0]
        
    except Exception:
        return [-1] * 30
    
    def having_IP_Address(url):
        """1. Check if URL contains IP address instead of domain name"""
        ip_pattern = r'((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
        return -1 if re.search(ip_pattern, url) else 1
    
    def URL_Length(url):
        """2. Check URL length"""
        if len(url) < 54:
            return 1  # Short - legitimate
        elif len(url) < 75:
            return 0  # Medium - suspicious  
        else:
            return -1  # Long - phishing
    
    def Shortining_Service(url):
        """3. Check if URL uses shortening services"""
        shortening_services = [
            'bit.ly', 'goo.gl', 'shorte.st', 'x.co', 'ow.ly', 'tinyurl.com',
            't.co', 'bit.do', 'adf.ly', 'bitly.com', 'short.to', 'rb.gy',
            'cutt.ly', 'is.gd', 'buff.ly', 'tiny.cc', 'lnkd.in'
        ]
        for service in shortening_services:
            if service in url.lower():
                return -1
        return 1
    
    def having_At_Symbol(url):
        """4. Check for @ symbol in URL"""
        return -1 if '@' in url else 1
    
    def double_slash_redirecting(url):
        """5. Check for double slash after domain"""
        # Remove the initial http:// or https://
        if url.startswith('http://'):
            remaining = url[7:]
        elif url.startswith('https://'):
            remaining = url[8:]
        else:
            remaining = url
        
        # Find first single slash (end of domain part)
        first_slash = remaining.find('/')
        if first_slash != -1:
            after_domain = remaining[first_slash:]
            if '//' in after_domain:
                return -1
        return 1
    
    def Prefix_Suffix(domain):
        """6. Check for dash in domain name"""
        clean_domain_name = domain.split(':')[0]  # Remove port
        return -1 if '-' in clean_domain_name else 1
    
    def having_Sub_Domain(url):
        """7. Check number of subdomains"""
        try:
            ext = tldextract.extract(url)
            subdomain = ext.subdomain
            if not subdomain:
                return 1  # No subdomain
            
            subdomain_count = subdomain.count('.') + 1
            if subdomain_count == 1:
                return 1   # One subdomain - legitimate
            elif subdomain_count == 2:
                return 0   # Two subdomains - suspicious
            else:
                return -1  # Multiple subdomains - phishing
        except:
            return -1
    
    def SSLfinal_State(url, domain):
        """8. Check SSL certificate status"""
        if not url.startswith('https://'):
            return -1  # No HTTPS
        
        # Additional check for suspicious HTTPS usage
        if 'https' in domain.lower() and not url.startswith('https://'):
            return -1  # HTTPS in domain name but not using HTTPS
        
        return 1  # Using HTTPS properly
    
    def get_whois_info(domain):
        """Helper function to get WHOIS information"""
        try:
            return whois.whois(domain)
        except:
            return None
    
    def Domain_registeration_length(whois_info):
        """9. Check domain registration length"""
        try:
            if whois_info and whois_info.expiration_date and whois_info.creation_date:
                exp_date = whois_info.expiration_date
                create_date = whois_info.creation_date
                
                # Handle list format
                if isinstance(exp_date, list):
                    exp_date = exp_date[0]
                if isinstance(create_date, list):
                    create_date = create_date[0]
                
                if isinstance(exp_date, datetime) and isinstance(create_date, datetime):
                    reg_length = (exp_date - create_date).days
                    return 1 if reg_length >= 365 else -1
            
            return -1  # Suspicious if no registration info
        except:
            return -1
    
    def get_page_content(url):
        """Helper function to get page content"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            return response.text if response.status_code == 200 else None
        except:
            return None
    
    def Favicon(url, page_content):
        """10. Check favicon source"""
        if not page_content:
            return -1  # Changed from 0 to -1 for stricter security
        
        try:
            soup = BeautifulSoup(page_content, 'html.parser')
            favicon_links = soup.find_all('link', rel=lambda x: x and 'icon' in x.lower())
            
            if not favicon_links:
                return -1  # No favicon
            
            for link in favicon_links:
                href = link.get('href', '')
                if href:
                    # Check if favicon is from external domain
                    if href.startswith('http') and clean_domain not in href:
                        return -1  # External favicon - suspicious
            
            return 1  # Favicon from same domain
        except:
            return -1  # Changed from 0 to -1
    
    def port(url):
        """11. Check for non-standard ports"""
        try:
            port_num = parsed_url.port
            if port_num is None:
                return 1  # Standard port (80/443)
            elif port_num in [80, 443]:
                return 1  # Standard ports
            else:
                return -1  # Non-standard port
        except:
            return 1
    
    def HTTPS_token(url):
        """12. Check for HTTPS token in domain"""
        domain_part = parsed_url.netloc.lower()
        if 'https' in domain_part and not url.startswith('https://'):
            return -1  # HTTPS in domain but not using HTTPS
        return 1
    
    def Request_URL(page_content, domain):
        """13. Check percentage of external requests"""
        if not page_content:
            return -1  # Changed from 0 to -1 for stricter security
        
        try:
            soup = BeautifulSoup(page_content, 'html.parser')
            
            # Find all elements with src or href attributes
            elements = soup.find_all(['img', 'script', 'link', 'iframe', 'embed', 'object'])
            
            total_requests = 0
            external_requests = 0
            
            for element in elements:
                src = element.get('src') or element.get('href')
                if src:
                    total_requests += 1
                    if src.startswith('http') and domain not in src:
                        external_requests += 1
            
            if total_requests == 0:
                return 1
            
            external_percentage = external_requests / total_requests
            
            if external_percentage < 0.22:
                return 1   # Low external requests - legitimate
            elif external_percentage < 0.61:
                return 0   # Medium external requests - suspicious
            else:
                return -1  # High external requests - phishing
        except:
            return -1  # Changed from 0 to -1
    
    def URL_of_Anchor(page_content, domain):
        """14. Check anchor URLs"""
        if not page_content:
            return -1  # Changed from 0 to -1 for stricter security
        
        try:
            soup = BeautifulSoup(page_content, 'html.parser')
            anchors = soup.find_all('a', href=True)
            
            if not anchors:
                return 1
            
            total_anchors = len(anchors)
            suspicious_anchors = 0
            
            for anchor in anchors:
                href = anchor.get('href', '')
                if href in ['#', 'javascript:void(0)', 'javascript:;', '']:
                    suspicious_anchors += 1
                elif href.startswith('http') and domain not in href:
                    suspicious_anchors += 1
            
            suspicious_percentage = suspicious_anchors / total_anchors
            
            if suspicious_percentage < 0.31:
                return 1   # Few suspicious anchors - legitimate
            elif suspicious_percentage < 0.67:
                return 0   # Some suspicious anchors - suspicious
            else:
                return -1  # Many suspicious anchors - phishing
        except:
            return -1  # Changed from 0 to -1
    
    def Links_in_tags(page_content, domain):
        """15. Check links in meta, script, and link tags"""
        if not page_content:
            return -1  # Changed from 0 to -1 for stricter security
        
        try:
            soup = BeautifulSoup(page_content, 'html.parser')
            
            # Check meta tags
            meta_tags = soup.find_all('meta')
            script_tags = soup.find_all('script')
            link_tags = soup.find_all('link')
            
            total_tags = len(meta_tags) + len(script_tags) + len(link_tags)
            external_tags = 0
            
            for tag in meta_tags + script_tags + link_tags:
                for attr in ['content', 'src', 'href']:
                    value = tag.get(attr, '')
                    if value and value.startswith('http') and domain not in value:
                        external_tags += 1
                        break
            
            if total_tags == 0:
                return 1
            
            external_percentage = external_tags / total_tags
            
            if external_percentage < 0.17:
                return 1   # Few external links - legitimate
            elif external_percentage < 0.81:
                return 0   # Some external links - suspicious
            else:
                return -1  # Many external links - phishing
        except:
            return -1  # Changed from 0 to -1
    
    def SFH(page_content, domain):
        """16. Server Form Handler - Check form actions"""
        if not page_content:
            return -1  # Changed from 0 to -1 for stricter security
        
        try:
            soup = BeautifulSoup(page_content, 'html.parser')
            forms = soup.find_all('form')
            
            if not forms:
                return 1  # No forms
            
            for form in forms:
                action = form.get('action', '')
                if action == '' or action == '#':
                    return -1  # Empty or suspicious action
                elif action.startswith('http') and domain not in action:
                    return -1  # External form handler
                elif 'mailto:' in action:
                    return -1  # Email form handler
            
            return 1  # Normal form handlers
        except:
            return -1  # Changed from 0 to -1
    
    def Submitting_to_email(page_content):
        """17. Check if forms submit to email"""
        if not page_content:
            return -1  # Changed from 0 to -1 for stricter security
        
        try:
            if 'mailto:' in page_content.lower():
                return -1  # Form submits to email
            return 1
        except:
            return -1  # Changed from 0 to -1
    
    def Abnormal_URL(whois_info, url):
        """18. Check if URL appears in WHOIS info"""
        if not whois_info:
            return -1  # No WHOIS info - suspicious
        
        try:
            whois_text = str(whois_info).lower()
            domain_name = clean_domain.lower()
            
            # Check if domain appears in WHOIS info
            if domain_name in whois_text:
                return 1  # Domain found in WHOIS - normal
            else:
                return -1  # Domain not in WHOIS - abnormal
        except:
            return -1
    
    def Redirect(url):
        """19. Check for redirects"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.head(url, headers=headers, timeout=10, allow_redirects=False)
            
            if response.status_code in [301, 302, 303, 307, 308]:
                # Check number of redirects
                redirect_response = requests.get(url, headers=headers, timeout=10)
                redirect_count = len(redirect_response.history)
                
                if redirect_count <= 1:
                    return 1   # Few redirects - normal
                elif redirect_count <= 4:
                    return 0   # Some redirects - suspicious
                else:
                    return -1  # Many redirects - phishing
            
            return 1  # No redirects
        except:
            return -1  # Changed from 0 to -1 for stricter security
    
    def on_mouseover(page_content):
        """20. Check for mouseover events that change status bar"""
        if not page_content:
            return 1
        
        try:
            # Check for suspicious JavaScript mouseover events
            suspicious_patterns = [
                'onmouseover.*window.status',
                'onmouseover.*location.href',
                'window.status.*onmouseover'
            ]
            
            page_lower = page_content.lower()
            for pattern in suspicious_patterns:
                if re.search(pattern, page_lower):
                    return -1  # Suspicious mouseover
            
            return 1  # No suspicious mouseover
        except:
            return 1
    
    def RightClick(page_content):
        """21. Check if right-click is disabled"""
        if not page_content:
            return 1
        
        try:
            # Check for right-click disabling code
            disable_patterns = [
                'oncontextmenu.*return false',
                'oncontextmenu.*false',
                'event.button.*2',
                'contextmenu.*preventdefault'
            ]
            
            page_lower = page_content.lower()
            for pattern in disable_patterns:
                if re.search(pattern, page_lower):
                    return -1  # Right-click disabled
            
            return 1  # Right-click not disabled
        except:
            return 1
    
    def popUpWidnow(page_content):
        """22. Check for popup windows"""
        if not page_content:
            return 1
        
        try:
            # Check for popup window code
            popup_patterns = [
                'window.open',
                'popup',
                'alert\(',
                'confirm\('
            ]
            
            page_lower = page_content.lower()
            popup_count = sum(1 for pattern in popup_patterns if pattern in page_lower)
            
            if popup_count == 0:
                return 1   # No popups
            elif popup_count <= 2:
                return 0   # Few popups - suspicious
            else:
                return -1  # Many popups - phishing
        except:
            return 1
    
    def Iframe(page_content):
        """23. Check for iframe usage"""
        if not page_content:
            return 1
        
        try:
            soup = BeautifulSoup(page_content, 'html.parser')
            iframes = soup.find_all('iframe')
            
            if not iframes:
                return 1  # No iframes
            
            # Check for invisible or suspicious iframes
            suspicious_iframes = 0
            for iframe in iframes:
                width = iframe.get('width', '100')
                height = iframe.get('height', '100')
                style = iframe.get('style', '')
                
                # Check for invisible iframes
                if (width in ['0', '1'] or height in ['0', '1'] or 
                    'display:none' in style.replace(' ', '') or
                    'visibility:hidden' in style.replace(' ', '')):
                    suspicious_iframes += 1
            
            if suspicious_iframes == 0:
                return 1   # No suspicious iframes
            elif suspicious_iframes <= len(iframes) // 2:
                return 0   # Some suspicious iframes
            else:
                return -1  # Many suspicious iframes
        except:
            return 1
    
    def age_of_domain(whois_info):
        """24. Check domain age"""
        try:
            if whois_info and whois_info.creation_date:
                create_date = whois_info.creation_date
                if isinstance(create_date, list):
                    create_date = create_date[0]
                
                if isinstance(create_date, datetime):
                    age_days = (datetime.now() - create_date).days
                    
                    if age_days >= 180:  # 6 months
                        return 1   # Old domain - legitimate
                    elif age_days >= 30:  # 1 month
                        return 0   # Medium age - suspicious
                    else:
                        return -1  # New domain - phishing
            
            return -1  # No creation date - suspicious
        except:
            return -1
    
    def DNSRecord(domain):
        """25. Check if domain has DNS record"""
        try:
            socket.gethostbyname(domain)
            return 1  # DNS record exists
        except:
            return -1  # No DNS record
    
    def web_traffic(domain):
        """26. Website traffic - now more strict"""
        # Since we can't access external APIs, assume low traffic = suspicious
        # Most legitimate sites have some traffic data available
        return -1  # Changed from 0 to -1 for stricter security
    
    def Page_Rank(domain):
        """27. Page rank - now more strict"""
        # Since we can't access Google PageRank, assume no PageRank = suspicious
        # Most legitimate sites have some PageRank
        return -1  # Changed from 0 to -1 for stricter security
    
    def Google_Index(url):
        """28. Check if indexed by Google - now more strict"""
        # Since we can't check Google indexing, assume not indexed = suspicious
        # Most legitimate sites are indexed by Google
        return -1  # Changed from 0 to -1 for stricter security
    
    def Links_pointing_to_page(domain):
        """29. Number of links pointing to page - now more strict"""
        # Since we can't check backlinks, assume no backlinks = suspicious
        # Most legitimate sites have some backlinks
        return -1  # Changed from 0 to -1 for stricter security
    
    def Statistical_report(domain):
        """30. Statistical report based on other security services - now more strict"""
        # Since we can't check threat intelligence, assume unknown = suspicious
        # Most legitimate sites have clean reputation
        return -1  # Changed from 0 to -1 for stricter security
    
    # Main feature extraction
    features = []
    
    try:
        # Get WHOIS info and page content (with timeout)
        whois_info = get_whois_info(clean_domain)
        page_content = get_page_content(url)
        
        # Extract all 30 features in the specified order
        features.append(having_IP_Address(url))                        # 1
        features.append(URL_Length(url))                              # 2
        features.append(Shortining_Service(url))                      # 3
        features.append(having_At_Symbol(url))                        # 4
        features.append(double_slash_redirecting(url))                # 5
        features.append(Prefix_Suffix(domain))                        # 6
        features.append(having_Sub_Domain(url))                       # 7
        features.append(SSLfinal_State(url, domain))                  # 8
        features.append(Domain_registeration_length(whois_info))      # 9
        features.append(Favicon(url, page_content))                   # 10
        features.append(port(url))                                    # 11
        features.append(HTTPS_token(url))                             # 12
        features.append(Request_URL(page_content, clean_domain))      # 13
        features.append(URL_of_Anchor(page_content, clean_domain))    # 14
        features.append(Links_in_tags(page_content, clean_domain))    # 15
        features.append(SFH(page_content, clean_domain))              # 16
        features.append(Submitting_to_email(page_content))            # 17
        features.append(Abnormal_URL(whois_info, url))                # 18
        features.append(Redirect(url))                                # 19
        features.append(on_mouseover(page_content))                   # 20
        features.append(RightClick(page_content))                     # 21
        features.append(popUpWidnow(page_content))                    # 22
        features.append(Iframe(page_content))                         # 23
        features.append(age_of_domain(whois_info))                    # 24
        features.append(DNSRecord(clean_domain))                      # 25
        features.append(web_traffic(clean_domain))                    # 26
        features.append(Page_Rank(clean_domain))                      # 27
        features.append(Google_Index(url))                            # 28
        features.append(Links_pointing_to_page(clean_domain))         # 29
        features.append(Statistical_report(clean_domain))             # 30
        
    except Exception as e:
        print(f"Error extracting features: {e}")
        features = [-1] * 30
    
    # Ensure exactly 30 features
    while len(features) < 30:
        features.append(-1)
    
    return features[:30]