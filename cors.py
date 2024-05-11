import argparse, requests, random, sys, time, os, urllib3, socket
from urllib.parse import urlparse, urljoin
from colorama import Fore, init, Style, Back
from bs4 import BeautifulSoup

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init(autoreset=True)

# Define color constants
r = Fore.RED + Style.BRIGHT
g = Fore.GREEN + Style.BRIGHT
c = Fore.CYAN + Style.BRIGHT
y = Fore.YELLOW + Style.BRIGHT
m = Fore.MAGENTA + Style.BRIGHT
b = Fore.BLACK + Style.BRIGHT
o = Fore.RESET + Style.RESET_ALL

# Global variables
pages_list = []
potential_vulnerable_sites = []

# ASCII banner
banner = r"""
        /$$$$$$$  /$$$$$$   /$$$$$$   /$$$$$$$
       /$$_____/ /$$__  $$ /$$__  $$ /$$_____/
      | $$      | $$  \ $$| $$  \__/|  $$$$$$ 
      | $$      | $$  | $$| $$       \____  $$
      |  $$$$$$$|  $$$$$$/| $$       /$$$$$$$/
       \_______/ \______/ |__/      |_______/ 
                                    @0x.ans
"""

def search_for_pages(s, url, verbose=True, proxies=None):
    """Search for pages and extract URLs."""
    headers = {'User-Agent': random_user_agent()}
    try:
        res = s.get(url, verify=False, proxies=proxies, headers=headers)
        res.raise_for_status()
        if res.status_code == 200:
            soup = BeautifulSoup(res.content, 'html.parser')
            links = soup.find_all('a', href=True)
            pages_list.append(url)
            if links:
                print(Fore.GREEN + f"[+] URLs found:")
                for link in links:
                    href = link['href']
                    f_url = urljoin(url, href)
                    if f_url not in pages_list:
                        if verbose and int(verbose) >= 3:
                            print(c + f">> {b}{f_url}")
                            pages_list.append(f_url)
                            time.sleep(0.2)
                        elif f_url not in pages_list:
                            pages_list.append(f_url)
                return pages_list
            else:
                if verbose and int(verbose) >= 3:
                    print(r + f"-x {b}No links found on page: {url}")
        else:
            print(r + f"[-] Failed to retrieve page: {url} - Status code: {res.status_code}")
            return []
    except requests.exceptions.RequestException as e:
        if isinstance(e, requests.exceptions.ConnectionError) and isinstance(e.__cause__, socket.gaierror):
            if verbose and int(verbose) >= 3:
                print(r + f"-x Failed to resolve domain: {b}{url}")
            return
        else:
            print(r + f"[-] Error occurred while retrieving page: {b}{url} {r}- {e}")
            return
    return []


def test_cors(s, url, origin_header, output_file, verbose=True, proxies=None):
    """Test for CORS vulnerabilities."""
    print(y + f'\n[+] Testing CORS availability:\n')
    headers = {"Origin": origin_header, "User-Agent": random_user_agent()}
    try:
        for url in pages_list:
            try:
                res = s.get(url, headers=headers, verify=False, proxies=proxies, timeout=5)
                if 'Access-Control-Allow-Origin' in res.headers and res.headers['Access-Control-Allow-Origin'] == origin_header:
                    print(g + f'>> {y}Potential CORS at: {c}{url}')
                    potential_vulnerable_sites.append(url)
                    with open(output_file, 'a') as f:
                        f.write(url + '\n')
                else:
                    if verbose and int(verbose) >= 2:
                        print(r + f'-x Not vulnerable: {b}{url}')
            except requests.exceptions.RequestException as e:
                if verbose and int(verbose) >= 3:
                    print(r + f"-xx Request timed for:{b} {url} {r}- Skipping...")
                continue
    except Exception as e:
        print(r + f'\n[-] Error occurred while testing {b}{url}:{r} {e}')
        return
    except KeyboardInterrupt:
        return


def random_user_agent():
    """Generate a random user agent."""
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36',
    ]
    return random.choice(user_agents)


def check_url_reachability(url):
    """Check if a URL is reachable."""
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    try:
        requests.get(url)
        return True, url
    except requests.exceptions.RequestException:
        return False, url


def main():
    """Main function to execute the tool."""
    parser = argparse.ArgumentParser(description='Tool to find potential CORS vulnerabilities.')
    parser.add_argument('-u', '--url', required=False, help='The target URL.')
    parser.add_argument('-x', '--origin', required=False, default='https://example.com/', help='Custom origin header.')
    parser.add_argument('-p', '--proxy', required=False, help='The proxy parser.')
    parser.add_argument('-c', '--cookie', required=False, help='Cookie session.')
    parser.add_argument('-v', '--verbose', default=1, help='Verbose mode (e.g., -v 1,3).')
    parser.add_argument('-a', '--all_pages', action='store_true', help='Search for all site pages.')
    parser.add_argument('-w', '--wordlist', required=False, help='Wordlist file containing URLs.')
    parser.add_argument('-o', '--output_file', required=False, help='Output file to save potential vulnerabilities.')
    args = parser.parse_args()

    url = args.url
    wordlist = args.wordlist
    pages = args.all_pages
    origin_header = args.origin
    proxy = args.proxy
    cookie = args.cookie
    verbose = args.verbose
    output_file = args.output_file

    if len(sys.argv) < 2:
        parser.print_help()
        exit(0)

    s = requests.Session()

    proxies = {'http': proxy, 'https': proxy} if proxy else None

    if cookie:
        s.headers['Cookie'] = f'session={cookie}'

    if '-h' in sys.argv or '--help' in sys.argv:
        parser.print_help()
        exit(0)

    if wordlist:
        with open(args.wordlist, 'r') as f:
            wordlist_urls = f.readlines()
            for wordlist_url in wordlist_urls:
                wordlist_url = wordlist_url.strip()
                if not wordlist_url.startswith("http://") or not wordlist_url.startswith("https://"):
                    wordlist_url = f"http://{wordlist_url}"
                if wordlist_url not in pages_list:
                    if check_url_reachability(wordlist_url):
                        pages_list.append(wordlist_url)
                    else:
                        print(r + f"[-] Unable to reach or resolve domain: {wordlist_url}")

    else:
        if check_url_reachability(url)[0]:
            url = check_url_reachability(url)[1]
            search_for_pages(s, url, verbose=verbose, proxies=proxies)
        else:
            print(r + f"[-] Unable to reach or resolve domain: {b}{url}")
            return

    if output_file:
        test_cors(s, url, origin_header, output_file, verbose=verbose, proxies=proxies)
    else:
        default_output_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'potential_vulnerable_sites.txt')
        test_cors(s, url, origin_header, default_output_file, verbose=verbose, proxies=proxies)

    print('\nCORS testing completed.')

if __name__ == '__main__':
    os.system('cls' if os.name == 'nt' else 'clear')
    print(b + banner)
    main()
