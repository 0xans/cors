# CORS Scanner Tool
## Name: CORS
## Author: 0x.ans
## Contact: Instagram: [0x.ans](https://instagram.com/0x.ans)

       /$$$$$$$  /$$$$$$   /$$$$$$   /$$$$$$$
      /$$_____/ /$$__  $$ /$$__  $$ /$$_____/
     | $$      | $$  \ $$| $$  \__/|  $$$$$$
     | $$      | $$  | $$| $$       \____  $$
     |  $$$$$$$|  $$$$$$/| $$       /$$$$$$$/
      \_______/ \______/ |__/      |_______/
                                    @0x.ans

## Usage:
python3 cors.py -u <url>

## Tool Description:
CORS (Cross-Origin Resource Sharing) Scanner is a Python tool designed to find potential CORS vulnerabilities in web applications. It helps security professionals and developers identify misconfigurations that could lead to security risks.

## Options:

- `-h, --help`: Show help message and exit.
- `-u URL, --url URL`: Specify the target URL.
- `-x ORIGIN, --origin ORIGIN`: Custom origin header.
- `-p PROXY, --proxy PROXY`: Specify the proxy parser.
- `-c COOKIE, --cookie COOKIE`: Cookie session.
- `-v VERBOSE, --verbose VERBOSE`: Verbose mode (e.g., -v 1,3).
- `-a, --all_pages`: Search for all site pages.
- `-w WORDLIST, --wordlist WORDLIST`: Wordlist file containing URLs.
- `-o OUTPUT_FILE, --output_file OUTPUT_FILE`: Output file to save potential vulnerabilities.

## Example Usage:

**To scan a specific URL:**
python3 cors.py -u https://example.com

**To specify a custom origin header:**
python3 cors.py -u https://example.com -x https://custom-origin.com

**To save potential vulnerabilities to a file:**
python3 cors.py -u https://example.com -o output.txt

For more details on usage and options, refer to the help message provided by the tool.

## BUG ?
- Submit new issue
- dm me in insta
- do you want ask about the tool ? you can add me in instagram : 0x.ans
