#!/usr/bin/python
# VTCodeSimilarity Yara generator
# Ariel Jungheit, @arieljt
import requests
import json
import os
import sys
import argparse

__version__ = "0.4"
apiurl = "https://virustotal.com/api/v3/"
apikey = os.getenv("VT_API_KEY")

def print_banner():
    print("------------------------------------------------------------------------------")
    print("........ O ........  _   __ ______  _____          __                         ")
    print("...... O---o ...... | | / //_  __/ / ___/ ___  ___/ / ___                     ")
    print("..... O-----o ..... | |/ /  / /   / /__  / _ \/ _  / / -_)                    ")
    print(".... o-------o .... |___/  /_/    \___/  \___/\_,_/  \__/                     ")
    print("..... o-----O .....    ____   _           _    __               _   __        ")
    print("...... o---O ......   / __/  (_)  __ _   (_)  / / ___ _  ____  (_) / /_  __ __")
    print("........ O ........  _\ \   / /  /  ' \ / /  / / / _ `/ / __/ / / / __/ / // /")
    print("...... O---o ...... /___/  /_/  /_/_/_//_/  /_/  \_,_/ /_/   /_/  \__/  \_, / ")
    print("..... O-----o .....                                     Version: {0}   /___/  ").format(__version__ )
    print("------------------------------------------------------------------------------")

def parse_input_file(min_similarity, file_path, min_block_size, debug):
    # Parses hash list file
    if not os.path.isfile(file_path):
        print("[-] File path {0} does not exist. Exiting...".format(file_path))
        sys.exit()
    with open(file_path) as file:
        for line in file:
            print("[+] Running script for hash {0}: ".format(line.strip()))
            file_hash = line.strip()
            generator = Generator(min_similarity, file_hash, min_block_size, debug)
            generator.calculate_blocks()


class Generator(object):

    def __init__(self, min_similarity, file_hash, min_block_size, debug):
        self.min_similarity = float(min_similarity.strip('%')) / 100.0
        self.file_hash = file_hash.lower()
        self.min_block_size = min_block_size
        self.min_size = None
        self.max_size = self.min_size
        self.version = __version__
        self.samples_over_threshold_counter = 0
        self.original_sample_blocks = []
        self.debug = debug

    def fetch_blocks_from_VT(self):
        # Fetches code blocks from VirusTotal for a given hash
        headers = {'x-apikey': apikey, 'Content-Type': 'application/json'}
        response = requests.get(
            apiurl + 'intelligence/search?query=code-similar-to:' + self.file_hash, headers=headers)
        response_json = response.json()
        if self.debug == True:
            # Save json file for debugging purposes
            with open('VT_Similar_{0}.json'.format(self.file_hash), 'w') as f:
                json.dump(response_json, f)
                f.close()
        return(response_json)

    def calculate_blocks(self):
        # Calculates code blocks popularity and performs basic checks
        code_blocks_dict = {}
        try:  # Try to open json results file to spare retrieving it again
            f = open('VT_Similar_{0}.json'.format(self.file_hash), 'r')
            raw_data = json.load(f)
        except IOError:
            raw_data = self.fetch_blocks_from_VT()
        if raw_data.get('data'):
            for item in raw_data['data']:
                # If the resulting sample is over the similarity threshold
                if item['context_attributes']['similarity_score'] > self.min_similarity: # Check if resulting sample is over set similarity threshold
                    if item.get('attributes', {}).get('pe_info'):  # Check if the resulting sample is a pe file
                        self.samples_over_threshold_counter += 1
                        if item['attributes']['md5'] == self.file_hash: # If we're looking at our original sample
                            self.min_size = item['attributes']['size'] # Set initial filesize
                            original_sample_code_blocks = item['context_attributes']['code_block'] # Collect original sample codeblocks
                            self.original_sample_blocks = [x['binary']
                                                           for x in original_sample_code_blocks]
                            print ("[+] Extracted {0} code blocks from {1}".format(
                                len(self.original_sample_blocks), self.file_hash))
                        else:
                            self.get_filesize_range(item['attributes']['size']) # Update filesize range
                        for block in item['context_attributes']['code_block']: # Collect codeblocks
                            if block['length'] >= self.min_block_size: # Check that block size is over set length
                                if not code_blocks_dict.has_key(block['binary']): # If codeblock doesn't exist
                                    code_blocks_dict.update({block['binary']: {'counter': 0, 'asm': [block['asm']], 'offset': [
                                                            block['offset']]}})  # Add new codeblock, its assembly and offset
                                code_blocks_dict[block['binary']]['counter'] += 1 # Up the count seen for each codeblock
                                if block['offset'] not in code_blocks_dict[block['binary']]['offset']: # If offset seen for the codeblock is new
                                    code_blocks_dict[block['binary']
                                                     ]['offset'].append(block['offset'])
        else:
            print "[-] Got no results, please try another hash\n"
            return
        if self.samples_over_threshold_counter >= 100:
            print "[-] Similarity threshold too low, catching over 100 samples, consider raising threshold\n"
        elif self.samples_over_threshold_counter == 1:
            print "[-] Similarity threshold too high, caught 1 sample, consider lowering threshold\n"
            self.max_size = self.min_size
        else:
            print "[+] Parsed {0} samples over the similarity threshold of {1:.1%}".format(
                self.samples_over_threshold_counter, self.min_similarity)
        print "[+] Samples size ranges between {0} bytes to {1} bytes".format(
            self.min_size, self.max_size)
        if code_blocks_dict:
            self.generate_yara(code_blocks_dict)
        else:
            print "[-] Found no code blocks over set threshold size of {0}".format(self.min_block_size)

    def get_filesize_range(self, filesize):
        # Stores maximal and minimal file sizes seen across samples
        self.max_size = max(self.max_size, filesize)
        self.min_size = min(self.min_size, filesize)

    def count_blocks(self, code_blocks):
        # Counts number of code blocks present in the original sample
        counter = 0
        for block in code_blocks:
            if block in self.original_sample_blocks:
                counter += 1
        return counter

    def generate_yara(self, code_blocks_dict):
        # Generates Yara rule
        i = 0
        sorted_code_blocks = sorted(code_blocks_dict, key=lambda x: (
            code_blocks_dict[x]['counter']), reverse=True)
        top_popular = input("\n[+] Found {0} code blocks over set threshold, how many top ones to include?: ".format(
            len(sorted_code_blocks)))
        top_code_blocks = sorted_code_blocks[:top_popular]
        min_condition = self.count_blocks(top_code_blocks)
        rulefile = open('Similarity_rule_{0}.yara'.format(self.file_hash), 'w')
        rulefile.write("rule VTCodeSimilarity_"+self.file_hash+" {\n")
        rulefile.write("\n\tmeta: \n")
        rulefile.write(
            "\t\tdescription = \"rule to hunt for samples similar to {0}\"\n".format(self.file_hash))
        rulefile.write("\t\tscript_version = \"{0}\"\n".format(self.version))
        rulefile.write("\t\tsimilarity_threshold = \"{0:.0%}\"\n".format(self.min_similarity))
        rulefile.write("\t\tminimal_codeblock_size = \"{0}\"\n".format(self.min_block_size))
        rulefile.write("\t\tsimilar_samples_analyzed = \"{0}\"\n".format(
            self.samples_over_threshold_counter))
        rulefile.write("\n\tstrings: \n")
        for block in top_code_blocks:
            i += 1
            rulefile.write(
                "\t\t$block{0} = {{ {1} }} // Seen in {2} samples\n".format(i, block, code_blocks_dict[block]['counter']))
        rulefile.write("\n\tcondition: \n")
        rulefile.write("\t\t(uint16(0) == 0x5A4D) and filesize >= {0}KB and filesize <= {1}KB \n".format(
            self.min_size/1024, self.max_size/1024+1))
        rulefile.write("\tand {0} of them }}\n".format(min_condition))
        print "[+] Generated yara rule for {0}\n".format(self.file_hash)


def main():
    parser = argparse.ArgumentParser(description='VirusTotal Code Similarity Yara Generator')
    parser.add_argument('--hash', metavar='MD5/SHA1/SHA256', type=str, dest='file_hash',
                        help='MD5/SHA1/SHA256 hash to check on VTi')
    parser.add_argument('--threshold', metavar='50%', type=str, dest='min_similarity',
                        default="50%", help='Minimum similarity threshold')
    parser.add_argument('--hashlist', metavar='hashes.txt', type=str, dest='file_path',
                        help='Path to a file containing list of hashes')
    parser.add_argument('--min_block', metavar='4', type=int, dest='min_block_size',
                        default=4, help='Minimum desired codeblock size')
    parser.add_argument('--apikey', type=str, dest='apikey', help='VT API key')
    parser.add_argument('--debug', action='store_true', help='Store VirusTotal JSON data')
    args = parser.parse_args()

    global apikey
    apikey = args.apikey or apikey

    if len(sys.argv) == 1:
        print_banner()
        parser.print_help(sys.stderr)
    elif not apikey:
        parser.error("API key missing")
    elif args.file_path:
        parse_input_file(args.min_similarity, args.file_path, args.min_block_size, args.debug)
    elif args.file_hash:
        generator = Generator(args.min_similarity, args.file_hash, args.min_block_size, args.debug)
        generator.calculate_blocks()


if __name__ == "__main__":
    main()
