import requests
import json
import os
import sys
import argparse
from collections import Counter, defaultdict

apiurl = "https://virustotal.com/api/v3/"
apikey = os.getenv("VT_API_KEY")
MIN_SIZE = 1024
MAX_SIZE = 1024 * 3
VERSION = 0.3


def parse_input_file(min_threshold, file_path, min_block_size):
    if not os.path.isfile(file_path):
        print("File path {0} does not exist. Exiting...".format(file_path))
        sys.exit()
    with open(file_path) as file:
        for line in file:
            print("Running script for hash {0}: ".format(line.strip()))
            file_hash = line.strip()
            generator = Generator(min_threshold, file_hash, min_block_size)
            generator.calculate_blocks()

class Generator(object):

    def __init__(self, min_threshold, file_hash, min_block_size):
        self.min_threshold = min_threshold
        self.file_hash = file_hash.lower()
        self.min_block_size = min_block_size
        self.min_size = MIN_SIZE
        self.max_size = MAX_SIZE
        self.version = VERSION
        self.samples_over_threshold_counter = 0

    def fetch_blocks_from_VT(self):
        headers = {'x-apikey': apikey, 'Content-Type': 'application/json'}
        response = requests.get(
            apiurl + 'intelligence/search?query=code-similar-to:' + self.file_hash, headers=headers)
        response_json = response.json()
        with open('VT_Similar_{0}.json'.format(self.file_hash), 'w') as f: # save json file for debugging purposes
            json.dump(response_json, f)
            f.close()
        return(response_json)

    def calculate_blocks(self):
        code_blocks_dict = {}
        try: # try to open json results file to spare retrieving it again
            f = open('VT_Similar_{0}.json'.format(self.file_hash), 'r')
            raw_data = json.load(f)
        except IOError:
            raw_data = self.fetch_blocks_from_VT()
        if raw_data.get('data'):
            for item in raw_data['data']:
                if item['context_attributes']['similarity_score'] > self.min_threshold: # if the resulting sample is over the similarity threshold
                    if item.get('attributes',{}).get('pe_info'): # check if the resulting sample is a pe file
                        self.samples_over_threshold_counter += 1
                        if item['attributes']['md5'] == self.file_hash:
                            self.min_size = item['attributes']['size']
                        else:
                            self.get_filesize_range(item['attributes']['size'])
                        for block in item['context_attributes']['code_block']:
                            if block['length'] >= self.min_block_size:
                                if not code_blocks_dict.has_key(block['binary']): # if codeblock doesn't exist
                                    code_blocks_dict.update({block['binary']:{'counter': 0, 'asm': [block['asm']], 'offset': [block['offset']]}}) # add new codeblock, its assembly and offset
                                code_blocks_dict[block['binary']]['counter'] += 1 # up the count seen for each codeblock
                                if block['offset'] not in code_blocks_dict[block['binary']]['offset']:
                                    code_blocks_dict[block['binary']]['offset'].append(block['offset'])
        else:
            print "Got no results, please try another hash\n"
            return
        if self.samples_over_threshold_counter >= 100:
            print "Threshold too low, catching over 100 samples, consider raising threshold\n"
        elif self.samples_over_threshold_counter == 1:
            print "Threshold too high, caught 1 sample, consider raising threshold\n"
            self.max_size = self.min_size
        else:
            print "Found {0} samples over the similarity threshold of {1:.1%}".format(self.samples_over_threshold_counter,self.min_threshold)
        print "Samples size ranges between {0} bytes to {1} bytes".format(self.min_size, self.max_size)
        if code_blocks_dict:
            self.generate_yara(code_blocks_dict)
        else:
            print "No code blocks found over set threshold size of {0}".format(self.min_block_size)

    def get_filesize_range(self, filesize):
        self.max_size = max(self.max_size, filesize)
        self.min_size = min(self.min_size, filesize)

    def generate_yara(self, code_blocks_dict):
        i = 0
        sorted_code_blocks = sorted(code_blocks_dict, key=lambda x: (code_blocks_dict[x]['counter']), reverse = True)
        top_popular = input("Found {0} code blocks over set threshold, how many top ones should I use?: ".format(len(sorted_code_blocks)))
        top_code_blocks = sorted_code_blocks[:top_popular]
        min_condition =  code_blocks_dict[top_code_blocks[-1]]['counter'] # autoset min condition to the least popular codeblock selected so we'll detect our own sample
        rulefile = open('Similarity_rule_{0}.yara'.format(self.file_hash), 'w')
        rulefile.write("rule VTSimilarity_"+self.file_hash+" {\n")
        rulefile.write("\n\tmeta: \n")
        rulefile.write("\t\tdescription = \"rule to hunt for samples similar to {0}\"\n".format(self.file_hash))
        rulefile.write("\t\tscript_version = \"{0}\"\n".format(self.version))
        rulefile.write("\t\tsimilarity_threshold = \"{0:.0%}\"\n".format(self.min_threshold))
        rulefile.write("\t\tminimal_codeblock_size = \"{0}\"\n".format(self.min_block_size))
        rulefile.write("\t\tsimilar_samples_analyzed = \"{0}\"\n".format(self.samples_over_threshold_counter))
        rulefile.write("\n\tstrings: \n")
        for block in top_code_blocks:
            i += 1
            rulefile.write("\t\t$block{0} = {{ {1} }} // Seen in {2} samples\n".format(i, block, code_blocks_dict[block]['counter']))
        rulefile.write("\n\tcondition: \n")
        rulefile.write("\t\t(uint16(0) == 0x5A4D) and filesize >= {0}KB and filesize <= {1}KB \n".format(self.min_size/1024, self.max_size/1024+1))
        rulefile.write("\tand {0} of them }}\n".format(min_condition))
        print "Generated yara rule for {0}\n".format(self.file_hash)


def main():
    parser = argparse.ArgumentParser(description='VTSimilarity Yara Generator')
    parser.add_argument('--hash', metavar='Hash', type=str, dest='file_hash',
                       help='MD5/SHA1/SHA256 hash to check on VTi')
    parser.add_argument('--t', metavar='0.5', type=float, dest='min_threshold',
                                    default=0.5, help='Minimum similarity threshold (default=0.5)')
    parser.add_argument('--hashlist', metavar='hash_list.txt', type=str, dest='file_path',
                                    help='Path to a file containing list of hashes')
    parser.add_argument('--min_block', metavar='4', type=int, dest='min_block_size',
                                    default=4, help='Minimum desired codeblock size')
    parser.add_argument('--apikey', metavar='Your VirusTotal API Key', type=str, dest='apikey',
                                    help='VT API Key')
    args = parser.parse_args()
    global apikey
    apikey = args.apikey or apikey
    if args.file_path:
        parse_input_file(args.min_threshold, args.file_path, args.min_block_size)
    elif args.file_hash:
        generator = Generator(args.min_threshold, args.file_hash, args.min_block_size)
        generator.calculate_blocks()

if __name__ == "__main__":
    main()
