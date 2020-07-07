import requests
import json
import os
import sys
import argparse
from collections import Counter, defaultdict

apiurl = "https://virustotal.com/api/v3/"
apikey = os.getenv("VT_API_KEY")
min_threshold = 0.5 # 50% similarity score
min_size = 1024
max_size = 1024 * 3


def parse_input_file(min_threshold, file_path, min_block_length):
    if not os.path.isfile(file_path):
        print("File path {0} does not exist. Exiting...".format(file_path))
        sys.exit()
    with open(file_path) as file:
        for line in file:
            print("Running script for hash {0}: ".format(line.strip()))
            file_hash = line.strip()
            calculate_blocks(min_threshold, file_hash, min_block_length)

class Generator(object):

    def __init__(self, min_threshold, file_hash, min_block_length):
        self.min_threshold = min_threshold
        self.file_hash = file_hash
        self.min_block_length = min_block_length

    def fetch_blocks_from_VT(file_hash):
        headers = {'x-apikey': apikey, 'Content-Type': 'application/json'}
        response = requests.get(
            apiurl + 'intelligence/search?query=code-similar-to:' + file_hash, headers=headers)
        response_json = response.json()
        with open('VT_Similar_{0}.json'.format(file_hash), 'w') as f: # Save json file for debugging purposes
            json.dump(response_json, f)
            f.close()
        return(response_json)

    def calculate_blocks(min_threshold, file_hash, min_block_length):
        code_blocks_list = []
        code_blocks_dict = defaultdict(list)
        samples_over_threshold_counter = 0
        try: # Try to open json results file to spare retrieving it again
            f = open('VT_Similar_{0}.json'.format(file_hash), 'r')
            raw_data = json.load(f)
        except IOError:
            raw_data = fetch_blocks_from_VT(file_hash)
        if raw_data.get('data'):
            for item in raw_data['data']:
                if item['context_attributes']['similarity_score'] > min_threshold: #If the resulting sample is over the similarity threshold
                    if item.get('attributes',{}).get('pe_info'): #check if the resulting sample is a pe file
                        samples_over_threshold_counter += 1
                        get_filesize_range(item['attributes']['size'])
                        for block in item['context_attributes']['code_block']:
                            if block['length'] > min_block_length:
                                if block['offset'] not in code_blocks_dict[block['binary']]:
                                    code_blocks_dict[block['binary']].append(block['offset'])
                                code_blocks_list.append(block['binary'])
        else:
            print "Got no results, please try another hash\n"
            return
        if samples_over_threshold_counter >= 100:
            print "Threshold too low, catching over 100 samples, please raise threshold\n"
            return
        elif samples_over_threshold_counter == 0:
            print "Threshold too high, caught 0 samples, please lower threshold\n"
            return
        else:
            print "Found {0} samples over the threshold of {1}".format(samples_over_threshold_counter,min_threshold)
        print "Samples size ranges between {0} bytes to {1} bytes".format(min_size,max_size)
        cnt = Counter(code_blocks_list) # Dict of code blocks and their repetition count
        generate_yara(cnt, code_blocks_dict,file_hash)

    def get_filesize_range(filesize):
        global max_size
        global min_size
        max_size = max(max_size,filesize)
        min_size = min(min_size,filesize)


    def generate_yara(cnt, code_blocks_dict,file_hash):
        i = 0
        top_popular = input("Found {0} code blocks over set threshold, how many top ones should I use?: ".format(len(cnt)))
        top_code_blocks = dict(cnt.most_common(top_popular))
        num_of_them =  input("Out of {0} code blocks, what's the minimal condition?: ".format(top_popular))
        rulefile = open('Similarity_rule_{0}.yara'.format(file_hash), 'w')
        rulefile.write("rule VTSimilarity_"+file_hash+" {\n")
        rulefile.write("\tmeta: \n")
        rulefile.write("\t\tdescription = \"rule to hunt for samples similar to {0}\"\n".format(file_hash))
        rulefile.write("\tstrings: \n")
        for block in top_code_blocks:
            i += 1
            rulefile.write("\t\t$block{0} = {{ {1} }}\n".format(i, block))
        rulefile.write("\tcondition: \n")
        rulefile.write("\t\t(uint16(0) == 0x5A4D) and filesize > {0}KB and filesize < {1}KB \n".format(min_size/1024,max_size/1024))
        rulefile.write("\tand {0} of them }}\n".format(num_of_them))
        print "Generated yara rule for {0}\n".format(file_hash)


def main():
    parser = argparse.ArgumentParser(description='VTSimilarity Yara Generator')
    parser.add_argument('--hash', metavar='Hash', type=str, dest='file_hash',
                       help='MD5/SHA1/SHA256 hash to check on VTi')
    parser.add_argument('--t', metavar='0.5', type=float, dest='min_threshold',
                                    default=0.5, help='Minimum similarity threshold (default=0.5)')
    parser.add_argument('--list', metavar='hash_list.txt', type=str, dest='file_path',
                                    help='Path to a file containing list of hashes')
    parser.add_argument('--min_block', metavar='4', type=int, dest='min_block_length',
                                    default=4, help='Minimum desired codeblock size')
    parser.add_argument('--apikey', metavar='4', type=str, dest='apikey',
                                    default='', help='VT API Key')
    args = parser.parse_args()
    global apikey
    apikey = args.apikey or apikey
    if args.file_path:
        parse_input_file(args.min_threshold, args.file_path, args.min_block_length)
    elif args.file_hash:
        calculate_blocks(args.min_threshold, args.file_hash, args.min_block_length)

if __name__ == "__main__":
    main()
