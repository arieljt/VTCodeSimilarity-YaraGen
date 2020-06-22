import requests
import json
import os
import sys
import argparse
from collections import Counter, defaultdict

apiurl = "https://virustotal.com/api/v3/"
apikey = "KEY"
max_size = 1024 * 3 # bytes
min_size = 1024
min_block_length = 3 # 3 seems too small
min_threshold = 0.5

def parse_input_file(min_threshold, file_path):
    if not os.path.isfile(file_path):
        print("File path {0} does not exist. Exiting...".format(file_path))
        sys.exit()
    with open(file_path) as file:
        #print("Parsed {0} lines".format(len(line))
        for line in file:
            print("Running script for hash {0}: ".format(line.strip()))
            file_hash = line.strip()
            print file_hash
            calculate_blocks(min_threshold, file_hash)

def fetch_blocks_from_VT(file_hash):
    headers = {'x-apikey': apikey, 'Content-Type': 'application/json'}
    response = requests.get(
        apiurl + 'intelligence/search?query=code-similar-to:' + file_hash, headers=headers)
    response_json = response.json()
    with open('VT_Similar_{0}.json'.format(file_hash), 'w') as f: # Save json file for debugging purposes
        json.dump(response_json, f)
        f.close()
    return(response_json)

def calculate_blocks(min_threshold, file_hash):
    code_blocks_list = []
    code_blocks_dict = defaultdict(list)
    interesting_samples_counter = 0
    try: # Try to open json results file to spare retrieving it again
        f = open('VT_Similar_{0}.json'.format(file_hash), 'r')
        datastore = json.load(f)
    except IOError:
        datastore = fetch_blocks_from_VT(file_hash)
    if datastore.get('data'):
        for item in datastore['data']:
            if item['context_attributes']['similarity_score'] > min_threshold:
                if not item['attributes']['pe_info']:
                    print "{0} is not a pe file, exiting".format(item['attributes']['md5'])
                    sys.exit()
                interesting_samples_counter += 1
                get_filesize_range(item['attributes']['size'])
                for block in item['context_attributes']['code_block']:
                    if block['length'] > min_block_length:
                        if block['offset'] not in code_blocks_dict[block['binary']]:
                            code_blocks_dict[block['binary']].append(block['offset'])
                        code_blocks_list.append(block['binary'])
    else:
        print "Got no results, please try another hash"
        return
    if interesting_samples_counter >= 100:
        print "Threshold too low, catching over 100 samples, please raise threshold"
        return
    elif interesting_samples_counter == 0:
        print "Threshold too high, caught 0 samples, please lower threshold"
        return
    else:
        print "Found {0} samples over the threshold of {1}".format(interesting_samples_counter,min_threshold)
    print "Samples size ranges between {0} bytes to {1} bytes".format(min_size,max_size)
    cnt = Counter(code_blocks_list)
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
    args = parser.parse_args()
    if args.file_path:
        parse_input_file(args.min_threshold, args.file_path)
    elif args.hash:
        calculate_blocks(args.min_threshold, args.file_hash)

if __name__ == "__main__":
    main()
