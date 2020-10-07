# VT Code Similarity Yara Generator

Yara rule generator using VirusTotal code similarity feature `code-similar-to:`

## Introduction

This Yara generator is using VirusTotal 'code-similar-to:' beta search modifier to gather code blocks from PE files and automatically create a Yara signature using them.
This Yara generator was presented on GReAT Ideas July 2020 showing how you could use the generated Yara rule to hunt for similar APT samples and greatly refine the results using Kaspersky KTAE. [Slides](/media/ThreatHunting_GReAT_ideas.pdf)

## Prerequisites
- VirusTotal Enterprise API key
- Python 2/3, requests, json

### How does it work?
![Execution Flow](/media/workflow.gif?raw=true)

##### TL;DR
>Provide hash, get Yara rule to hunt for similar samples.

This tool accepts a PE file hash and queries VirusTotal for files sharing code blocks with it, post-processesing the results using minimal code block length and similarity score thresholds you can set.

It then iterates over the returned files, for each file collecting its code blocks, their offset and filesize which will be used to determine the file size range for the Yara rule. It ranks the code blocks that were seen across the most files returned (most popular code blocks).

User is prompted to choose how many of the most popular code blocks to include in the Yara rule. The code blocks that are picked are then compared against the code blocks from the original file that was used when executing the Yara generator to determine the Yara rule minimal matching condition.

### Commandline Parameters

```
usage: VTCodeSimilarity_YaraGen.py [-h] [--hash MD5/SHA1/SHA256]
                                   [--threshold 50%] [--hashlist hashes.txt]
                                   [--min_block 4] [--apikey APIKEY] [--debug]

VirusTotal Code Similarity Yara Generator

optional arguments:
  -h, --help            show this help message and exit
  --hash MD5/SHA1/SHA256
                        MD5/SHA1/SHA256 hash to check on VTi
  --threshold 50%       Minimum similarity threshold
  --hashlist hashes.txt
                        Path to a file containing list of hashes
  --min_block 4         Minimum desired codeblock size
  --apikey APIKEY       VT API Key
  --debug               Store VirusTotal JSON data
```

I suggest to use `--debug` if you're playing around with a rule. It will store the results from VirusTotal in a json file instead of fetching them each time.

### Example

```
python VTCodeSimilarity_YaraGen.py --hash 7ec8a9641d7342d1a471ebcd98e28b62 --threshold 80%
```

Will result in this rule:
![Turla Carbon Rule](/media/rule_example.jpg?raw=true)

Some stats from running KTAE on the Retrohunt results of the rule above:
![KTAE Stats Turla Carbon](/media/KTAE_magic.jpg?raw=true)

## Caveats

This VirusTotal feature is still in beta phase.
- The sample set is limited
- Packed samples are an issue
- Code blocks returned could be a subset of each other
- No code block whitelist. Code blocks might be of a 3rd party library and therefore 'benign'.
- General bugs in code similarity calculation.

## More details

The code blocks are stored in a nested dictionary:
```
{ binary : { counter : 1, offset : 536990455,43655401} }
```
Where:
- `binary` is the actual code block
- `counter` contains the number of times this code block was seen across results
- ~~`asm` contains the assembly representation of that code block~~ Removed, since it might be removed from the API in the future
- `offset` contains all the offsets that this code block was seen at

### TODO

Please feel free to contribute and submit pull requests. Some ideas so far:
- ~~Print the assembly code, most likely printing it interactively.~~ Removed, since it might be removed from the API in the future
- Make use of the offsets of the code blocks in the Yara condition.
- Give more information when pruning less popular code blocks.


## GREETZ

Thanks to [Juan Infantes Diaz](https://twitter.com/jinfantesd) from VirusTotal for his help and this new feature.

## License

This project is licensed under the GNUGPLv3 - see the [LICENSE.md](LICENSE.md) file for details.
