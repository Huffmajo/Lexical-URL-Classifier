# Lexical-URL-Classifier
Monitors lexical data from URLs to determine a safety level and ultimately decide if they are malicious or safe to visit. A URL's potentially malicious rank is decided from the following rules, as malicious URLs tend to have:
- Long host lengths
- Long URL lengths
- Low domain ages
- Many domain tokens
- Long path lengths
- Many path tokens
- High or no Alexa
- Non-standard default ports (anything that is not 80 or 443)
- TLDs composed of integers

### Testing Classifier with Known Data
Testing the classifier is necessary to determine if we are getting accurate using pulled data from known safe and malicious URLs contained in `train.json`. This compares the URLs flagged from the ruleset above to the known malicious URLs and returns statistics on the results. The following information is returns to provide feedback on the success of the classifier:
- Quantity of flagged URLs out of the all URLs provided
- Quantity of correctly flagged URLs
- Quantity of safe URLs flagged as malicious (false positives)
- Quantity of malicious URLs not flagged
The classifier is tested by using the command `python readcorpus.py train.json`.

### Classifying Unknown URLs
The classifier can classify URLs of unknown origin as safe or malicious by using the command `python readcorpus.py <json file name>`.
This will generate `results.txt` containing each tested URL followed by a value indicating if the URL is malicious or not (0 = safe, 1 = malicious).