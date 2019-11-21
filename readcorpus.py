#!/usr/bin/python

import json, sys, getopt, os

def usage():
	print("Usage: %s --file=[filename]" % sys.argv[0])
	sys.exit()

def main(argv):

	file=''
 
	myopts, args = getopt.getopt(sys.argv[1:], "", ["file="])
 
	for o, a in myopts:
		if o in ('-f, --file'):
			file=a
		else:
			usage()

	if len(file) == 0:
		usage()
 
	corpus = open(file)
	urldata = json.load(corpus, encoding="latin1")

	# test out our current classification on known data
	if file == "train.json":
		# gather data for classification metrics
		gather(urldata)
		test(urldata)
	# otherwise classify unknown data
	else:
		classify(urldata)
	corpus.close()

def gather(urldata):
	# print header
	print "======================================="
	print "\tMALICIOUS\tSAFE"
	getAvg(urldata, "host_len")
	getAvg(urldata, "url_len")
	getAvg(urldata, "domain_age_days")
	getAvg(urldata, "num_domain_tokens")
	getAvg(urldata, "path_len")
	getAvg(urldata, "num_path_tokens")
	getAvg(urldata, "alexa_rank")
	
	getFrequency(urldata, "default_port")
	getFrequency(urldata, "port")
	getFrequency(urldata, "tld")
	getFrequency(urldata, "alexa_rank")
	getFrequency(urldata, "file_extension")
	getFrequency(urldata, "scheme")

# used to gather frequency data for non-int url data
def getFrequency(urldata, field):
	# setup variables
	mURL = {}
	sURL = {}

	for record in urldata:
		if record["malicious_url"] == 1:
			# provide null selection for empty fields
			if record[field] is None:
				data = "Null"
			else:
				data = record[field]
			# increment occurance of data if already in dict, otherwise add it
			if data in mURL:
				mURL[data] += 1
			else:
				mURL[data] = 1
		elif record["malicious_url"] == 0:
			# provide null selection for empty fields
			if record[field] is None:
				data = "Null"
			else:
				data = record[field]
			# increment occurance of data if already in dict, otherwise add it
			if data in sURL:
				sURL[data] += 1
			else:
				sURL[data] = 1

	# print results
	print "======================================="
	print (field.upper())
	print "===MALICIOUS==="
	for key, value in sorted(mURL.iteritems(), key=lambda (k,v):(v,k), reverse=True):
		print "%s\t%s" % (key, value)
	print "===SAFE==="
	for key, value in sorted(sURL.iteritems(), key=lambda (k,v):(v,k), reverse=True):
		print "%s\t%s" % (key, value)

def getAvg(urldata, field):
	# setup variables
	mCount = 0
	mSum = 0
	mAvg = 0
	mMax = 0
	mMin = 999
	sCount = 0
	sSum = 0
	sAvg = 0
	sMax = 0
	sMin = 999

	# organize and count safe and malicious urls
	for record in urldata:
		if record["malicious_url"] == 1:
			# get data from field, check for null
			if record[field] is None:
				data = 999999
			else:
				data = int(record[field])
			mCount += 1
			mSum += data
			# check for max and min
			if data > mMax:
				mMax = data
			if data < mMin:
				mMin = data

		elif record["malicious_url"] == 0:
			# get data from field, check for null
			if record[field] is None:
				data = 999999
			else:
				data = int(record[field])
			sCount += 1
			sSum += data
			# check for max and min
			if data > sMax:
				sMax = data
			if data < sMin:
				sMin = data
			
	# calculate avg from data
	mAvg = mSum / mCount
	sAvg = sSum / sCount

	# print results
	print "======================================="
	print (field.upper())
	print "Max:\t%d\t\t%d" % (mMax, sMax)
	print "Avg:\t%d\t\t%d" % (mAvg, sAvg)
	print "Min:\t%d\t\t%d" % (mMin, sMin)

# used to validate classify function on known data
def test(urldata):
	knownMalURLs = []
	guessMalURLs = []
	allURLs = {}

	# use rules to classify URLs 
	for record in urldata:

		# get known malicious URLs
		if record["malicious_url"] == 1:
			knownMalURLs.append(record["url"])

		# store URL and set initialize score as key to 0		
		curURL = record["url"]
		allURLs[curURL] = 0

		# long host length is sketchy
		if int(record["host_len"]) > 70:
			allURLs[curURL] += 10
		elif int(record["host_len"]) > 40:
			allURLs[curURL] += 5			

		# long urls are sketchy
		if int(record["url_len"]) > 600:
			allURLs[curURL] += 10
		elif int(record["url_len"]) > 100:
			allURLs[curURL] += 5

		# young domains are sketchy
		if int(record["domain_age_days"]) < 0:
			allURLs[curURL] += 20
		elif int(record["domain_age_days"]) < 400:
			allURLs[curURL] += 10
		elif int(record["domain_age_days"]) >= 400:
			allURLs[curURL] -= 20

		# too many domain tokens are sketchy
		if int(record["num_domain_tokens"]) > 10:
			allURLs[curURL] += 10

		# too long a path is sketchy
		if int(record["path_len"]) > 250:
			allURLs[curURL] += 10

		# too many path tokens are sketchy
		if int(record["num_path_tokens"]) > 15:
			allURLs[curURL] += 10

		# High alexa rank or no rank are sketchy
		if record["alexa_rank"] is None:
			allURLs[curURL] += 10
		elif int(record["alexa_rank"]) > 500000:
			allURLs[curURL] += 20
		elif int(record["alexa_rank"]) > 95000:
			allURLs[curURL] += 10
		elif int(record["alexa_rank"]) < 500:
			allURLs[curURL] -= 10

		# default ports that aren't 80 or 443 are sketchy
		if int(record["default_port"]) == 80 or int(record["default_port"]) == 443:
			allURLs[curURL] -= 1
		else:
			allURLs[curURL] += 20

		# ports that aren't 80 or 443 are sketchy
		if int(record["port"]) == 80 or int(record["port"]) == 443:
			allURLs[curURL] -= 1
		else:
			allURLs[curURL] += 20

		# a tld that is an integer is sketchy
		if isinstance(record["tld"], (int, long)):
			allURLs[curURL] += 20

	# all URLs past threshold are deemed malicious
	threshold = 0

	# add all urls past threshold to guessed malicious url list
	for url in allURLs:
		if allURLs[url] > threshold:
			guessMalURLs.append(url)

	correct = 0
	notMal = 0
	totalMal = len(knownMalURLs)

	# check which guessed urls are actually malicious
	for url in guessMalURLs:
		if url in knownMalURLs:
			correct += 1
			knownMalURLs.remove(url)			
		else:
			notMal += 1

	missedMal = len(knownMalURLs)
	
	# print results
	print "Targeted %d out of %d URLs as malicious" % (len(guessMalURLs), len(allURLs))
	print "Correctly removed %d/%d malicious URLs" % (correct, totalMal)
	print "Incorrectly removed %d safe URLs and missed %d malicious URLs" % (notMal, missedMal)

	# print missed results
	for url in knownMalURLs:
		print url

# used to classify unknown URLs 
def classify(urldata):
	guessMalURLs = []
	guessSafeURLs = []
	allURLs = {}

	# use rules to classify URLs 
	for record in urldata:

		# store URL and set initialize score as key to 0		
		curURL = record["url"]
		allURLs[curURL] = 0

		# long host length is sketchy
		if int(record["host_len"]) > 70:
			allURLs[curURL] += 10
		elif int(record["host_len"]) > 40:
			allURLs[curURL] += 5			

		# long urls are sketchy
		if int(record["url_len"]) > 600:
			allURLs[curURL] += 10
		elif int(record["url_len"]) > 100:
			allURLs[curURL] += 5

		# young domains are sketchy
		if int(record["domain_age_days"]) < 0:
			allURLs[curURL] += 20
		elif int(record["domain_age_days"]) < 400:
			allURLs[curURL] += 10
		elif int(record["domain_age_days"]) >= 400:
			allURLs[curURL] -= 20

		# too many domain tokens are sketchy
		if int(record["num_domain_tokens"]) > 10:
			allURLs[curURL] += 10

		# too long a path is sketchy
		if int(record["path_len"]) > 250:
			allURLs[curURL] += 10

		# too many path tokens are sketchy
		if int(record["num_path_tokens"]) > 15:
			allURLs[curURL] += 10

		# High alexa rank or no rank are sketchy
		if record["alexa_rank"] is None:
			allURLs[curURL] += 10
		elif int(record["alexa_rank"]) > 500000:
			allURLs[curURL] += 20
		elif int(record["alexa_rank"]) > 95000:
			allURLs[curURL] += 10
		elif int(record["alexa_rank"]) < 500:
			allURLs[curURL] -= 10

		# default ports that aren't 80 or 443 are sketchy
		if int(record["default_port"]) == 80 or int(record["default_port"]) == 443:
			allURLs[curURL] -= 1
		else:
			allURLs[curURL] += 20

		# ports that aren't 80 or 443 are sketchy
		if int(record["port"]) == 80 or int(record["port"]) == 443:
			allURLs[curURL] -= 1
		else:
			allURLs[curURL] += 20

		# a tld that is an integer is sketchy
		if isinstance(record["tld"], (int, long)):
			allURLs[curURL] += 20

	# all URLs past threshold are deemed malicious
	threshold = 0

	# add all urls past threshold to guessed malicious url list
	for url in allURLs:
		if allURLs[url] > threshold:
			guessMalURLs.append(url)
		else:
			guessSafeURLs.append(url)

	# print results
	print "Targeted %d out of %d URLs as malicious" % (len(guessMalURLs), len(allURLs))

	# write results to file
	resultfile = open("results.txt","w")
	for url in guessMalURLs:
		resultfile.write("%s, 1\n" % (url))
	for url in guessSafeURLs:
		resultfile.write("%s, 0\n" % (url))

	resultfile.close()

	print "Results written to results.txt"

if __name__ == "__main__":
	main(sys.argv[1:])
