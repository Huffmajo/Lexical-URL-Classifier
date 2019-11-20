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

	# analyze data for classification metrics if gather flag is used
	if "-gather" in sys.argv:
		gather(urldata)
	# or test out our current classification on known data
	elif file == "train.json":
		gather(urldata)
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
				data = 0
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
				data = 0
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
	malURLs = []

	# get known malicious URLs
	for record in urldata:
		if record["malicious_url"] == 1:
			malURLs.append(record["url"])

# used to classify unknown URLs 
def classify(urldata):
	print "Not yet implemented"

if __name__ == "__main__":
	main(sys.argv[1:])
