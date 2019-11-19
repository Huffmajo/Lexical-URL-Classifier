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
	if "-train" in sys.argv:
		train(urldata)
	# or test out our current classification on known data
	elif "-test" in sys.argv and file == "train.json":
		test(urldata)
	# otherwise classify unknown data
	else:
		classify(urldata)

	corpus.close()

# used to gather data for test function
def train(urldata):
	domainAgeInfo(urldata)

# used to validate classify function on known data
def test(urldata):
	malURLs = []

	# get known malicious URLs
	for record in urldata
		if record["malicious_url"] == 1:
			malURLs.append(record["url"])

# used to classify unknown URLs 
def classify(urldata):

	for record in urldata: 
		

def domainAgeInfo(urldata):
	# setup variables
	malURLs = {}	
	safeURLs = {}
	malCount = 0
	malSum = 0
	malAvg = 0
	malMax = 0
	malMin = 999
	safeCount = 0
	safeSum = 0
	safeAvg = 0
	safeMax = 0
	safeMin = 999

	# organized and count safe and malicious urls
	for record in urldata:
		if record["malicious_url"] == 1:
			# save malicious url and domain age
			urlAge = int(record["domain_age_days"])
			malURLs[record["url"]] = urlAge
			malCount += 1
			malSum += urlAge
			# check for max and min
			if urlAge > malMax:
				malMax = urlAge
			if urlAge < malMin:
				malMin = urlAge
#			print "Mal URL: %s age: %d" % (str(record["url"]), urlAge)

		elif record["malicious_url"] == 0:
			# save safe url and domain age
			urlAge = int(record["domain_age_days"])
			safeURLs[record["url"]] = urlAge
			safeCount += 1
			safeSum += urlAge
			# check for max and min
			if urlAge > safeMax:
				safeMax = urlAge
			if urlAge < safeMin:
				safeMin = urlAge
#			print "Safe URL: %s age: %d" % (str(record["url"]), urlAge)
			
	# calculate domain age results
	malAvg = malSum / malCount
	safeAvg = safeSum / safeCount

	# print results
	print "Malicious Stats"
	print "Max age: %d" % malMax
	print "Avg age: %d" % malAvg
	print "Min age: %d" % malMin

	print "Safe Stats"
	print "Max age: %d" % safeMax
	print "Avg age: %d" % safeAvg
	print "Min age: %d" % safeMin

if __name__ == "__main__":
	main(sys.argv[1:])
